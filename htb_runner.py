"""
htb_runner.py - Run the agent against a live Hack The Box CTF event over MCP.

Reuses the competition solver stack unchanged (DockerSolver / ToolDispatcher /
run_agent / tools.json). Only the I/O is swapped:
  * challenges + files come from HTB's CTF MCP server (htb_mcp.HTBClient)
  * the agent's submit_flag is routed to HTB's real submit_flag, so it gets
    genuine correct/incorrect feedback in-loop and can retry format variants.

Usage (once the event is live):
    export HTB_TOKEN=<your HTB MCP token>
    export CTF_PROVIDER=openai CTF_BASE_URL=... CTF_API_KEY=<gateway key>
    export CTF_MODEL=claude-sonnet-5-5 CTF_FALLBACK_MODEL=gemini-2.5-flash
    HTB_EVENT_ID=3755 python3 htb_runner.py            # Duke AI CTF

First run against the real event PRINTS the raw challenge object + download/
container/submit responses so we can confirm the field names (every
retrieve_ctf returned 403 before the event opened, so a few accessors below are
best-guess and marked CONFIRM).
"""
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import requests

from htb_mcp import HTBClient
from agent_core import run_agent
from controller import ToolDispatcher
from flag_verifier import FlagVerifier
from solver_runtime import DockerSolver

BASE = Path(__file__).resolve().parent
EVENT_ID = int(os.environ.get("HTB_EVENT_ID", "3755"))        # Duke AI CTF
DEFAULT_MODEL = os.environ.get("CTF_MODEL", "claude-sonnet-5-5")
MAX_STEPS = int(os.environ.get("CTF_MAX_STEPS", "80"))
MAX_SECONDS = int(os.environ.get("CTF_MAX_SECONDS", "1800"))
# Fixed team token budget: stop launching challenges once we've spent this many
# (input+output) tokens. 0 = unlimited (set it on game day to your real budget).
TOKEN_BUDGET = int(os.environ.get("CTF_TOKEN_BUDGET", "0"))
# Cap real HTB submissions per challenge (avoid rate limits / wrong-flag spam).
MAX_SUBMITS = int(os.environ.get("HTB_MAX_SUBMITS", "10"))

FORBIDDEN_SOLVER_FILES = {
    "flag.txt", "flag", "solve.txt", "solve.sh", "solve.py",
    "solution.txt", "solution.md",
}


# --------------------------------------------------------------------------- #
# flexible accessors (field names CONFIRMED against the first live run)
# --------------------------------------------------------------------------- #
def field(obj, *keys, default=None):
    if isinstance(obj, dict):
        for k in keys:
            if obj.get(k) is not None:
                return obj[k]
    return default


def extract_challenges(ctf):
    """Find the challenge list inside a retrieve_ctf() response."""
    if isinstance(ctf, list):
        return ctf
    for k in ("challenges", "challenge", "ctf_challenges", "data"):
        v = field(ctf, k)
        if isinstance(v, list):
            return v
    return []


def target_from_status(st):
    """Pull a host:port out of a container_status() response (CONFIRM shape)."""
    if not isinstance(st, dict):
        return None
    host = field(st, "ip", "host", "ip_address", "hostname", "server")
    port = field(st, "port", "server_port")
    if not port:                                  # HTB returns ports as a list
        ports = field(st, "ports", "docker_ports")
        if isinstance(ports, list) and ports:
            port = ports[0]
    if host and port:
        return f"{host}:{port}"
    # Some servers return a ready-made connection string.
    conn = field(st, "connection", "connection_string", "address")
    if isinstance(conn, str) and conn.strip():
        return conn.strip()
    return None


def flag_is_correct(resp):
    """Interpret a submit_flag() response (CONFIRM shape on first live run)."""
    if isinstance(resp, dict):
        for k in ("correct", "solved", "success", "is_correct"):
            if resp.get(k) is True:
                return True
        if str(field(resp, "status", "result", default="")).lower() in (
            "correct", "solved", "success"):
            return True
        if "correct" in str(field(resp, "message", default="")).lower():
            return True
        return False
    return "correct" in str(resp).lower()


# --------------------------------------------------------------------------- #
# file staging
# --------------------------------------------------------------------------- #
def _normalize_perms(workspace):
    for root, _dirs, filenames in os.walk(workspace):
        try:
            os.chmod(root, 0o755)
        except OSError:
            pass
        for fname in filenames:
            try:
                os.chmod(os.path.join(root, fname), 0o644)
            except OSError:
                pass


def download_and_stage(client, challenge_id, workspace):
    """get_download_link -> fetch -> extract archives -> stage into workspace."""
    link = client.get_download_link(challenge_id)
    url = link if isinstance(link, str) else field(
        link, "url", "download_link", "link", "signed_url")
    if not url:
        print(f"  [dl] no download URL in response: {json.dumps(link)[:200]}")
        return []

    blob = requests.get(url, timeout=120).content
    archive = workspace / "_download"
    archive.write_bytes(blob)

    # Try zip, then tar(.gz/.xz); otherwise keep the raw file.
    try:
        if zipfile.is_zipfile(archive):
            with zipfile.ZipFile(archive) as z:
                z.extractall(workspace)
            archive.unlink()
        elif tarfile.is_tarfile(archive):
            with tarfile.open(archive) as t:
                t.extractall(workspace)
            archive.unlink()
        else:
            archive.rename(workspace / f"challenge_{challenge_id}.bin")
    except Exception as e:
        print(f"  [dl] extract warning: {e}")

    exported = []
    for path in sorted(workspace.rglob("*")):
        if path.is_file():
            if path.name.lower() in FORBIDDEN_SOLVER_FILES:
                path.unlink()
                continue
            exported.append(str(path.relative_to(workspace)))
    _normalize_perms(workspace)
    return exported


def get_target(client, challenge_id, wait=120):
    """Start the challenge container and poll for its host:port."""
    print(f"  [container] starting for challenge {challenge_id} ...")
    print("    start:", json.dumps(client.start_container(challenge_id))[:300])
    deadline = time.time() + wait
    shown = False
    while time.time() < deadline:
        st = client.container_status(challenge_id)
        if not shown:
            print("    status:", json.dumps(st)[:400])   # confirm the shape once
            shown = True
        tgt = target_from_status(st)
        if tgt:
            print(f"    target: {tgt}")
            return tgt
        time.sleep(5)
    print("    (no target resolved; adjust target_from_status to the shape above)")
    return None


# --------------------------------------------------------------------------- #
# solve one challenge
# --------------------------------------------------------------------------- #
def solve_challenge(client, ch, tools, printed):
    cid = field(ch, "id", "challenge_id")
    name = field(ch, "name", "title", default=f"challenge-{cid}")
    category = str(field(ch, "category", "challenge_category",
                         "category_name", default="")).lower()
    description = field(ch, "description", "desc", default="")
    has_container = bool(field(ch, "hasDocker", "docker", "container",
                               "hasContainer", "has_docker", "isContainer"))

    if not printed["done"]:                 # show the raw shape once
        print("\n--- first challenge object (confirm field names) ---")
        print(json.dumps(ch, indent=2)[:1500])
        print("----------------------------------------------------\n")
        printed["done"] = True

    print(f"\n==== [{category}] {name} (id={cid}) ====")

    has_download = bool(field(ch, "filename", "hasDownload", "download"))

    with tempfile.TemporaryDirectory(prefix="htb_") as temp:
        workspace = Path(temp)
        workspace.chmod(0o755)
        exported = []
        if has_download:
            try:
                exported = download_and_stage(client, cid, workspace)
            except Exception as e:
                print(f"  [dl] download error (continuing without files): {e}")
        print(f"  files: {exported or '(none)'}")

        target = get_target(client, cid) if has_container else None
        network = "host" if target else "none"

        target_note = ""
        if target:
            target_note = (
                f"\n\nREMOTE TARGET: {target}. Connect to it over the network "
                f"(pwntools remote(), curl, or requests). The flag comes from "
                f"interacting with this target."
            )

        # The agent's submit_flag -> HTB's real submit_flag (capped).
        state = {"n": 0}

        def htb_verify(flag):
            if state["n"] >= MAX_SUBMITS:
                return False
            state["n"] += 1
            try:
                resp = client.submit_flag(cid, flag)
            except Exception as e:
                print(f"  [submit] error: {e}")
                return False
            print(f"  [submit #{state['n']}] {flag!r} -> {json.dumps(resp)[:200]}")
            return flag_is_correct(resp)

        verifier = FlagVerifier(verify_callback=htb_verify)

        solver = DockerSolver()
        result = None
        try:
            solver.start(challenge_dir=workspace, network=network,
                         allow_host=(network in ("host", "bridge")))
            dispatcher = ToolDispatcher(solver, verifier=verifier)
            result = run_agent(
                challenge_id=f"htb-{cid}",
                description=(f"Challenge: {name}\nCategory: {category}\n"
                             f"Description: {description}{target_note}"),
                files=[f"/challenge/{p}" for p in exported],
                execute_tool=dispatcher,
                api_key=os.environ.get("CTF_API_KEY")
                        or os.environ.get("OLLAMA_API_KEY") or "",
                tools=tools,
                model=DEFAULT_MODEL,
                max_steps=MAX_STEPS,
                max_seconds=MAX_SECONDS,
            )
        finally:
            solver.stop()
            if has_container:
                try:
                    client.stop_container(cid)
                except Exception:
                    pass

    solved = (result or {}).get("status") == "verified"
    used = ((result or {}).get("known_input_tokens", 0)
            + (result or {}).get("known_output_tokens", 0))
    print(f"  => {'SOLVED' if solved else 'not solved'} "
          f"({result.get('status') if result else 'error'}), ~{used} tokens")

    # Per-challenge trace digest (the just-finished run is the newest log).
    # Disable with CTF_DIGEST=0.
    trace = (result or {}).get("trace_file")
    if trace:
        print(f"  trace: {trace}")
    if os.environ.get("CTF_DIGEST", "1") != "0":
        print("  --- trace digest ---")
        try:
            subprocess.run([sys.executable, str(BASE / "trace_digest.py")],
                           check=False)
        except Exception as e:
            print(f"  [digest] {e}")

    return solved, used


# --------------------------------------------------------------------------- #
def main():
    token = os.environ.get("HTB_TOKEN")
    if not token:
        raise SystemExit("set HTB_TOKEN to your HTB MCP token")
    client = HTBClient(token)
    tools = json.loads((BASE / "tools.json").read_text(encoding="utf-8"))

    ctf = client.retrieve_ctf(EVENT_ID)
    challenges = extract_challenges(ctf)
    if not challenges:
        print("No challenges found. retrieve_ctf returned:")
        print(json.dumps(ctf, indent=2)[:2000])
        return

    # Easiest first: sort by points if available so we bank the 5-solve threshold.
    challenges.sort(key=lambda c: field(c, "points", "value", default=9999))

    print(f"Event {EVENT_ID}: {len(challenges)} challenges")
    solved_count, total_tokens = 0, 0
    printed = {"done": False}
    results = []

    for ch in challenges:
        if field(ch, "solved", "isSolved", default=False):
            continue
        if TOKEN_BUDGET and total_tokens >= TOKEN_BUDGET:
            print(f"\nToken budget reached ({total_tokens} >= {TOKEN_BUDGET}); stopping.")
            break
        try:
            solved, used = solve_challenge(client, ch, tools, printed)
        except Exception as e:
            print(f"  !! challenge error: {e}")
            solved, used = False, 0
        total_tokens += used
        solved_count += int(solved)
        results.append({"id": field(ch, "id", "challenge_id"),
                        "name": field(ch, "name", "title"),
                        "solved": solved, "tokens": used})

    print("\n" + "=" * 60)
    print(f"DONE. solved {solved_count}/{len(challenges)}  tokens~{total_tokens}")
    print("=" * 60)

    out = BASE / "results" / "htb"
    out.mkdir(parents=True, exist_ok=True)
    (out / f"{uuid.uuid4()}.json").write_text(json.dumps({
        "event_id": EVENT_ID,
        "solved": solved_count,
        "total_tokens": total_tokens,
        "results": results,
        "recorded_at": datetime.now(timezone.utc).isoformat(),
    }, indent=2))


if __name__ == "__main__":
    main()
