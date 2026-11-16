"""
competition_runner.py - Run the agent against an ad-hoc challenge that is NOT
in the CTFTiny dataset (e.g. a downloaded HackTheBox competition challenge).

Differences from benchmark_runner / practice_runner:
  * Takes a plain files directory + free-text description + optional remote
    target, instead of a dataset challenge_id.
  * There is no local answer key. HTB verifies flags, so a submitted candidate
    is accepted when it matches the expected flag FORMAT; every candidate is
    recorded and printed for you to submit on the HTB scoreboard.
  * Network: defaults to the host stack (--network host) so the solver can
    reach remote pwn/web targets over the host VPN. Use --network none for a
    pure file challenge (reversing/crypto/forensics) to keep it offline.

SECURITY NOTE: --network host removes the solver's network isolation (it shares
the host's interfaces, including the VPN and the internet). That is a
deliberate competition choice; do not use it for the graded benchmark.

Examples:
  # remote pwn challenge over the VPN
  python3 competition_runner.py --name "Spooky" --category pwn \
      --files-dir ./spooky_files --target 10.10.10.5:1337

  # offline reversing challenge (files only)
  python3 competition_runner.py --name "Baby RE" --category rev \
      --files-dir ./babyre --network none
"""
import argparse
import json
import os
import re
import shutil
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from agent_core import run_agent
from controller import ToolDispatcher
from flag_verifier import FlagVerifier
from solver_runtime import DockerSolver

BASE = Path(__file__).resolve().parent
DEFAULT_MODEL = os.environ.get("CTF_MODEL", "gpt-oss:120b")

# Never stage the answer or a worked solution into the solver (defense in depth
# if you point --files-dir at a folder that contains one).
FORBIDDEN_SOLVER_FILES = {
    "flag.txt", "flag", "solve.txt", "solve.sh", "solve.py",
    "solution.txt", "solution.md",
}

# Permissive default: HTB{...}, flag{...}, csawctf{...}, and generic word{...}.
DEFAULT_FLAG_FORMAT = r"[A-Za-z0-9_]{2,}\{[^{}\n]{1,200}\}"


def stage_files(files_dir, workspace):
    """Copy challenge files into the workspace and make them solver-readable."""
    exported = []
    src = Path(files_dir).resolve()
    for path in sorted(src.rglob("*")):
        if path.is_file():
            if path.name.lower() in FORBIDDEN_SOLVER_FILES:
                print(f"WARNING: withheld '{path.name}' from solver (leakage guard)")
                continue
            rel = path.relative_to(src)
            dest = workspace / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, dest)
            exported.append(str(rel))
    # Normalize perms so the unprivileged solver uid can traverse + read.
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
    return exported


def main():
    ap = argparse.ArgumentParser(description="Run the agent on an ad-hoc challenge")
    ap.add_argument("--name", required=True, help="Challenge name")
    ap.add_argument("--category", default="", help="rev/crypto/pwn/web/forensics")
    ap.add_argument("--files-dir", default=None, help="Directory of challenge files")
    ap.add_argument("--description", default="", help="Challenge prompt text")
    ap.add_argument("--description-file", default=None, help="Read description from a file")
    ap.add_argument("--target", default=None, help="Remote target as host:port")
    ap.add_argument("--flag-format", default=DEFAULT_FLAG_FORMAT,
                    help="Regex a candidate flag must match to be accepted")
    ap.add_argument("--network", default="host", choices=["host", "bridge", "none"],
                    help="Solver network: host (default, reaches VPN), bridge "
                         "(internet via NAT), or none (offline)")
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--max-steps", type=int,
                    default=int(os.environ.get("CTF_MAX_STEPS", "60")))
    ap.add_argument("--max-seconds", type=int,
                    default=int(os.environ.get("CTF_MAX_SECONDS", "1800")))
    args = ap.parse_args()

    api_key = os.environ.get("OLLAMA_API_KEY")
    if not api_key:
        ap.error("OLLAMA_API_KEY is missing; set the competition gateway key")

    tools = json.loads((BASE / "tools.json").read_text(encoding="utf-8"))

    flag_re = re.compile(args.flag_format)
    verifier = FlagVerifier(verify_callback=lambda c: bool(flag_re.search(c)))

    description = args.description
    if args.description_file:
        description = Path(args.description_file).read_text(encoding="utf-8")

    target_note = ""
    if args.target:
        target_note = (
            f"\n\nREMOTE TARGET: {args.target}. Connect to it over the network "
            f"(e.g. pwntools remote(), curl, or requests). The flag is obtained "
            f"by interacting with this target."
        )

    run_id = str(uuid.uuid4())
    with tempfile.TemporaryDirectory(prefix="ctf_comp_") as temp:
        workspace = Path(temp)
        workspace.chmod(0o755)
        exported = stage_files(args.files_dir, workspace) if args.files_dir else []

        solver = DockerSolver()
        start = time.monotonic()
        try:
            solver.start(
                challenge_dir=workspace,
                network=args.network,
                allow_host=(args.network in ("host", "bridge")),
            )
            dispatcher = ToolDispatcher(solver, verifier=verifier)
            result = run_agent(
                challenge_id=f"comp-{args.name}",
                description=(
                    f"Challenge: {args.name}\n"
                    f"Category: {args.category}\n"
                    f"Description: {description}"
                    f"{target_note}"
                ),
                files=[f"/challenge/{p}" for p in exported],
                execute_tool=dispatcher,
                api_key=api_key,
                tools=tools,
                model=args.model,
                max_steps=args.max_steps,
                max_seconds=args.max_seconds,
            )
        finally:
            solver.stop()

    elapsed = round(time.monotonic() - start, 2)
    candidates = [s["candidate"] for s in verifier.submissions]

    print("\n" + "=" * 60)
    print(f"CHALLENGE: {args.name} [{args.category}]   ({elapsed}s)")
    print(f"status: {result.get('status')}   steps: {result.get('tool_calls')}")
    if candidates:
        print("\nCANDIDATE FLAG(S) -- submit these on the HTB scoreboard:")
        for c in candidates:
            print(f"   {c}")
    else:
        print("\nNo candidate flag produced. Check the trace:")
    print(f"trace: {result.get('trace_file')}")
    print("=" * 60)

    # Persist a small record alongside the practice results.
    out = BASE / "results" / "competition"
    out.mkdir(parents=True, exist_ok=True)
    (out / f"{run_id}.json").write_text(json.dumps({
        "run_id": run_id,
        "name": args.name,
        "category": args.category,
        "target": args.target,
        "network": args.network,
        "status": result.get("status"),
        "candidates": candidates,
        "tool_calls": result.get("tool_calls"),
        "elapsed_s": elapsed,
        "trace_file": result.get("trace_file"),
        "recorded_at": datetime.now(timezone.utc).isoformat(),
    }, indent=2))


if __name__ == "__main__":
    main()
