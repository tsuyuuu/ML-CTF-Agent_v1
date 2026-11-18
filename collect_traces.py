#!/usr/bin/env python3
"""
collect_traces.py -- bundle CTF agent trace logs into one compact, secret-scrubbed
digest file for debugging.

Usage:
    python3 collect_traces.py                 # failed/unsolved challenges only (default)
    python3 collect_traces.py --all           # every challenge, solved included
    python3 collect_traces.py logs/<id>.jsonl # one or more specific files
    python3 collect_traces.py --out foo.txt   # choose output path

Reads logs/*.jsonl, writes trace_digests.txt in the repo root. Upload that one file.

Safe to run while the agent is running; it only reads the logs.
"""
import os, sys, json, glob, re

HERE = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(HERE, "logs")

# ---- secret redaction -------------------------------------------------------
# Exact values from the environment (most reliable), plus generic patterns.
_SECRET_ENV = ("ANTHROPIC_API_KEY", "OLLAMA_API_KEY", "HTB_TOKEN",
               "CTF_API_KEY", "OPENAI_API_KEY", "CTF_FALLBACK_API_KEY",
               "GOOGLE_API_KEY")
_EXACT = sorted(
    {v for k in _SECRET_ENV if (v := os.environ.get(k)) and len(v) >= 8},
    key=len, reverse=True,
)
_PATTERNS = [
    re.compile(r"sk-ant-[A-Za-z0-9_\-]+"),
    re.compile(r"sk-[A-Za-z0-9_\-]{20,}"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9_\-\.=]+"),
    re.compile(r"(?i)(api[_-]?key|token|secret)\s*[=:]\s*['\"]?[A-Za-z0-9_\-\.]{12,}"),
]

def scrub(text):
    if not isinstance(text, str):
        text = str(text)
    for v in _EXACT:
        text = text.replace(v, "[REDACTED]")
    for pat in _PATTERNS:
        text = pat.sub("[REDACTED]", text)
    return text

# ---- helpers ----------------------------------------------------------------
def short(obj, n=240):
    """Compact one-line repr, truncated."""
    if isinstance(obj, (dict, list)):
        s = json.dumps(obj, default=str)
    else:
        s = str(obj)
    s = s.replace("\n", " ")
    return s[:n] + ("…" if len(s) > n else "")

def result_brief(res, n=260):
    """Pull the signal out of a tool result dict."""
    if not isinstance(res, dict):
        return short(res, n)
    for key in ("error",):
        if res.get(key):
            return f"ERROR: {short(res[key], n)}"
    bits = []
    if "exit_code" in res:
        bits.append(f"exit={res['exit_code']}")
    if res.get("timed_out"):
        bits.append("TIMED_OUT")
    if res.get("verified") is not None:
        bits.append(f"verified={res['verified']}")
    for key in ("stdout", "content", "disassembly", "stderr"):
        val = res.get(key)
        if isinstance(val, str) and val.strip():
            bits.append(f"{key}: {short(val, n)}")
            break
    if not bits:
        return short(res, n)
    return "  ".join(bits)

MARKERS = {
    "context_compaction": lambda e: f"** COMPACTION {e.get('old_message_count')}->{e.get('new_message_count')} msgs",
    "scope_violation_recovery": lambda e: f"** SCOPE-VIOLATION recovered (#{e.get('scope_violations')})",
    "provider_fallback": lambda e: f"** PROVIDER FALLBACK -> {e.get('to') or e.get('model') or ''}",
    "budget_escalation": lambda e: f"** BUDGET ({e.get('steps_left')} left)",
    "model_retry": lambda e: "** model_retry",
    "empty_response_recovery": lambda e: "** empty_response_recovery",
    "no_tool_recovery": lambda e: "** no_tool_recovery",
}

def digest_one(path):
    events = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except Exception:
                        pass
    except Exception as e:
        return None, f"(could not read {path}: {e})"

    start = next((e for e in events if e.get("type") == "start"), {})
    end = next((e for e in events if e.get("type") == "end"), {})
    summary = end.get("summary", {}) if isinstance(end, dict) else {}
    status = summary.get("status", "UNKNOWN")
    verified = bool(summary.get("verified"))

    out = []
    out.append("#" + "=" * 70)
    out.append(f"# file      : {os.path.basename(path)}")
    out.append(f"# challenge : {start.get('challenge_id', '?')}")
    out.append(f"# model     : {start.get('model','?')}  "
               f"max_steps={start.get('max_steps','?')} "
               f"max_seconds={start.get('max_seconds','?')}")
    out.append(f"# STATUS    : {status}  verified={verified}")
    out.append(f"# steps={summary.get('tool_calls')} "
               f"elapsed={summary.get('elapsed_s')}s "
               f"in_tok={summary.get('known_input_tokens')} "
               f"out_tok={summary.get('known_output_tokens')}")
    out.append("#" + "-" * 70)

    n = 0
    for e in events:
        t = e.get("type")
        if t in MARKERS:
            try:
                out.append("  " + MARKERS[t](e))
            except Exception:
                out.append(f"  ** {t}")
        elif t == "tool_execution":
            n += 1
            args = e.get("arguments", {})
            out.append(f"[{n:>3}] {e.get('tool','?')}({short(args, 120)})")
            out.append(f"      -> {result_brief(e.get('result'))}")
    return (status, verified), "\n".join(out)

def main():
    argv = sys.argv[1:]
    include_all = "--all" in argv
    out_path = os.path.join(HERE, "trace_digests.txt")
    if "--out" in argv:
        i = argv.index("--out")
        out_path = argv[i + 1]
        argv = argv[:i] + argv[i + 2:]
    files = [a for a in argv if a.endswith(".jsonl")]
    if not files:
        files = sorted(glob.glob(os.path.join(LOG_DIR, "*.jsonl")),
                       key=os.path.getmtime, reverse=True)
    if not files:
        print(f"No .jsonl logs found in {LOG_DIR}")
        return

    chunks, index = [], []
    for p in files:
        meta, text = digest_one(p)
        if meta is None:
            continue
        status, verified = meta
        if verified and not include_all:
            index.append(f"  SKIP (solved)   {os.path.basename(p)}  {status}")
            continue
        index.append(f"  included        {os.path.basename(p)}  {status}")
        chunks.append(scrub(text))

    header = [
        "TRACE DIGESTS (secrets redacted)",
        f"logs scanned: {len(files)}   included: {len(chunks)}   "
        f"mode: {'all' if include_all else 'failed-only'}",
        "",
    ] + index + ["", "=" * 72, ""]

    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(header) + "\n\n".join(chunks) + "\n")

    size = os.path.getsize(out_path)
    print(f"wrote {out_path}  ({size/1024:.1f} KB, {len(chunks)} challenge(s))")
    print("Upload that one file. Secrets were scrubbed; skim it first if you want to be sure.")

if __name__ == "__main__":
    main()
