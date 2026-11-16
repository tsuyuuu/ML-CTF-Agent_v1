"""
Compact, readable digest of one agent run trace, for diagnosing failures.

Usage:
    python3 trace_digest.py                       # newest logs/*.jsonl
    python3 trace_digest.py logs/<run-id>.jsonl   # a specific run

Prints the run summary, then every step as `tool(args) -> result`, with
loop-discipline events (skips, nudges, budget, compaction) inline. Long values
are truncated. Paste the whole output back for a diagnosis.
"""
import glob
import json
import os
import sys


def load(path):
    out = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return out


def brief(value, n=150):
    s = value if isinstance(value, str) else json.dumps(value, default=str)
    s = s.replace("\n", "\\n")
    return s if len(s) <= n else s[:n] + "…"


def main():
    if len(sys.argv) > 1:
        path = sys.argv[1]
    else:
        files = glob.glob("logs/*.jsonl")
        if not files:
            print("no logs/*.jsonl found; pass a path")
            return
        path = max(files, key=os.path.getmtime)

    events = load(path)
    print(f"# trace: {path}")

    start = next((e for e in events if e.get("type") == "start"), {})
    end = next((e for e in events if e.get("type") == "end"), {})
    summ = end.get("summary", {})
    print(f"# challenge : {start.get('challenge_id')}")
    print(f"# model     : {start.get('model')}  "
          f"max_steps={start.get('max_steps')} max_seconds={start.get('max_seconds')}")
    print(f"# STATUS    : {summ.get('status')}  verified={summ.get('verified')}")
    print(f"# steps={summ.get('tool_calls')} "
          f"short_circuits={summ.get('short_circuits')} "
          f"transition_nudges={summ.get('transition_nudges')} "
          f"elapsed={summ.get('elapsed_s')}s "
          f"in_tok={summ.get('known_input_tokens')} out_tok={summ.get('known_output_tokens')}")
    print("#" + "-" * 60)

    step = 0
    for e in events:
        t = e.get("type")
        if t == "tool_execution":
            step += 1
            auto = " [triage]" if e.get("automatic_triage") else ""
            res = e.get("result", {})
            if isinstance(res, dict):
                show = {k: res[k] for k in
                        ("error", "exit_code", "verified", "timed_out",
                         "stdout", "disassembly", "content", "blocks",
                         "assignment_count", "skipped")
                        if k in res}
            else:
                show = res
            print(f"[{step:>2}] {e.get('tool')}({brief(e.get('arguments'), 80)}){auto}")
            print(f"      -> {brief(show, 200)}")
        elif t == "tool_skipped":
            print(f"  ** SKIPPED {e.get('tool')}: {brief(e.get('reason'), 90)}")
        elif t == "transition_nudge":
            print(f"  ** TRANSITION NUDGE (consecutive_recon="
                  f"{e.get('consecutive_recon')}, constants={e.get('triage_constants')})")
        elif t == "budget_escalation":
            print(f"  ** BUDGET ({e.get('steps_left')} left): "
                  f"{brief(e.get('directive'), 80)}")
        elif t == "context_compaction":
            print(f"  ** COMPACTION {e.get('old_message_count')}->"
                  f"{e.get('new_message_count')} msgs")
        elif t == "model_response":
            msg = e.get("message", {})
            content = (msg.get("content") or "").strip()
            if content and not msg.get("tool_calls"):
                print(f"  (model said, no tool): {brief(content, 160)}")


if __name__ == "__main__":
    main()
