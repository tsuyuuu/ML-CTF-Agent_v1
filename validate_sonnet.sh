#!/usr/bin/env bash
# Broad Sonnet validation across categories on your personal Anthropic key.
# Finds where the strong model actually fails so we fix the right things.
#
#   ANTHROPIC_API_KEY=sk-ant-... bash validate_sonnet.sh
#
# Tune:  PER_CAT=1 (cheaper, 1 per category)   CATS="rev cry"   CTF_MODEL=claude-sonnet-5-5
# Pwn is excluded on purpose (Claude refuses it -> route pwn to Gemini on the gateway).
set -u
export CTF_PROVIDER=anthropic
export ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY:?set your sk-ant key}"
export CTF_MODEL="${CTF_MODEL:-claude-sonnet-5-5}"
export CTF_TEMPERATURE=1.0
export CTF_MAX_OUTPUT_TOKENS=4096
export CTF_ENABLE_SERVICES=1

PER_CAT="${PER_CAT:-2}"
CATS="${CATS:-rev cry web for}"

echo "=== available challenges by category ==="
for c in $CATS pwn; do
  echo "[$c]"; grep -iE "(^|[^a-z])${c}" practice_ids.txt | sed 's/^/  /' || true
done
echo "========================================"

RAN=()
for c in $CATS; do
  while read -r cid; do
    [ -z "$cid" ] && continue
    echo; echo "===================== $c :: $cid ====================="
    python3 practice_runner.py --challenge-id "$cid"
    RAN+=("$cid")
  done < <(grep -iE "(^|[^a-z])${c}" practice_ids.txt | head -n "$PER_CAT")
done

echo; echo "===== SUMMARY (model=$CTF_MODEL) ====="
python3 - "${RAN[@]}" <<'EOF'
import json, sys
ids = sys.argv[1:]
last = {}
try:
    for l in open("results/practice/attempts.jsonl"):
        try: e = json.loads(l)
        except Exception: continue
        if e.get("challenge_id") in ids:
            last[e["challenge_id"]] = e
except FileNotFoundError:
    pass
w = max([len(i) for i in ids] + [10]) if ids else 10
solved = 0
for i in ids:
    e = last.get(i, {})
    ok = e.get("verified")
    solved += 1 if ok else 0
    print(f"  {i.ljust(w)}  {('PASS' if ok else 'fail').ljust(4)}  "
          f"{str(e.get('status','(none)')):<16} {e.get('elapsed_s','?')}s  "
          f"subs={e.get('submissions_count','?')}")
print(f"\n  SOLVED {solved}/{len(ids)}")
EOF
