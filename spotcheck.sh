#!/usr/bin/env bash
# Spot-check the remaining competition categories (reversing, pwn, web) against
# the hardened agent, one challenge each. Run from the repo root:
#   bash spotcheck.sh
#
# It first PRINTS the available challenges per category so you can see the menu,
# then runs the PICKS below. To change a pick, edit the PICKS array to any id
# shown in the menu (a substring is fine -- it resolves via practice_ids.txt).
set -u

export CTF_SOLVER_IMAGE=ctf-solver:tools-v1
export CTF_ENABLE_SERVICES=1          # pwn/web service challenges need this
export CTF_MAX_STEPS=80               # headroom for harder challenges
export CTF_MAX_SECONDS=1800

echo "================ available challenges by category ================"
for pre in rev pwn web for cry; do
  echo "[$pre]"
  grep -iE "(^|[^a-z])${pre}" practice_ids.txt || echo "  (none found)"
done
echo "================================================================="
echo

# One challenge per competition category. Edit these to any id from the menu.
# Defaults re-test the categories you've already touched, plus a harder reversing
# case (rev-rox) that previously failed on decoy flags -- a good regression test
# of the decoy-flag guidance.
PICKS=(
  "rev-rox"      # REVERSING  (decoy-flag handling)
  "pwn-"         # PWN        (first pwn challenge found)
  "web-"         # WEB        (first web challenge found)
)

for sel in "${PICKS[@]}"; do
  C=$(grep -iE "$sel" practice_ids.txt | head -1)
  if [ -z "$C" ]; then
    echo "!! no id matches '$sel' -- pick one from the menu above and edit PICKS"
    echo
    continue
  fi
  echo "===================== running: $C ====================="
  python3 practice_runner.py --challenge-id "$C"
  python3 trace_digest.py
  echo
done

echo "Spot-check complete. Paste the three digests back for review."
