#!/usr/bin/env bash
# Game-day launcher: routes each challenge to the best NON-REFUSING backend
# through the Duke AI Gateway (OpenAI-compatible).
#   Claude Sonnet  -> rev / crypto / web / forensics  (Sonnet refuses pwn)
#   Gemini         -> pwn                              (paper: 73% pwn, no refusals)
#
# Usage:  CTF_API_KEY=<duke-litellm-key> bash run_ctf.sh <challenge-id>
set -u
CID="${1:?usage: run_ctf.sh <challenge-id>}"

# --- Duke AI Gateway (OpenAI-compatible endpoint) ---
export CTF_PROVIDER=openai
export CTF_BASE_URL="${CTF_BASE_URL:-https://litellm.oit.duke.edu/v1}"
export CTF_API_KEY="${CTF_API_KEY:?set CTF_API_KEY to your Duke LiteLLM key}"
export CTF_TEMPERATURE=1.0
export CTF_MAX_OUTPUT_TOKENS=4096

# --- per-category model routing (override ids via env if the gateway differs) ---
CLAUDE="${CTF_CLAUDE_MODEL:-claude-sonnet-5-5}"
GEMINI="${CTF_GEMINI_MODEL:-gemini-2.5-flash}"

case "$CID" in
  pwn-*)  export CTF_MODEL="$GEMINI" ;;   # Claude refuses pwn -> Gemini
  *)      export CTF_MODEL="$CLAUDE" ;;   # everything else -> Claude Sonnet
esac

echo ">>> $CID   provider=$CTF_PROVIDER   model=$CTF_MODEL"

# Practice validation. For the real competition, swap the next line for your
# competition_runner.py invocation (same routing logic applies by category).
python3 practice_runner.py --challenge-id "$CID" && python3 trace_digest.py
