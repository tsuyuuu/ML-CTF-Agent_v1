#!/usr/bin/env bash
# Game-day setup. Secrets (ANTHROPIC_API_KEY, HTB_TOKEN, OLLAMA_API_KEY) should
# come from your Codespaces environment; the config below is set here.
#
#   SOURCE it (so the exports stick in your shell):   source START_HERE.sh
#   then run:                                         python3 htb_runner.py

# --- non-secret config ---
export CTF_SOLVER_IMAGE=ctf-solver:tools-v1
export CTF_PROVIDER=anthropic
export CTF_MODEL=claude-sonnet-5-5
export CTF_TEMPERATURE=1.0
export CTF_MAX_OUTPUT_TOKENS=4096
export CTF_FALLBACK_PROVIDER=ollama
export CTF_FALLBACK_MODEL=gpt-oss:120b
export HTB_EVENT_ID=3755
# To use Gemini as the fallback instead, comment the two FALLBACK lines above and:
#   export CTF_FALLBACK_PROVIDER=openai
#   export CTF_FALLBACK_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai
#   export CTF_FALLBACK_API_KEY='your-google-key'
#   export CTF_FALLBACK_MODEL=gemini-2.5-flash

# --- secret check ---
echo "key lengths -> anthropic:${#ANTHROPIC_API_KEY}  htb:${#HTB_TOKEN}  ollama:${#OLLAMA_API_KEY}"
missing=0
for v in ANTHROPIC_API_KEY HTB_TOKEN OLLAMA_API_KEY; do
  if [ -z "${!v}" ]; then echo "!! $v is EMPTY -- add it as a Codespaces secret (then restart the Codespace) or export it"; missing=1; fi
done

# --- venv check ---
case "$(which python3)" in
  *".venv"*) : ;;
  *) echo "!! venv not active -- run: source .venv/bin/activate" ; missing=1 ;;
esac

# --- pre-flight: imports + HTB connection + challenge list ---
if [ "$missing" = "0" ]; then
  python3 -c "import agent_core, htb_mcp; print('imports OK')" || missing=1
  python3 -c "from htb_mcp import HTBClient; import os; c=HTBClient(os.environ['HTB_TOKEN']); ch=c.retrieve_ctf(int(os.environ['HTB_EVENT_ID'])).get('challenges',[]); print(len(ch),'challenges visible:',[x.get('name') for x in ch])" || missing=1
fi

if [ "$missing" = "0" ]; then
  echo ">>> READY. Run:  python3 htb_runner.py"
else
  echo ">>> Fix the items marked !! above, then re-run: source START_HERE.sh"
fi
