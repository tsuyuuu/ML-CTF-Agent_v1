# Competition runbook (HTB Agent CTF, Nov 18–19)

Categories: **Reversing, Crypto, Pwn, Web, Forensics**. Difficulty easy→insane
(mostly medium/hard). 10 challenges, 24h window. Targets reached over the HTB
VPN. Your agent already solves all five categories; this doc is how to run it
live and get the most out of the hardened toolchain.

## 1. One-time setup (do this BEFORE noon Wednesday)

```bash
# Rebuild both images with the beefed-up toolchain (this build is longer now
# because of radare2 / tshark / ruby gems / angr — budget ~10-20 min).
docker build -f Dockerfile.solver     -t ctf-solver:dev      .
docker build -f Dockerfile.ctf-tools  -t ctf-solver:tools-v1 .

# Verify the new tools actually landed:
docker run --rm --entrypoint bash ctf-solver:tools-v1 -lc \
  'for t in radare2 ltrace strace binwalk tshark steghide patchelf ROPgadget ropper one_gadget; do \
     command -v $t >/dev/null && echo "ok  $t" || echo "MISSING  $t"; done; \
   python3 -c "import angr; print(\"ok  angr\")" 2>/dev/null || echo "MISSING angr (optional)"; \
   python3 -c "import gmpy2, Crypto, z3, sympy, pwn; print(\"ok  py libs\")"'

# Set the competition gateway key (replace with the one you're issued):
export OLLAMA_API_KEY="<competition-gateway-key>"
# If the gateway uses a different model string, set it:
# export CTF_MODEL="<model-name>"
```

Then connect the HTB VPN per the instructions in the class email **on the host**
(the `--network host` solver shares the host's VPN).

## 2. Running a challenge

Download the challenge's files (if any) into a folder, grab its remote target
(if any) from the HTB challenge page, then:

```bash
# Remote pwn/web challenge (needs the VPN → host network, the default):
python3 competition_runner.py --name "ChalName" --category pwn \
    --files-dir ./chalname_files --target 10.10.x.y:PORT

# Offline file challenge (reversing/crypto/forensics) — keep it isolated:
python3 competition_runner.py --name "ChalName" --category rev \
    --files-dir ./chalname_files --network none

# No downloadable files, remote only:
python3 competition_runner.py --name "ChalName" --category web \
    --target 10.10.x.y:PORT --description "login page, find the flag"
```

The runner prints **CANDIDATE FLAG(S)** at the end — those are what you paste
into the HTB scoreboard (there's no local answer key; HTB verifies). Every
candidate the agent tried is recorded, and a JSON record is saved under
`results/competition/`.

Point `--flag-format` at HTB's exact format if you want to be strict, e.g.
`--flag-format 'HTB\{[^}]+\}'`. The default also accepts `flag{...}` etc.

## 3. Network modes (important)

- `--network host` (default): solver shares the host's network stack, so it
  reaches the HTB target over the VPN. **This removes network isolation** — the
  solver can also reach the internet. That's an accepted competition trade-off;
  never use it for the graded benchmark.
- `--network none`: fully offline. Use for pure file challenges so the agent
  can't wander — faster and safer.
- `--network bridge`: internet via NAT but not the host's VPN routes; rarely
  what you want here.

## 4. Budget & step guidance (token limits are real)

Each run costs ~100–300k input tokens. With a daily gateway cap and 10
challenges, spend deliberately:

- Defaults are tuned for hard challenges: `--max-steps 60`, `--max-seconds 1800`
  (override with `CTF_MAX_STEPS` / `CTF_MAX_SECONDS` or the flags).
- **One good run per challenge, not three.** Unlike the graded eval, the
  competition only needs the flag once. Re-run a challenge only if the trace
  shows it was close (e.g. right approach, wrong format/offset).
- **Triage first.** Start easy/medium challenges (cheap, build score). Give the
  insane one a single bounded attempt late, not your whole budget.
- **Kill early.** If `trace_digest.py` shows the agent looping or off-track in
  the first ~15 steps, stop it and adjust the `--description` (feed it the hint
  from the challenge page) rather than letting it burn 60 steps.
- Tunable loop-discipline knobs if needed: `CTF_REPEAT_LIMIT`,
  `CTF_RECON_HARD_CAP`, `CTF_TRANSITION_AT`.

## 5. Per-category quick tips (the agent has playbooks; these are for you)

- **Rev/Crypto/Forensics**: usually just files → download, run with
  `--network none`. Hard RE may lean on angr; crypto on gmpy2/z3; forensics on
  binwalk/tshark/steghide/zsteg.
- **Pwn/Web**: download any provided source/binary, pass the `--target`, run on
  host network. Pwn uses pwntools + ROPgadget/one_gadget; web uses requests.
- Put the challenge page's description/hint into `--description` — it meaningfully
  steers the agent.

## 6. If something breaks live

- Port/preflight errors → re-export the env vars (a shell restart drops them).
- Can't reach target → confirm the VPN is up on the host (`ping`/`nc` the target
  yourself), and that you used `--network host`.
- Tool missing in-run → it wasn't baked into the image; you can't pip-install at
  solve time (even on host network it's cleaner to rebuild). Note it and move on.
