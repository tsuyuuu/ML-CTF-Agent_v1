# ml-ctf-agent: CTFTiny tooling upgrade

Prepared against `tsuyuuu/ml-ctf-agent` main at `928998a6aa98ce9364848ec40a04a2d18a0e144e` (Nov 15, 2026 read). No push is included.

## Apply in GitHub Codespaces

From the folder where you extracted this ZIP:

```bash
bash ./apply_upgrade.sh /workspaces/ml-ctf-agent
```

If no clone exists, the script clones the repository itself. It creates a new local branch named `feat/ctftiny-solver-tooling`, adds tool-image files, patches `solver_runtime.py` to honor `CTF_SOLVER_IMAGE` from the trusted controller environment, and runs offline Python unit tests. Existing `ctf-solver:dev` behavior is the default; all scoring artifacts are untouched.

**Inspect the output**; the script deliberately refuses to change a dirty or unexpected checkout. It does not automatically commit or push.

## Docker validation

```bash
docker build -f Dockerfile.solver -t ctf-solver:dev .
docker build -f Dockerfile.ctf-tools -t ctf-solver:tools-v1 .
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges --read-only --tmpfs /tmp:rw,nosuid,size=64m --entrypoint python ctf-solver:tools-v1 /opt/ctf-tools/ctf_tool_audit.py --json --strict
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges --read-only --tmpfs /tmp:rw,nosuid,size=64m --entrypoint python ctf-solver:tools-v1 /opt/ctf-tools/test_ctf_tooling.py
```

Development sessions can then select the new image with `export CTF_SOLVER_IMAGE=ctf-solver:tools-v1`. Do not use original scored evaluation outputs as a test destination. The image still runs through `DockerSolver.start` with the project's existing isolation options.

## Scope and limits

This first change installs useful cross-category libraries and command-line utilities. It does not add Ghidra, pwntools-specific agent tool schemas, live HTTP target networking, challenge-category planning, or service challenge setup. It **has not been Docker-built or used to solve CTFTiny challenges** in this environment. That requires Codespaces and an authorized target configuration.

## Attribution

Upgrade scaffolding and tests prepared with AI assistance; team members should review changes, test them in Codespaces, and disclose the assistance as required by the course.
