#!/usr/bin/env bash
# Apply the reviewed tool-image upgrade to a clean ml-ctf-agent checkout.
set -euo pipefail
BUNDLE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="${1:-/workspaces/ml-ctf-agent}"
REPO_URL="https://github.com/tsuyuuu/ml-ctf-agent.git"
BRANCH="feat/ctftiny-solver-tooling"

if [[ ! -d "${REPO_DIR}/.git" ]]; then
  echo "Cloning ${REPO_URL} into ${REPO_DIR}..."
  git clone "$REPO_URL" "$REPO_DIR"
fi
cd "$REPO_DIR"
ORIGIN="$(git remote get-url origin)"
case "$ORIGIN" in
  "https://github.com/tsuyuuu/ml-ctf-agent.git"|"https://github.com/tsuyuuu/ml-ctf-agent"|"git@github.com:tsuyuuu/ml-ctf-agent.git") ;;
  *) echo "Unexpected origin: $ORIGIN (refusing to modify another repository)" >&2; exit 1 ;;
esac
if [[ -n "$(git status --porcelain)" ]]; then
  echo "Working tree is not clean. Commit or stash your edits before applying."
  exit 1
fi
if [[ "$(git branch --show-current)" != "$BRANCH" ]]; then
  git switch -c "$BRANCH"
fi

for file in Dockerfile.ctf-tools requirements.solver-tools.txt ctf_tool_audit.py test_ctf_tooling.py test_solver_image_selection.py; do
  if [[ -e "$file" ]]; then
    echo "Refusing to overwrite existing file: $file" >&2
    exit 1
  fi
done
cp "$BUNDLE_DIR"/{Dockerfile.ctf-tools,requirements.solver-tools.txt,ctf_tool_audit.py,test_ctf_tooling.py,test_solver_image_selection.py} .
python3 "$BUNDLE_DIR/patch_solver_runtime.py" solver_runtime.py
python3 - <<'PYCODE'
from pathlib import Path
for name in ("solver_runtime.py", "ctf_tool_audit.py", "test_ctf_tooling.py", "test_solver_image_selection.py"):
    compile(Path(name).read_text(encoding="utf-8"), name, "exec")
print("Python source syntax checks passed")
PYCODE
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v test_solver_image_selection

git diff --check
cat <<'EOF'

Upgrade applied in a NEW LOCAL BRANCH. No remote GitHub branch or PR was created.

Next, build and smoke-test in Codespaces:
  docker build -f Dockerfile.solver -t ctf-solver:dev .
  docker build -f Dockerfile.ctf-tools -t ctf-solver:tools-v1 .
  docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges --read-only --tmpfs /tmp:rw,nosuid,size=64m --entrypoint python ctf-solver:tools-v1 /opt/ctf-tools/ctf_tool_audit.py --strict
  docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges --read-only --tmpfs /tmp:rw,nosuid,size=64m --entrypoint python ctf-solver:tools-v1 /opt/ctf-tools/test_ctf_tooling.py

When these pass, enable the new image for DEVELOPMENT ONLY:
  export CTF_SOLVER_IMAGE=ctf-solver:tools-v1

Inspect changes before committing/pushing:
  git status --short
  git diff -- solver_runtime.py
  git add Dockerfile.ctf-tools requirements.solver-tools.txt ctf_tool_audit.py test_ctf_tooling.py test_solver_image_selection.py solver_runtime.py
  git commit -m 'Add isolated CTFTiny solver tool image and offline tests'
  git push -u origin feat/ctftiny-solver-tooling
EOF
