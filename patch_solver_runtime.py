#!/usr/bin/env python3
"""Minimal, fail-closed integration patch for ml-ctf-agent/solver_runtime.py.

Preserves the original ctf-solver:dev default and runtime security options.
"""
from pathlib import Path
import sys

OLD_IMPORTS = "import subprocess\nimport uuid\nfrom pathlib import Path\n"
NEW_IMPORTS = "import os\nimport re\nimport subprocess\nimport uuid\nfrom pathlib import Path\n"
OLD_INIT = '    def __init__(self, image="ctf-solver:dev"):\n        self.image = image\n'
NEW_INIT = '''    def __init__(self, image=None):
        # Trusted-controller configuration; never accepted from agent tools.
        selected = image if image is not None else os.environ.get(
            "CTF_SOLVER_IMAGE", "ctf-solver:dev"
        )
        # Fail closed for malformed refs instead of passing them to Docker.
        if not isinstance(selected, str) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._/:@-]{0,199}", selected
        ):
            raise ValueError("Invalid CTF solver image reference")
        self.image = selected
'''

def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: patch_solver_runtime.py PATH_TO_SOLVER_RUNTIME")
    p = Path(sys.argv[1])
    source = p.read_text(encoding="utf-8")
    if OLD_IMPORTS not in source or OLD_INIT not in source:
        raise SystemExit(
            "Refusing to patch: solver_runtime.py differs from the inspected "
            "main-branch version. No changes made."
        )
    patched = source.replace(OLD_IMPORTS, NEW_IMPORTS, 1).replace(
        OLD_INIT, NEW_INIT, 1
    )
    compile(patched, str(p), "exec")
    p.write_text(patched, encoding="utf-8")
    print("Patched solver_runtime.py (default preserved: ctf-solver:dev)")

if __name__ == "__main__":
    main()
