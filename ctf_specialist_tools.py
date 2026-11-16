"""Structured, bounded tool wrappers for the existing DockerSolver.

All shell commands execute in the existing isolated, unprivileged solver
container; this module never runs contestant input in the trusted controller.
"""

from __future__ import annotations

import base64
import shlex
import uuid

SPECIALIST_TOOL_NAMES = frozenset({"list_files", "run_python", "analyze_artifact"})
MAX_SCRIPT_BYTES = 2700
MAX_ARTIFACT_BYTES = 200 * 1024 * 1024


def _result(reply, *, kind, **fields):
    """Normalize output so the agent can recognize failures consistently."""
    if not isinstance(reply, dict):
        reply = {"error": "Unexpected solver response"}
    stdout = reply.get("stdout", "")
    stderr = reply.get("stderr", "")
    exit_code = reply.get("exit_code")
    timed_out = bool(reply.get("timed_out", False))
    error = reply.get("error")
    return {
        "ok": exit_code == 0 and not timed_out and not error,
        "kind": kind,
        "exit_code": exit_code,
        "stdout": stdout,
        "stderr": stderr,
        "truncated": bool(reply.get("truncated", False)),
        "timed_out": timed_out,
        **({"error": str(error)} if error else {}),
        **fields,
    }


def execute_specialist_tool(name, args, solver, safe_path, timeout_s=10):
    """Execute a recognized specialist tool with validated model arguments.

    `safe_path` MUST be the existing ToolDispatcher._safe_path so read access
    remains restricted to /challenge and /work and writes to /work.
    """
    if name not in SPECIALIST_TOOL_NAMES:
        raise ValueError("Unknown specialist tool")
    if not isinstance(args, dict):
        raise ValueError("Tool arguments must be an object")

    if name == "list_files":
        root = args.get("root", "/challenge")
        if root not in ("/challenge", "/work"):
            raise ValueError("Directory outside permitted roots")
        # No user string is interpolated: root is from a two-value allowlist.
        command = (
            f"test -d {root} && "
            f"find {root} -maxdepth 3 -type f -print | head -80"
        )
        result = _result(solver.run_command(command, timeout_s=timeout_s), kind=name)
        result["files"] = [p for p in result["stdout"].splitlines() if p][:80]
        return result

    if name == "run_python":
        code = args.get("code")
        if not isinstance(code, str) or not code.strip():
            raise ValueError("Python code must be nonempty text")
        data = code.encode("utf-8")
        if len(data) > MAX_SCRIPT_BYTES:
            raise ValueError(
                f"Python code exceeds {MAX_SCRIPT_BYTES} UTF-8 bytes; "
                "write a script using write_file and run it with run_command"
            )
        encoded = base64.b64encode(data).decode("ascii")
        filename = f"/work/ctf_{uuid.uuid4().hex}.py"
        command = (
            f"umask 077; printf '%s' '{encoded}' | base64 -d > "
            f"{shlex.quote(filename)} && python3 -B {shlex.quote(filename)}"
        )
        # DockerSolver.run_command caps command length at 4000 characters.
        if len(command) > 4000:
            raise ValueError("Encoded Python command exceeds runner limit")
        reply = solver.run_command(command, timeout_s=timeout_s)
        return _result(reply, kind=name, script_path=filename)

    # analyze_artifact: read-only, bounded inspection of existing file.
    path = safe_path(args.get("path"))
    mode = args.get("mode", "overview")
    if mode not in ("overview", "hex", "strings", "archive"):
        raise ValueError("Unsupported artifact analysis mode")
    quoted = shlex.quote(path)
    check = solver.run_command(
        f"test -f {quoted} && test ! -L {quoted} && "
        f"test $(wc -c < {quoted}) -le {MAX_ARTIFACT_BYTES}",
        timeout_s=timeout_s,
    )
    if check.get("exit_code") != 0:
        return {
            "ok": False,
            "kind": name,
            "mode": mode,
            "path": path,
            "error": "File missing, symbolic link, or exceeds 200 MiB",
        }
    commands = {
        "overview": f"file -- {quoted} && sha256sum -- {quoted} && exiftool {quoted} | head -55",
        "hex": f"xxd -l 512 {quoted}",
        "strings": f"strings -a -n 5 -- {quoted} | head -80",
        "archive": f"7z l -slt {quoted} | head -100",
    }
    reply = solver.run_command(commands[mode], timeout_s=timeout_s)
    return _result(reply, kind=name, path=path, mode=mode)
