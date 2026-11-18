
import base64
import shlex
from pathlib import PurePosixPath

from ctf_tools import (
    inspect_binary,
    disassemble_binary,
    extract_stack_constants,
)
from ctf_specialist_tools import (
    SPECIALIST_TOOL_NAMES,
    execute_specialist_tool,
    _stage_bytes,
)


# Size limits (bytes). Raised from the original 2000/6000: those were far too
# small -- read_file silently truncated any source file over 6 KB, and
# write_file could not hold a real script. These ceilings still bound a single
# tool result while letting the agent read whole files and write real scripts.
_MAX_READ_BYTES = 131072    # 128 KiB -- read a whole source file / notebook
_MAX_WRITE_BYTES = 262144   # 256 KiB -- hold a real script or data blob


# Switches between tools, choosing which ones should be called as necessary.
class ToolDispatcher:
    def __init__(self, solver, verifier=None):
        self.solver = solver
        self.verifier = verifier
    # Ensures that the path is permitted, not outside of reasonable work environment
    def _safe_path(self, raw_path, write=False):
        if not isinstance(raw_path, str) or not raw_path:
            raise ValueError("Invalid path")

        if "\x00" in raw_path:
            raise ValueError("Invalid path")

        path = PurePosixPath(raw_path)

        if ".." in path.parts:
            raise ValueError("Parent directory traversal blocked")

        if not path.is_absolute():
            path = PurePosixPath("/work") / path

        value = str(path)

        if write:
            allowed = value.startswith("/work/")
        else:
            allowed = (
                value.startswith("/work/")
                or value.startswith("/challenge/")
            )

        if not allowed:
            raise ValueError("Path outside permitted workspace")

        return value
    # Different tools that can be called, looking at each name to see if needed
    # This code was created using ChatGPT-6 on November 10, 2026. The code was reviewed and debugged by team members to fit desired results.
    # The changing by name portions were handwriten, but the checks and other variables were generated
    def __call__(self, name, args, timeout_s=10):
        try:
            if name in SPECIALIST_TOOL_NAMES:
                return execute_specialist_tool(
                    name, args, self.solver, self._safe_path,
                    timeout_s=timeout_s,
                )
            if name == "inspect_binary":
                path = self._safe_path(args["path"])

                # Inspect only a regular file within the solver.
                # The size check prevents excessive processing.
                quoted = shlex.quote(path)

                check = self.solver.run_command(
                    f"test -f {quoted} && "
                    f"test ! -L {quoted} && "
                    f"test $(wc -c < {quoted}) -le 10485760",
                    timeout_s=timeout_s,
                )

                if check.get("exit_code") != 0:
                    return {
                        "error": (
                            "File missing, symbolic link, "
                            "or exceeds 10 MiB"
                        )
                    }

                return inspect_binary(self.solver, path)

            elif name == "disassemble_binary":
                path = self._safe_path(args["path"])

                quoted = shlex.quote(path)
                check = self.solver.run_command(
                    f"test -f {quoted} && "
                    f"test ! -L {quoted} && "
                    f"test $(wc -c < {quoted}) -le 10485760",
                    timeout_s=timeout_s,
                )

                if check.get("exit_code") != 0:
                    return {
                        "error": "File missing, symbolic link, or exceeds 10 MiB"
                    }

                return disassemble_binary(
                    self.solver,
                    path,
                    args["start_address"],
                    args["stop_address"],
                )

            elif name == "extract_stack_constants":
                path = self._safe_path(args["path"])

                quoted = shlex.quote(path)
                check = self.solver.run_command(
                    f"test -f {quoted} && "
                    f"test ! -L {quoted} && "
                    f"test $(wc -c < {quoted}) -le 10485760",
                    timeout_s=timeout_s,
                )

                if check.get("exit_code") != 0:
                    return {
                        "error": "File missing, symbolic link, or exceeds 10 MiB"
                    }

                return extract_stack_constants(
                    self.solver,
                    path,
                    args.get("function_name", "main"),
                )
            elif name == "run_command":
                command = args["command"]

                return self.solver.run_command(
                    command, timeout_s=timeout_s
                )

            elif name == "read_file":
                path = self._safe_path(args["path"])

                command = (
                    "head -c " + str(_MAX_READ_BYTES + 1) + " -- "
                    + shlex.quote(path)
                )

                result = self.solver.run_command(
                    command, timeout_s=timeout_s
                )

                output = result.get("stdout", "")

                return {
                    "content": output[:_MAX_READ_BYTES],
                    "truncated": len(output) > _MAX_READ_BYTES,
                    "exit_code": result.get("exit_code"),
                    "error": result.get("stderr", "")
                }

            elif name == "write_file":
                path = self._safe_path(
                    args["path"], write=True
                )

                content = args["content"]

                if not isinstance(content, str):
                    return {"error": "Content must be text"}

                data = content.encode("utf-8")
                if len(data) > _MAX_WRITE_BYTES:
                    return {
                        "error": "Content exceeds 256 KiB"
                    }

                # Stage in chunks so large content is not blocked by the
                # solver's 4000-char per-command limit.
                result = _stage_bytes(
                    self.solver, path, data, timeout_s=timeout_s
                )

                return {
                    "written": isinstance(result, dict)
                    and result.get("exit_code") == 0,
                    "path": path,
                    "error": result.get("stderr", "")
                    if isinstance(result, dict) else "staging failed",
                }

            elif name == "submit_flag":
                if self.verifier is None:
                    return {
                        "verified": False,
                        "error": "Private evaluator not configured"
                    }

                return self.verifier.verify(args["flag"])

            elif name == "finish":
                return {
                    "finished": True,
                    "reason": args.get("reason", "")
                }

            return {
                "error": "Unknown tool",
                "error_type": "ValueError"
            }

        except (ValueError, KeyError, TypeError) as e:
            message = str(e)
            # Looks for out of scope violation to run
            is_scope_violation = (
                message == "Path outside permitted workspace"
                or message == "Parent directory traversal blocked"
            )

            return {
                "error": message,
                "error_type": type(e).__name__,
                "scope_violation": is_scope_violation,
            }
