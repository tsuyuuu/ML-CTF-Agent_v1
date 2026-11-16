import base64
import os
import re
import unittest
from unittest.mock import patch

from ctf_specialist_tools import execute_specialist_tool
from ctf_runtime_config import limits_from_env


class FakeSolver:
    def __init__(self):
        self.commands = []
    def run_command(self, command, timeout_s=10):
        self.commands.append((command, timeout_s))
        if command.startswith("test -f"):
            return {"exit_code": 0, "stdout": "", "stderr": "", "truncated": False}
        if command.startswith("test -d"):
            return {"exit_code": 0, "stdout": "/challenge/one.txt\n/challenge/two.bin\n", "stderr": ""}
        return {"exit_code": 0, "stdout": "example", "stderr": "", "truncated": False}


def safe_path(path):
    if not isinstance(path, str) or ".." in path.split("/") or not path.startswith(("/challenge/", "/work/")):
        raise ValueError("Path outside permitted workspace")
    return path


class SpecialistToolTests(unittest.TestCase):
    def setUp(self):
        self.solver = FakeSolver()

    def call(self, name, args):
        return execute_specialist_tool(name, args, self.solver, safe_path)

    def test_list_files_works(self):
        result = self.call("list_files", {"root": "/challenge"})
        self.assertTrue(result["ok"])
        self.assertEqual(result["files"], ["/challenge/one.txt", "/challenge/two.bin"])

    def test_list_files_rejects_outside_directory(self):
        with self.assertRaises(ValueError):
            self.call("list_files", {"root": "/etc"})
        self.assertFalse(self.solver.commands)

    def test_run_python_is_base64_encoded_and_bounded(self):
        source = 'from Crypto.Util.number import long_to_bytes\nprint(long_to_bytes(65))'
        r = self.call("run_python", {"code": source})
        self.assertTrue(r["ok"])
        cmd = self.solver.commands[0][0]
        encoded = re.search(r"printf '%s' '([^']+)'", cmd).group(1)
        self.assertEqual(base64.b64decode(encoded).decode(), source)
        self.assertLess(len(cmd), 4000)
        self.assertTrue(r["script_path"].startswith("/work/ctf_"))

    def test_run_python_rejects_oversized(self):
        with self.assertRaises(ValueError):
            self.call("run_python", {"code": "x" * 2701})
        self.assertFalse(self.solver.commands)

    def test_run_python_rejects_nontext(self):
        with self.assertRaises(ValueError):
            self.call("run_python", {"code": 123})
        self.assertFalse(self.solver.commands)

    def test_artifact_mode_and_path_safety(self):
        with self.assertRaises(ValueError):
            self.call("analyze_artifact", {"path": "/etc/passwd", "mode": "overview"})
        self.assertFalse(self.solver.commands)
        r = self.call("analyze_artifact", {"path": "/challenge/a.zip", "mode": "archive"})
        self.assertTrue(r["ok"])
        self.assertIn("7z l -slt", self.solver.commands[-1][0])

    def test_invalid_artifact_mode_never_executes(self):
        with self.assertRaises(ValueError):
            self.call("analyze_artifact", {"path": "/challenge/a", "mode": "exec"})
        self.assertFalse(self.solver.commands)

    def test_timeout_surfaces_in_structured_result(self):
        class TimeoutSolver(FakeSolver):
            def run_command(self, command, timeout_s=10):
                return {"timed_out": True, "error": "timeout"}
        r = execute_specialist_tool("run_python", {"code": "print(1)"}, TimeoutSolver(), safe_path)
        self.assertFalse(r["ok"])
        self.assertTrue(r["timed_out"])

    def test_default_limits(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(limits_from_env(), (15, 300))

    def test_configurable_limits_and_caps(self):
        with patch.dict(os.environ, {"CTF_MAX_STEPS": "40", "CTF_MAX_SECONDS": "900"}):
            self.assertEqual(limits_from_env(), (40, 900))
        with patch.dict(os.environ, {"CTF_MAX_STEPS": "0", "CTF_MAX_SECONDS": "900"}):
            with self.assertRaises(ValueError):
                limits_from_env()
        with patch.dict(os.environ, {"CTF_MAX_STEPS": "40", "CTF_MAX_SECONDS": "99999"}):
            with self.assertRaises(ValueError):
                limits_from_env()


if __name__ == "__main__":
    unittest.main()
