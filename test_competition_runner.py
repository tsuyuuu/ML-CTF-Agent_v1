"""
Offline tests for competition_runner helpers: file staging (perms) and the
format-based candidate verifier. No Docker / Ollama / network.

Run:  python3 -m unittest -v test_competition_runner
"""
import os
import re
import stat
import tempfile
import unittest
from pathlib import Path

import competition_runner
from flag_verifier import FlagVerifier


class StageFilesTest(unittest.TestCase):
    def test_nested_files_staged_readable(self):
        src = Path(tempfile.mkdtemp())
        (src / "sub").mkdir()
        (src / "sub" / "bin").write_bytes(b"\x7fELF")
        (src / "readme.txt").write_text("hint")

        ws = Path(tempfile.mkdtemp())
        old = os.umask(0o077)
        try:
            exported = competition_runner.stage_files(src, ws)
        finally:
            os.umask(old)

        self.assertIn("readme.txt", exported)
        self.assertIn(os.path.join("sub", "bin"), exported)
        # nested dir traversable, file readable by "other" (the solver uid)
        dmode = stat.S_IMODE(os.stat(ws / "sub").st_mode)
        fmode = stat.S_IMODE(os.stat(ws / "sub" / "bin").st_mode)
        self.assertTrue(dmode & stat.S_IXOTH and dmode & stat.S_IROTH)
        self.assertTrue(fmode & stat.S_IROTH)


class CandidateVerifierTest(unittest.TestCase):
    def setUp(self):
        self.re = re.compile(competition_runner.DEFAULT_FLAG_FORMAT)
        self.v = FlagVerifier(verify_callback=lambda c: bool(self.re.search(c)))

    def test_format_valid_flag_accepted_and_recorded(self):
        self.assertTrue(self.v.verify("HTB{sym_exec_ftw}")["verified"])
        self.assertTrue(self.v.verify("flag{abc}")["verified"])
        self.assertTrue(self.v.verify("csawctf{y0ure_a_m4s7er}")["verified"])
        self.assertEqual(len(self.v.submissions), 3)

    def test_non_flag_rejected(self):
        self.assertFalse(self.v.verify("not a flag")["verified"])
        self.assertFalse(self.v.verify("")["verified"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
