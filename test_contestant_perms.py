"""
Regression test for the nested-contestant-file permission bug (msc-ezmaze).

A contestant file nested in a subdirectory must end up traversable+readable by
the unprivileged solver uid, even when staged under a restrictive umask. Proves
prepare_contestant_files normalizes dirs to o+rx and files to o+r.

nyuctf is stubbed so the module imports without the dataset package.

Run:  python3 -m unittest -v test_contestant_perms
"""
import os
import stat
import sys
import tempfile
import types
import unittest
from pathlib import Path

# Stub the nyuctf package so challenge_runner imports without it.
for name in ("nyuctf", "nyuctf.dataset", "nyuctf.challenge"):
    if name not in sys.modules:
        sys.modules[name] = types.ModuleType(name)
sys.modules["nyuctf.dataset"].CTFDataset = object
sys.modules["nyuctf.challenge"].CTFChallenge = object

import challenge_runner  # noqa: E402


class FakeChallenge:
    def __init__(self, challenge_dir, files):
        self.challenge_dir = challenge_dir
        self.files = files


class ContestantPermsTest(unittest.TestCase):
    def test_nested_file_is_traversable_and_readable(self):
        src = Path(tempfile.mkdtemp())
        (src / "attachment").mkdir()
        (src / "attachment" / "maze.pt").write_bytes(b"\x80\x04maze")

        workspace = Path(tempfile.mkdtemp())
        challenge = FakeChallenge(str(src), ["attachment/maze.pt"])

        old_umask = os.umask(0o077)  # force non-traversable dirs without the fix
        try:
            exported = challenge_runner.prepare_contestant_files(
                challenge, workspace)
        finally:
            os.umask(old_umask)

        self.assertEqual(exported, ["attachment/maze.pt"])

        dir_mode = stat.S_IMODE(os.stat(workspace / "attachment").st_mode)
        file_mode = stat.S_IMODE(os.stat(workspace / "attachment" / "maze.pt").st_mode)

        # "other" must have read+execute on the directory, read on the file.
        self.assertTrue(dir_mode & stat.S_IROTH, oct(dir_mode))
        self.assertTrue(dir_mode & stat.S_IXOTH, oct(dir_mode))
        self.assertTrue(file_mode & stat.S_IROTH, oct(file_mode))
        # and never writable by other
        self.assertFalse(file_mode & stat.S_IWOTH, oct(file_mode))


if __name__ == "__main__":
    unittest.main(verbosity=2)
