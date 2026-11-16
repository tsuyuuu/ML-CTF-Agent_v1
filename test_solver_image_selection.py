"""Offline unit tests for trusted-controller solver image selection.

Does not invoke Docker or the Ollama Cloud API.
"""
import os
import unittest
from unittest.mock import patch

from solver_runtime import DockerSolver


class SolverImageSelectionTests(unittest.TestCase):
    def test_default_unchanged(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(DockerSolver().image, "ctf-solver:dev")

    def test_env_override(self):
        with patch.dict(os.environ, {"CTF_SOLVER_IMAGE": "ctf-solver:tools-v1"}):
            self.assertEqual(DockerSolver().image, "ctf-solver:tools-v1")

    def test_explicit_image_wins(self):
        with patch.dict(os.environ, {"CTF_SOLVER_IMAGE": "ctf-solver:tools-v1"}):
            self.assertEqual(DockerSolver(image="ctf-solver:dev").image, "ctf-solver:dev")

    def test_malformed_reference_rejected(self):
        for candidate in ("", " image", "image;touch /tmp/unsafe", "image\nhello", None):
            with self.subTest(candidate=candidate):
                if candidate is None:
                    with patch.dict(os.environ, {"CTF_SOLVER_IMAGE": "invalid image"}):
                        with self.assertRaises(ValueError):
                            DockerSolver()
                else:
                    with self.assertRaises(ValueError):
                        DockerSolver(image=candidate)


if __name__ == "__main__":
    unittest.main(verbosity=2)
