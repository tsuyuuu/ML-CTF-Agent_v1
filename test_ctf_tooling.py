#!/usr/bin/env python3
"""Offline smoke checks for solver-side CTF libraries and binaries.

No challenge answers or network required. Run *inside* the tool image.
"""
from __future__ import annotations

import io
import shutil
import subprocess
import unittest


class CTFToolSmokeTests(unittest.TestCase):
    def test_reverse_engineering_commands(self):
        for name in ("file", "strings", "readelf", "objdump", "nm", "gdb"):
            with self.subTest(command=name):
                self.assertIsNotNone(shutil.which(name), f"missing {name}")

    def test_cryptography(self):
        from Crypto.Cipher import AES
        from sympy import mod_inverse
        key = b"0123456789abcdef"
        cipher = AES.new(key, AES.MODE_ECB)
        plain = b"sixteen-byte-msg"
        self.assertEqual(cipher.decrypt(cipher.encrypt(plain)), plain)
        self.assertEqual(mod_inverse(3, 11), 4)

    def test_symbolic_solver(self):
        from z3 import Int, Solver, sat
        x = Int("x")
        solver = Solver()
        solver.add(x * 2 == 14)
        self.assertEqual(solver.check(), sat)
        self.assertEqual(solver.model()[x].as_long(), 7)

    def test_binary_exploitation_helpers(self):
        from pwnlib.util.cyclic import cyclic, cyclic_find
        pattern = cyclic(64)
        self.assertEqual(cyclic_find(pattern[20:24]), 20)

    def test_web_libraries(self):
        import requests
        from bs4 import BeautifulSoup
        self.assertTrue(hasattr(requests, "Session"))
        self.assertEqual(BeautifulSoup("<p>ready</p>", "html.parser").p.text, "ready")

    def test_forensics_image_library(self):
        from PIL import Image
        output = io.BytesIO()
        Image.new("RGB", (2, 2)).save(output, format="PNG")
        output.seek(0)
        self.assertEqual(Image.open(output).size, (2, 2))

    def test_exiftool_installed(self):
        self.assertIsNotNone(shutil.which("exiftool"))

    def test_nonroot_and_no_docker_socket(self):
        import os
        self.assertNotEqual(os.geteuid(), 0, "solver should not run as root")
        self.assertFalse(os.path.exists("/var/run/docker.sock"), "Docker socket exposed!")


if __name__ == "__main__":
    unittest.main(verbosity=2)
