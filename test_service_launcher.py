"""
Offline tests for ServiceLauncher. subprocess.run is mocked, so no Docker
daemon, no image builds, and no network are required. These tests focus on the
two safety-critical guarantees and correct spec parsing.

Run:  python3 -m unittest -v test_service_launcher
"""
import tempfile
import unittest
from pathlib import Path

import service_launcher

PUFFIN_COMPOSE = """\
services:
  game-server:
    image: llmctf/2023q-pwn-puffin:latest
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    networks:
      ctfnet:
        aliases:
          - pwn.chal.csaw.io
    ports:
      - 31140:31140
networks:
  ctfnet:
    external: true
"""

PUFFIN_DOCKERFILE = "FROM ubuntu:22.04\nEXPOSE 31140\nCMD [\"socat\"]\n"

WEB_COMPOSE = """\
services:
  game-server:
    image: llmctf/2021q-web-poem_collection:latest
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    networks:
      ctfnet:
        aliases:
          - web.chal.csaw.io
networks:
  ctfnet:
    external: true
"""

WEB_DOCKERFILE = "FROM php:7.0-apache\nUSER nobody\n"


class FakeCompleted:
    def __init__(self, returncode=0, stdout="id\n", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class RecordingRun:
    """Records every subprocess.run invocation; returns success by default."""
    def __init__(self, probe_ready=True):
        self.calls = []
        self.probe_ready = probe_ready

    def __call__(self, cmd, *a, **k):
        self.calls.append(cmd)
        # Probe container: return 0 only when probe_ready.
        if "--entrypoint" in cmd and "python3" in cmd:
            return FakeCompleted(returncode=0 if self.probe_ready else 1)
        return FakeCompleted()

    def cmds_with(self, token):
        return [c for c in self.calls if token in c]


def make_challenge(tmp, compose, dockerfile):
    d = Path(tmp)
    (d / "docker-compose.yml").write_text(compose)
    (d / "Dockerfile").write_text(dockerfile)
    return d


class ServiceLauncherTest(unittest.TestCase):
    def setUp(self):
        self._orig = service_launcher.subprocess.run

    def tearDown(self):
        service_launcher.subprocess.run = self._orig

    def _launcher(self, compose, dockerfile, category="", probe_ready=True):
        tmp = tempfile.mkdtemp()
        make_challenge(tmp, compose, dockerfile)
        rec = RecordingRun(probe_ready=probe_ready)
        service_launcher.subprocess.run = rec
        lab = service_launcher.ServiceLauncher(
            tmp, "test-chal", category=category, probe_image="ctf-solver:dev")
        return lab, rec

    # -- parsing ------------------------------------------------------------
    def test_pwn_spec(self):
        lab, _ = self._launcher(PUFFIN_COMPOSE, PUFFIN_DOCKERFILE, "pwn")
        spec = lab.parse_spec()
        self.assertEqual(spec["port"], 31140)
        self.assertIn("pwn.chal.csaw.io", spec["aliases"])
        self.assertIn("target", spec["aliases"])
        self.assertTrue(spec["socket_requested"])

    def test_web_spec_defaults_to_80(self):
        lab, _ = self._launcher(WEB_COMPOSE, WEB_DOCKERFILE, "web")
        spec = lab.parse_spec()
        self.assertEqual(spec["port"], 80)       # no ports/EXPOSE -> apache 80
        self.assertIn("web.chal.csaw.io", spec["aliases"])

    # -- safety-critical: socket is NEVER mounted ---------------------------
    def test_target_run_never_mounts_socket(self):
        lab, rec = self._launcher(PUFFIN_COMPOSE, PUFFIN_DOCKERFILE, "pwn")
        lab.parse_spec()
        lab.create_network()
        lab.start_target()
        run_cmd = rec.cmds_with("run")[0]
        joined = " ".join(run_cmd)
        self.assertNotIn("docker.sock", joined)
        self.assertNotIn("-v", run_cmd)
        self.assertNotIn("--mount", run_cmd)
        self.assertNotIn("--privileged", run_cmd)
        # but it IS on our network with the alias
        self.assertIn("--network", run_cmd)
        self.assertIn(lab.network_name, run_cmd)
        self.assertIn("pwn.chal.csaw.io", run_cmd)

    # -- safety-critical: network is internal (no internet) -----------------
    def test_network_is_internal(self):
        lab, rec = self._launcher(PUFFIN_COMPOSE, PUFFIN_DOCKERFILE, "pwn")
        lab.create_network()
        net_cmd = [c for c in rec.calls if "network" in c and "create" in c][0]
        self.assertIn("--internal", net_cmd)

    # -- full bring-up + teardown -------------------------------------------
    def test_up_and_teardown(self):
        lab, rec = self._launcher(PUFFIN_COMPOSE, PUFFIN_DOCKERFILE, "pwn")
        host, port = lab.up()
        self.assertEqual((host, port), ("pwn.chal.csaw.io", 31140))
        # build, network create, target run, and at least one probe happened
        self.assertTrue(rec.cmds_with("build"))
        self.assertTrue([c for c in rec.calls if "network" in c and "create" in c])
        lab.teardown()
        rm = [c for c in rec.calls if "rm" in c]
        self.assertTrue(any(lab.target_name in c for c in rm))
        self.assertTrue(any(lab.network_name in c for c in rm))

    def test_not_ready_raises(self):
        lab, rec = self._launcher(
            PUFFIN_COMPOSE, PUFFIN_DOCKERFILE, "pwn", probe_ready=False)
        lab.ready_attempts = 2
        lab.ready_interval_s = 0
        lab.parse_spec(); lab.create_network(); lab.start_target()
        with self.assertRaises(service_launcher.ServiceLaunchError):
            lab.wait_ready()


if __name__ == "__main__":
    unittest.main(verbosity=2)
