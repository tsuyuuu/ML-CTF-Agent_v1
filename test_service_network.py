"""
Offline tests for the DockerSolver network option (P2 enabler).

Confirms the default stays fully offline (--network none) and that the
controller-only network argument is validated fail-closed. subprocess.run is
mocked, so no Docker daemon is required.

Run:  python3 -m unittest -v test_service_network
"""
import unittest
import solver_runtime


class FakeCompleted:
    def __init__(self, stdout="deadbeefcafe\n"):
        self.stdout = stdout
        self.stderr = ""
        self.returncode = 0


class RecordingRun:
    def __init__(self):
        self.last_cmd = None

    def __call__(self, cmd, *a, **k):
        self.last_cmd = cmd
        return FakeCompleted()


def net_flag(cmd):
    i = cmd.index("--network")
    return cmd[i + 1]


class SolverNetworkTest(unittest.TestCase):
    def setUp(self):
        self._orig = solver_runtime.subprocess.run
        self.rec = RecordingRun()
        solver_runtime.subprocess.run = self.rec

    def tearDown(self):
        solver_runtime.subprocess.run = self._orig

    def test_default_is_network_none(self):
        s = solver_runtime.DockerSolver(image="ctf-solver:dev")
        s.start()
        self.assertEqual(net_flag(self.rec.last_cmd), "none")
        # Core isolation flags must still be present.
        for flag in ("--read-only", "--cap-drop", "no-new-privileges"):
            self.assertIn(flag, self.rec.last_cmd)

    def test_internal_network_is_passed_through(self):
        s = solver_runtime.DockerSolver(image="ctf-solver:dev")
        s.start(network="ctf-net-abc123")
        self.assertEqual(net_flag(self.rec.last_cmd), "ctf-net-abc123")

    def test_host_network_is_rejected(self):
        s = solver_runtime.DockerSolver(image="ctf-solver:dev")
        with self.assertRaises(ValueError):
            s.start(network="host")

    def test_malformed_network_is_rejected(self):
        s = solver_runtime.DockerSolver(image="ctf-solver:dev")
        for bad in ("bad name", "--privileged", "a/b", "x" * 200):
            s.container_id = None
            with self.assertRaises(ValueError):
                s.start(network=bad)

    def test_host_allowed_only_with_flag(self):
        # Competition escape hatch: host/bridge permitted only when allow_host.
        s = solver_runtime.DockerSolver(image="ctf-solver:dev")
        s.start(network="host", allow_host=True)
        self.assertEqual(net_flag(self.rec.last_cmd), "host")
        s.container_id = None
        s.start(network="bridge", allow_host=True)
        self.assertEqual(net_flag(self.rec.last_cmd), "bridge")
        # Without the flag, host is still rejected (benchmark path stays locked).
        s.container_id = None
        with self.assertRaises(ValueError):
            s.start(network="host", allow_host=False)


if __name__ == "__main__":
    unittest.main(verbosity=2)
