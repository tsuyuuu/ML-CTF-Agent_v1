"""
service_launcher.py - Trusted target-service launcher for CTF service challenges.

This component runs ONLY in the trusted controller. It brings up the
challenge's target service so the isolated solver can interact with it over a
single authorized port, then tears everything down.

Security model (all enforced here, never delegated to the solver/agent):

* The solver NEVER receives the Docker socket. The challenge compose files ship
  a `/var/run/docker.sock` bind mount (CSAW harness convention); this launcher
  deliberately IGNORES the compose `volumes:` and builds its own `docker run`
  command, so the socket is never mounted into any container we start.
* The target runs on a freshly created `--internal` Docker network. Internal
  networks have NO route to the internet, so neither the target nor the solver
  attached to it can reach the outside world (this also preserves the
  "no looking up the answer online" guarantee).
* The flag lives inside the target image (the challenge Dockerfile COPYs
  flag.txt). It is reachable only by exploiting the service over its port. The
  launcher never copies the flag into the solver and never passes it as output.
* The target is given resource caps and no Docker socket; the solver keeps its
  full hardening (see solver_runtime.DockerSolver). The target is run close to
  its intended configuration otherwise, because it is meant to be exploitable.

The launcher does not read, parse, or log the flag value.
"""

from __future__ import annotations

import re
import subprocess
import time
import uuid
from pathlib import Path


# A Docker/compose name we are willing to pass to the daemon.
_SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
# Compose network alias / hostname the agent will connect to.
_SAFE_ALIAS = re.compile(r"[A-Za-z0-9]([A-Za-z0-9._-]{0,253})")


class ServiceLaunchError(RuntimeError):
    """Raised when the target service cannot be prepared or started."""


class ServiceLauncher:
    def __init__(
        self,
        challenge_dir,
        challenge_id,
        category="",
        probe_image=None,
        build_timeout_s=600,
        run_timeout_s=60,
        ready_attempts=40,
        ready_interval_s=1.0,
    ):
        self.challenge_dir = Path(challenge_dir).resolve()
        if not self.challenge_dir.is_dir():
            raise ServiceLaunchError("Challenge directory not found")
        self.challenge_id = challenge_id
        self.category = (category or "").lower()

        token = uuid.uuid4().hex[:12]
        safe_id = re.sub(r"[^A-Za-z0-9]+", "-", challenge_id).strip("-")[:40] or "chal"
        self.network_name = f"ctfnet-{safe_id}-{token}"
        self.target_name = f"ctftgt-{safe_id}-{token}"
        self.image_tag = f"ctf-target-{safe_id}:{token}"

        # probe uses the solver tool image by default (it has python3).
        import os
        self.probe_image = probe_image or os.environ.get(
            "CTF_SOLVER_IMAGE", "ctf-solver:dev"
        )
        self.build_timeout_s = build_timeout_s
        self.run_timeout_s = run_timeout_s
        self.ready_attempts = ready_attempts
        self.ready_interval_s = ready_interval_s

        self._network_created = False
        self._target_started = False
        self._spec = None  # parsed compose spec

    # -- compose parsing ----------------------------------------------------
    def _compose_path(self):
        for name in ("docker-compose.yml", "docker-compose.yaml",
                     "compose.yml", "compose.yaml"):
            path = self.challenge_dir / name
            if path.exists():
                return path
        return None

    def parse_spec(self):
        """Extract the target's aliases and port from compose + Dockerfile.

        Returns a dict: {aliases, port, socket_requested}. Never trusts the
        compose `volumes:`/`networks:` sections for what we run.
        """
        compose = self._compose_path()
        aliases = []
        port = None
        socket_requested = False

        data = {}
        if compose is not None:
            text = compose.read_text(encoding="utf-8", errors="replace")
            socket_requested = "docker.sock" in text
            try:
                import yaml
                data = yaml.safe_load(text) or {}
            except Exception:
                data = {}

        services = data.get("services", {}) if isinstance(data, dict) else {}
        # Use the first service that declares a port or aliases, else the first.
        chosen = None
        for name, svc in services.items():
            if not isinstance(svc, dict):
                continue
            if chosen is None:
                chosen = svc
            if svc.get("ports") or (
                isinstance(svc.get("networks"), dict)
            ):
                chosen = svc
                break

        if isinstance(chosen, dict):
            # aliases: services.<svc>.networks.<net>.aliases
            nets = chosen.get("networks")
            if isinstance(nets, dict):
                for net in nets.values():
                    if isinstance(net, dict):
                        for alias in net.get("aliases", []) or []:
                            if isinstance(alias, str) and _SAFE_ALIAS.fullmatch(alias):
                                aliases.append(alias)
            # port: first of services.<svc>.ports ("H:C" or "C")
            for mapping in chosen.get("ports", []) or []:
                spec = str(mapping).split("/")[0]
                container_port = spec.split(":")[-1]
                if container_port.isdigit():
                    port = int(container_port)
                    break
            if port is None:
                for ex in chosen.get("expose", []) or []:
                    if str(ex).isdigit():
                        port = int(ex)
                        break

        # Regex fallback (PyYAML unavailable, or an unusual structure):
        # recover aliases and the container port straight from the text.
        if compose is not None:
            if not aliases:
                m = re.search(
                    r"aliases:\s*\n((?:[ \t]*-[ \t]*\S+[ \t]*\n?)+)", text
                )
                if m:
                    aliases = re.findall(r"-\s*(\S+)", m.group(1))
            if port is None:
                pm = re.search(
                    r"ports:\s*\n((?:[ \t]*-[ \t]*[^\n]+\n?)+)", text
                )
                if pm:
                    nums = re.findall(r"(\d+)", pm.group(1))
                    if nums:
                        # container port is the last number in "H:C" or "C"
                        port = int(nums[-1])

        # Fallbacks when compose omits the port.
        if port is None:
            port = self._port_from_dockerfile()
        if port is None and self.category == "web":
            port = 80
        if port is None:
            raise ServiceLaunchError(
                f"{self.challenge_id}: could not determine target port; "
                "declare it in the launcher config"
            )
        if not aliases:
            aliases = ["target"]
        # Always give a generic alias too so solve scripts and the agent can
        # use a predictable name in addition to the challenge's own hostname.
        if "target" not in aliases:
            aliases.append("target")

        aliases = [a for a in aliases if _SAFE_ALIAS.fullmatch(a)]
        self._spec = {
            "aliases": aliases,
            "port": port,
            "socket_requested": socket_requested,
        }
        return self._spec

    def _port_from_dockerfile(self):
        dockerfile = self.challenge_dir / "Dockerfile"
        if not dockerfile.exists():
            return None
        for line in dockerfile.read_text(
            encoding="utf-8", errors="replace"
        ).splitlines():
            m = re.match(r"\s*EXPOSE\s+(\d+)", line, re.IGNORECASE)
            if m:
                return int(m.group(1))
        return None

    # -- docker lifecycle ---------------------------------------------------
    def _run(self, cmd, *, timeout, check=True):
        return subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=check
        )

    def build_target_image(self):
        """Build the target image from the challenge Dockerfile (flag baked in)."""
        if not (self.challenge_dir / "Dockerfile").exists():
            raise ServiceLaunchError(
                f"{self.challenge_id}: no Dockerfile to build the target"
            )
        try:
            self._run(
                ["docker", "build", "-t", self.image_tag,
                 "-f", str(self.challenge_dir / "Dockerfile"),
                 str(self.challenge_dir)],
                timeout=self.build_timeout_s,
            )
        except subprocess.CalledProcessError as exc:
            raise ServiceLaunchError(
                f"Target image build failed: {exc.stderr[:400]}"
            ) from exc

    def create_network(self):
        """Create an internal (no-internet) network for solver<->target only."""
        if not _SAFE_NAME.fullmatch(self.network_name):
            raise ServiceLaunchError("Unsafe network name")
        self._run(
            ["docker", "network", "create", "--internal",
             "--driver", "bridge", self.network_name],
            timeout=30,
        )
        self._network_created = True
        return self.network_name

    def start_target(self):
        """Run the target on the internal network. NEVER mounts the socket."""
        if self._spec is None:
            self.parse_spec()

        cmd = [
            "docker", "run", "-d", "--rm",
            "--name", self.target_name,
            "--network", self.network_name,
            # Resource caps to bound a misbehaving target.
            "--pids-limit", "256",
            "--memory", "512m",
            "--cpus", "1",
        ]
        for alias in self._spec["aliases"]:
            cmd += ["--network-alias", alias]
        # Intentionally: no -v/--mount (drops the compose docker.sock mount),
        # no --privileged, no extra hosts. Image entrypoint/cmd are preserved.
        cmd += [self.image_tag]

        try:
            self._run(cmd, timeout=self.run_timeout_s)
        except subprocess.CalledProcessError as exc:
            raise ServiceLaunchError(
                f"Target start failed: {exc.stderr[:400]}"
            ) from exc
        self._target_started = True

    def wait_ready(self):
        """Poll the target port from a throwaway container on the network."""
        host = self._spec["aliases"][0]
        port = self._spec["port"]
        probe = (
            "import socket,sys\n"
            f"s=socket.socket()\ns.settimeout(2)\n"
            f"sys.exit(0 if s.connect_ex(({host!r},{port}))==0 else 1)"
        )
        for _ in range(self.ready_attempts):
            try:
                result = self._run(
                    ["docker", "run", "--rm", "--network", self.network_name,
                     "--entrypoint", "python3", self.probe_image, "-c", probe],
                    timeout=self.run_timeout_s, check=False,
                )
                if result.returncode == 0:
                    return True
            except subprocess.TimeoutExpired:
                pass
            time.sleep(self.ready_interval_s)
        raise ServiceLaunchError(
            f"{self.challenge_id}: target did not become ready on "
            f"{host}:{port}"
        )

    def target_address(self):
        """Return (host, port) the agent should connect to."""
        if self._spec is None:
            self.parse_spec()
        return self._spec["aliases"][0], self._spec["port"]

    def up(self):
        """Full bring-up: build -> network -> start -> ready. Returns address."""
        self.parse_spec()
        self.build_target_image()
        self.create_network()
        self.start_target()
        self.wait_ready()
        return self.target_address()

    def teardown(self):
        """Idempotent cleanup of target container and network."""
        if self._target_started:
            subprocess.run(
                ["docker", "rm", "-f", self.target_name],
                capture_output=True, timeout=30, check=False,
            )
            self._target_started = False
        if self._network_created:
            subprocess.run(
                ["docker", "network", "rm", self.network_name],
                capture_output=True, timeout=30, check=False,
            )
            self._network_created = False
