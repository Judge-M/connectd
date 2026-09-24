"""Ephemeral worker process boundary with profile-dependent isolation."""

import os
import json
import shutil
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID

from pydantic import BaseModel, Field

from connectd.config import ExecutionProfile, GrantMode, WorkerRuntime
from connectd.worker import Ticket, WorkerReport


class SecurityBoundaryViolation(Exception):
    pass


class WorkerInput(BaseModel):
    ticket: Ticket
    worker_id: UUID
    task_id: str
    tool: dict
    model_base_url: str
    model_id: str
    control_plane_url: str
    worker_token: str
    model_api_auth: bool = False
    max_turns: int = Field(default=5, ge=1, le=5)


def select_runtime(profile: ExecutionProfile, effect_tier: int) -> WorkerRuntime:
    runtime = profile.worker_runtime
    if profile.grant_mode == GrantMode.STRICT_ED25519 and runtime == WorkerRuntime.SUBPROCESS:
        raise SecurityBoundaryViolation("prod_secure prohibits subprocess workers")
    if profile.grant_mode == GrantMode.RISK_TIERED and effect_tier == 2 and runtime == WorkerRuntime.SUBPROCESS:
        return WorkerRuntime.DOCKER
    return runtime


class WorkerLauncher:
    def __init__(self, image: str = "connectd-worker:local", docker_network: str | None = None):
        self.image = image
        self.docker_network = docker_network

    @staticmethod
    def _container_url(url: str, secure: bool, expected_host: str) -> str:
        parsed = urlsplit(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise SecurityBoundaryViolation("worker service URL must be HTTP or HTTPS")
        if secure and parsed.hostname != expected_host:
            raise SecurityBoundaryViolation(f"prod_secure service must use the {expected_host} DNS alias")
        if not secure and parsed.hostname in ("localhost", "127.0.0.1", "::1"):
            host = "host.docker.internal"
            netloc = host + (f":{parsed.port}" if parsed.port else "")
            return urlunsplit(parsed._replace(netloc=netloc))
        return url

    @staticmethod
    def _assert_internal_network(binary: str, network: str) -> None:
        result = subprocess.run([binary, "network", "inspect", network], capture_output=True,
                                text=True, check=False)
        if result.returncode != 0:
            raise SecurityBoundaryViolation("prod_secure internal network is unavailable")
        try:
            networks = json.loads(result.stdout)
            if len(networks) != 1 or not networks[0]["Internal"]:
                raise ValueError("network is not internal")
        except (ValueError, KeyError, TypeError) as exc:
            raise SecurityBoundaryViolation("prod_secure requires a Docker internal network") from exc

    def run(self, payload: WorkerInput, worktree: Path, profile: ExecutionProfile,
            effect_tier: int, timeout_seconds: int = 300) -> WorkerReport:
        if not worktree.is_dir():
            raise ValueError("worker worktree does not exist")
        runtime = select_runtime(profile, effect_tier)
        if runtime == WorkerRuntime.SUBPROCESS:
            command = [sys.executable, "-m", "connectd.worker_entry"]
            # A subprocess is a development convenience, not an OS sandbox.
            env = {key: value for key, value in os.environ.items()
                   if key.upper() in {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "PYTHONPATH"}}
        else:
            secure = profile.grant_mode == GrantMode.STRICT_ED25519
            network = self.docker_network if secure else "bridge"
            if not network:
                raise SecurityBoundaryViolation("prod_secure requires an internal container network")
            binary = "podman" if runtime == WorkerRuntime.PODMAN else "docker"
            if shutil.which(binary) is None:
                raise SecurityBoundaryViolation(f"{binary} runtime is unavailable")
            if secure:
                self._assert_internal_network(binary, network)
            payload = payload.model_copy(update={
                "model_base_url": self._container_url(payload.model_base_url, secure, "model-api"),
                "control_plane_url": self._container_url(payload.control_plane_url, secure, "connectd-gateway"),
            })
            command = [binary, "run", "--rm", "-i", "--read-only", "--cap-drop=ALL",
                       "--security-opt=no-new-privileges", "--pids-limit=128", "--memory=1g",
                       "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m" if secure else "/tmp:rw,size=256m",
                       "--network", network,
                       "--mount", f"type=bind,source={worktree.resolve()},target=/workspace",
                       "--workdir", "/workspace"]
            if os.name != "nt" and hasattr(os, "getuid"):
                command.extend(["--user", f"{os.getuid()}:{os.getgid()}"])
            if not secure:
                command.extend(["--add-host", "host.docker.internal:host-gateway"])
            if runtime == WorkerRuntime.GVISOR:
                command.extend(["--runtime", "runsc"])
            command.extend([self.image, "python", "-m", "connectd.worker_entry"])
            env = None
        result = subprocess.run(command, input=payload.model_dump_json(), text=True,
                                capture_output=True, cwd=worktree if runtime == WorkerRuntime.SUBPROCESS else None,
                                env=env, timeout=timeout_seconds, check=False)
        if result.returncode != 0:
            raise SecurityBoundaryViolation(f"worker exited with status {result.returncode}")
        try:
            return WorkerReport.model_validate_json(result.stdout)
        except ValueError as exc:
            raise SecurityBoundaryViolation("worker returned an invalid report") from exc
