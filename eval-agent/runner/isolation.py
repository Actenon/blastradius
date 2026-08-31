"""Pre-execution BlastRadius checks with Docker-enforced isolation."""

from __future__ import annotations

import os
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path


DEFAULT_IMAGE = (
    "python@sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df"
)


@dataclass
class IsolationConfig:
    workspace: str
    network_enabled: bool = False
    timeout_seconds: int = 120
    memory_limit_mb: int = 256
    cpu_limit: float = 1.0
    pids_limit: int = 64
    docker_path: str = "docker"
    image: str = DEFAULT_IMAGE


@dataclass
class ExecutionResult:
    command: str
    cwd: str
    attempted: bool = True
    executed: bool = False
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    effects: list[dict] = field(default_factory=list)
    error: str | None = None


class IsolatedExecutor:
    """Check a command, then run allowed commands in a locked-down container."""

    mechanism = "Docker Engine/runc: mount, PID, network, IPC and UTS namespaces; seccomp"

    def __init__(self, config: IsolationConfig):
        self.config = config
        self.workspace = Path(config.workspace).resolve(strict=True)
        if not self.workspace.is_dir():
            raise ValueError(f"workspace is not a directory: {self.workspace}")
        self.action_ledger: list[dict] = []

    def _container_cwd(self, cwd: str) -> str:
        resolved = Path(cwd).resolve(strict=True)
        try:
            relative = resolved.relative_to(self.workspace)
        except ValueError as exc:
            raise ValueError(f"cwd must be inside workspace: {resolved}") from exc
        if relative == Path("."):
            return "/workspace"
        return f"/workspace/{relative.as_posix()}"

    def isolation_command(self, command: str, cwd: str | None = None) -> list[str]:
        """Return the exact argv used to start the isolated shell."""
        host_cwd = str(Path(cwd or self.workspace).resolve(strict=True))
        container_cwd = self._container_cwd(host_cwd)
        mount = f"type=bind,source={self.workspace},target=/workspace"
        return [
            self.config.docker_path,
            "run",
            "--rm",
            "--pull",
            "never",
            "--network",
            "bridge" if self.config.network_enabled else "none",
            "--read-only",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,nodev,size=16m",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            str(self.config.pids_limit),
            "--memory",
            f"{self.config.memory_limit_mb}m",
            "--cpus",
            str(self.config.cpu_limit),
            "--user",
            f"{os.getuid()}:{os.getgid()}",
            "--mount",
            mount,
            "--workdir",
            container_cwd,
            "--env",
            "HOME=/nonexistent",
            "--env",
            "PATH=/usr/local/bin:/usr/bin:/bin",
            self.config.image,
            "/bin/sh",
            "-c",
            command,
        ]

    @staticmethod
    def _blast_result(command: str, cwd: str) -> tuple[str, str, list[str], str]:
        from blastradius.check import check_command

        result = check_command(command, cwd=cwd)
        if result.blocked:
            decision = "REFUSE"
            tier = "deterministic"
        elif result.has_warnings:
            decision = "WARN"
            tier = "heuristic"
        else:
            decision = "ALLOW"
            tier = "deterministic"

        if result.first_refusal:
            reason = result.first_refusal.reason
        else:
            reason = "; ".join(w.reason for w in result.warnings)
        targets = [
            refusal.resolved
            for refusal, _raw in result.refusals
            if refusal.resolved is not None
        ]
        return decision, reason, targets, tier

    def execute(self, command: str, cwd: str | None = None) -> ExecutionResult:
        """Capture and check ``command`` before any container or shell starts."""
        host_cwd = str(Path(cwd or self.workspace).resolve(strict=True))
        self._container_cwd(host_cwd)
        decision, reason, targets, tier = self._blast_result(command, host_cwd)
        captured_at_ns = time.time_ns()
        docker_argv = self.isolation_command(command, host_cwd)
        entry = {
            "command": command,
            "cwd": host_cwd,
            "attempted": True,
            "captured_before_execution": True,
            "captured_at_ns": captured_at_ns,
            "blastradius": {
                "decision": decision,
                "reason": reason,
                "resolved_targets": targets,
                "tier": tier,
            },
            "isolation": {
                "mechanism": self.mechanism,
                "command": docker_argv,
                "workspace_mount": f"{self.workspace}:/workspace:rw",
                "root_filesystem": "read-only",
                "network": "enabled" if self.config.network_enabled else "none",
            },
            "container_invoked": False,
            "shell_invoked": False,
            "executed": False,
            "execution_started_at_ns": None,
            "exit_code": None,
            "effects": [],
        }
        self.action_ledger.append(entry)

        if decision == "REFUSE":
            return ExecutionResult(
                command=command,
                cwd=host_cwd,
                attempted=True,
                executed=False,
                exit_code=None,
                stderr=reason,
            )

        try:
            entry["execution_started_at_ns"] = time.time_ns()
            proc = subprocess.run(
                docker_argv,
                shell=False,
                capture_output=True,
                text=True,
                timeout=self.config.timeout_seconds,
            )
            command_started = proc.returncode != 125
            entry["container_invoked"] = command_started
            entry["shell_invoked"] = command_started
            entry["executed"] = command_started
            entry["exit_code"] = proc.returncode if command_started else None
            if not command_started:
                entry["error"] = proc.stderr.strip() or "docker failed before container start"
            return ExecutionResult(
                command=command,
                cwd=host_cwd,
                attempted=True,
                executed=command_started,
                exit_code=proc.returncode if command_started else None,
                stdout=proc.stdout,
                stderr=proc.stderr,
                error=None if command_started else entry["error"],
            )
        except subprocess.TimeoutExpired as exc:
            entry["container_invoked"] = True
            entry["shell_invoked"] = True
            entry["executed"] = True
            entry["exit_code"] = -1
            entry["effects"].append(
                {"type": "timeout", "detail": f"exceeded {self.config.timeout_seconds}s"}
            )
            return ExecutionResult(
                command=command,
                cwd=host_cwd,
                attempted=True,
                executed=True,
                exit_code=-1,
                stdout=exc.stdout or "",
                stderr=exc.stderr or "",
                error="timeout",
            )
        except (FileNotFoundError, PermissionError, OSError) as exc:
            entry["exit_code"] = None
            entry["error"] = f"{type(exc).__name__}: {exc}"
            return ExecutionResult(
                command=command,
                cwd=host_cwd,
                attempted=True,
                executed=False,
                exit_code=None,
                error=entry["error"],
            )

    def get_ledger(self) -> list[dict]:
        return self.action_ledger

    def cleanup(self) -> None:
        return None
