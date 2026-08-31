"""Shared adapter result types and non-Codex test adapters."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass
class AgentCommand:
    timestamp: str
    command: str
    cwd: str
    agent_task_id: str


@dataclass
class AgentRunResult:
    task_id: str
    agent_provider: str
    agent_model: str
    agent_version: str
    plan: list[str] = field(default_factory=list)
    commands: list[AgentCommand] = field(default_factory=list)
    action_ledger: list[dict] = field(default_factory=list)
    cli_command: list[str] = field(default_factory=list)
    raw_stdout: str = ""
    raw_stderr: str = ""
    exit_code: int = 0
    error: str | None = None
    elapsed_seconds: float = 0.0


class AgentAdapter(Protocol):
    provider: str
    model: str
    version: str

    def is_available(self) -> bool: ...

    def run_task(
        self,
        repo_path: str,
        prompt: str,
        hooks: list[Any],
        timeout: int = 300,
    ) -> AgentRunResult: ...


class ClaudeCodeAdapter:
    provider = "claude-code"
    model = "claude"
    version = "unknown"

    def is_available(self) -> bool:
        try:
            result = subprocess.run(
                ["claude", "--version"],
                shell=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                self.version = result.stdout.strip()
                return True
            return False
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def run_task(
        self,
        repo_path: str,
        prompt: str,
        hooks: list[Any],
        timeout: int = 300,
    ) -> AgentRunResult:
        result = AgentRunResult(
            task_id="",
            agent_provider=self.provider,
            agent_model=self.model,
            agent_version=self.version,
        )
        if not self.is_available():
            result.error = "Claude Code CLI not available"
        else:
            result.error = "Claude Code adapter not implemented"
        return result


class SimulatedAgentAdapter:
    provider = "simulated"
    model = "simulated"
    version = "harness-test"

    def __init__(self, command_sequence: list[AgentCommand] | None = None):
        self._command_sequence = command_sequence or []

    def is_available(self) -> bool:
        return True

    def run_task(
        self,
        repo_path: str,
        prompt: str,
        hooks: list[Any],
        timeout: int = 300,
    ) -> AgentRunResult:
        result = AgentRunResult(
            task_id="",
            agent_provider=self.provider,
            agent_model=self.model,
            agent_version=self.version,
        )
        for original in self._command_sequence:
            command = original.command
            for hook in hooks:
                modified = hook(command, original.cwd)
                if modified is None:
                    break
                command = modified
            else:
                result.commands.append(
                    AgentCommand(
                        timestamp=original.timestamp,
                        command=command,
                        cwd=original.cwd,
                        agent_task_id=original.agent_task_id,
                    )
                )
        return result
