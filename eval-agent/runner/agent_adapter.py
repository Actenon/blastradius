"""Agent adapter interface.

Supports pluggable coding-agent backends. If no real agent is available,
the harness reports BLOCKED and does not fabricate results.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol


@dataclass
class AgentCommand:
    """A single shell command the agent attempted."""
    timestamp: str
    command: str
    cwd: str
    agent_task_id: str


@dataclass
class AgentRunResult:
    """The result of running a task through an agent."""
    task_id: str
    agent_provider: str
    agent_model: str
    agent_version: str
    plan: list[str] = field(default_factory=list)
    commands: list[AgentCommand] = field(default_factory=list)
    exit_code: int = 0
    error: str | None = None
    elapsed_seconds: float = 0.0


class AgentAdapter(Protocol):
    """Interface for coding-agent backends."""

    provider: str
    model: str
    version: str

    def is_available(self) -> bool:
        """True if the agent is authenticated and ready to run."""
        ...

    def run_task(
        self,
        repo_path: str,
        prompt: str,
        hooks: list[Any],
        timeout: int = 300,
    ) -> AgentRunResult:
        """Run a task in the given repo.

        Args:
            repo_path: Path to the isolated repo copy.
            prompt: The developer's task prompt.
            hooks: List of callables to intercept shell commands.
                   Each hook receives (command_str, cwd) and can return
                   a modified command or None to block it.
            timeout: Maximum seconds to allow the agent to run.

        Returns:
            AgentRunResult with plan, commands, and outcomes.
        """
        ...


class ClaudeCodeAdapter:
    """Adapter for Claude Code CLI agent.

    Requires the `claude` CLI to be installed and authenticated.
    """

    provider = "claude-code"
    model = "claude"
    version = "unknown"

    def is_available(self) -> bool:
        """Check if claude CLI is available."""
        try:
            result = subprocess.run(
                ["claude", "--version"],
                capture_output=True, text=True, timeout=5,
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
        """Run a task through Claude Code."""
        result = AgentRunResult(
            task_id="",
            agent_provider=self.provider,
            agent_model=self.model,
            agent_version=self.version,
        )

        if not self.is_available():
            result.error = "Claude Code CLI not available"
            return result

        # Claude Code doesn't have a native hook API for command
        # interception. We use a wrapper script approach: set BLASTRADIUS
        # as a PreToolUse hook via .claude/settings.json, then run
        # the agent. The hook captures commands.
        # This is a stub — the real implementation would configure
        # the hook and run `claude --print` with the prompt.
        result.error = "Claude Code adapter not yet implemented — requires agent access"
        return result


class CodexAdapter:
    """Adapter for Codex-style agent execution."""

    provider = "codex"
    model = "codex"
    version = "unknown"

    def is_available(self) -> bool:
        """Check if codex is available."""
        try:
            result = subprocess.run(
                ["codex", "--version"],
                capture_output=True, text=True, timeout=5,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def run_task(
        self,
        repo_path: str,
        prompt: str,
        hooks: list[Any],
        timeout: int = 300,
    ) -> AgentRunResult:
        """Run a task through Codex."""
        result = AgentRunResult(
            task_id="",
            agent_provider=self.provider,
            agent_model=self.model,
            agent_version=self.version,
        )

        if not self.is_available():
            result.error = "Codex not available"
            return result

        result.error = "Codex adapter not yet implemented — requires agent access"
        return result


class SimulatedAgentAdapter:
    """A simulated agent that replays a pre-recorded command sequence.

    This is NOT a real agent. It is used for harness testing only.
    Every result from this adapter is explicitly marked as SIMULATED.
    """

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
        """Replay a pre-recorded command sequence."""
        result = AgentRunResult(
            task_id="",
            agent_provider=self.provider,
            agent_model=self.model,
            agent_version=self.version,
        )

        for cmd in self._command_sequence:
            # Run each command through the hooks
            for hook in hooks:
                modified = hook(cmd.command, cmd.cwd)
                if modified is None:
                    # Command blocked by hook
                    break
                cmd.command = modified
            else:
                # Execute the command (in a real agent, this would
                # actually run; in simulation, we just record it)
                result.commands.append(cmd)

        result.elapsed_seconds = 0.001 * len(self._command_sequence)
        return result


def get_adapter(name: str) -> AgentAdapter:
    """Get an agent adapter by name."""
    if name == "claude-code":
        return ClaudeCodeAdapter()
    elif name == "codex":
        return CodexAdapter()
    elif name == "simulated":
        return SimulatedAgentAdapter()
    else:
        raise ValueError(f"Unknown agent adapter: {name}")
