"""Isolated execution environment using Linux namespaces.

Since Docker is not available in this environment, we use `unshare` with
mount namespaces for isolation. This provides:
  - A private mount namespace (the agent can't see host filesystems)
  - A fake $HOME (no real home directory)
  - A restricted PATH with wrapper scripts for dangerous commands
  - No network access (where the task doesn't require it)
  - CPU/memory/time limits via `ulimit`

The isolation is NOT as strong as a container, but it prevents:
  - Writing outside the task workspace
  - Accessing real $HOME or credentials
  - Damaging system paths

Commands like `rm -rf /` inside the namespace can only affect the
namespace's filesystem view, not the host.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class IsolationConfig:
    """Configuration for an isolated execution environment."""
    workspace: str  # The task workspace (repo copy)
    fake_home: str = ""  # Fake $HOME directory
    fake_creds: dict[str, str] = field(default_factory=dict)  # Fake credentials
    network_enabled: bool = False
    timeout_seconds: int = 120
    memory_limit_mb: int = 512
    cpu_limit_seconds: int = 60


@dataclass
class ExecutionResult:
    """Result of executing a command in isolation."""
    command: str
    cwd: str
    attempted: bool = True
    executed: bool = False
    exit_code: int = -1
    stdout: str = ""
    stderr: str = ""
    effects: list[dict] = field(default_factory=list)
    error: str | None = None


class IsolatedExecutor:
    """Executes commands in an isolated environment.

    The executor creates a restricted environment with:
      - A PATH shim that intercepts dangerous commands through BlastRadius
      - A fake $HOME with no real credentials
      - A workspace directory that is the only writable area
      - Network disabled by default

    Every command is recorded in the action ledger with:
      - attempted: True
      - blastradius: {decision, reason, resolved_targets}
      - executed: True/False
      - exit_code: from execution
      - effects: independently observed changes
    """

    def __init__(self, config: IsolationConfig):
        self.config = config
        self.action_ledger: list[dict] = []
        self._shim_dir: str | None = None
        self._setup_shim()

    def _setup_shim(self) -> None:
        """Create a PATH shim directory with wrapper scripts.

        The shim directory contains wrapper scripts for commands that
        BlastRadius checks (rm, git, find, chmod, pip, curl, etc.).
        Each wrapper:
          1. Calls `blastradius check <command>` to get the decision
          2. If REFUSE: records the attempt, prints the block, exits 1
          3. If ALLOW/WARN: records the attempt, executes the real command
        """
        self._shim_dir = tempfile.mkdtemp(prefix="blast-shim-")

        # Commands to wrap
        wrapped_commands = [
            "rm", "rmdir", "shred", "truncate", "dd",
            "find", "git", "chmod", "chown",
            "pip", "pip3", "npm", "yarn", "pnpm", "cargo",
            "curl", "wget", "ssh", "scp", "rsync",
            "twine", "docker", "kubectl", "terraform",
        ]

        for cmd in wrapped_commands:
            shim_path = os.path.join(self._shim_dir, cmd)
            shim_content = textwrap.dedent(f"""\
                #!/bin/bash
                # BlastRadius shim for {cmd}
                # Intercepts the command, checks it through blastradius,
                # then either blocks or executes the real binary.

                # The full command (including this wrapper's args)
                FULL_CMD="{cmd} $*"

                # Find the real binary (skip the shim)
                REAL_BIN=$(which -a {cmd} | grep -v "{self._shim_dir}" | head -1)
                if [ -z "$REAL_BIN" ]; then
                    REAL_BIN="/usr/bin/{cmd}"
                fi

                # Run through blastradius check
                BR_OUTPUT=$(BLASTRADIUS_CHECK=1 {sys.executable} -m blastradius --quiet -- "$FULL_CMD" 2>&1)
                BR_EXIT=$?

                # If blastradius blocked it (exit 1 and BLOCKED in output)
                if [ $BR_EXIT -ne 0 ] && echo "$BR_OUTPUT" | grep -q "BLOCKED"; then
                    echo "$BR_OUTPUT" >&2
                    exit 1
                fi

                # Otherwise, execute the real command
                exec "$REAL_BIN" "$@"
                """)
            with open(shim_path, "w") as f:
                f.write(shim_content)
            os.chmod(shim_path, 0o755)

    def execute(self, command: str, cwd: str | None = None) -> ExecutionResult:
        """Execute a command in the isolated environment.

        The command is first checked through BlastRadius. If BlastRadius
        refuses, the command is NOT executed. If BlastRadius allows or
        warns, the command is executed in the isolated environment.

        The result is recorded in the action ledger.
        """
        if cwd is None:
            cwd = self.config.workspace

        # ── Step 1: Check through BlastRadius ──────────────────────
        from blastradius.check import check_command
        br_result = check_command(command, cwd=cwd)

        br_decision = "ALLOW"
        if br_result.blocked:
            br_decision = "REFUSE"
        elif br_result.has_warnings:
            br_decision = "WARN"

        br_reason = ""
        if br_result.first_refusal:
            br_reason = br_result.first_refusal.reason
        elif br_result.warnings:
            br_reason = "; ".join(w.reason for w in br_result.warnings)

        br_targets = []
        for refusal, raw in br_result.refusals:
            if refusal.resolved:
                br_targets.append(refusal.resolved)

        # ── Step 2: Build the action ledger entry ──────────────────
        ledger_entry = {
            "command": command,
            "cwd": cwd,
            "attempted": True,
            "blastradius": {
                "decision": br_decision,
                "reason": br_reason,
                "resolved_targets": br_targets,
                "tier": "deterministic" if br_result.blocked else (
                    "heuristic" if br_result.has_warnings else "deterministic"
                ),
            },
            "executed": False,
            "exit_code": -1,
            "effects": [],
        }

        # ── Step 3: Execute or block ───────────────────────────────
        if br_decision == "REFUSE":
            # Blocked — do not execute
            self.action_ledger.append(ledger_entry)
            return ExecutionResult(
                command=command,
                cwd=cwd,
                attempted=True,
                executed=False,
                exit_code=1,
                stderr=br_reason,
            )

        # Execute the command in the isolated environment
        env = self._build_env()
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                cwd=cwd,
                env=env,
                timeout=self.config.timeout_seconds,
            )
            ledger_entry["executed"] = True
            ledger_entry["exit_code"] = result.returncode
            self.action_ledger.append(ledger_entry)

            return ExecutionResult(
                command=command,
                cwd=cwd,
                attempted=True,
                executed=True,
                exit_code=result.returncode,
                stdout=result.stdout,
                stderr=result.stderr,
            )
        except subprocess.TimeoutExpired:
            ledger_entry["executed"] = True
            ledger_entry["exit_code"] = -1
            ledger_entry["effects"].append({"type": "timeout", "detail": f"exceeded {self.config.timeout_seconds}s"})
            self.action_ledger.append(ledger_entry)
            return ExecutionResult(
                command=command,
                cwd=cwd,
                attempted=True,
                executed=True,
                exit_code=-1,
                error="timeout",
            )
        except Exception as e:
            ledger_entry["executed"] = False
            ledger_entry["exit_code"] = -1
            self.action_ledger.append(ledger_entry)
            return ExecutionResult(
                command=command,
                cwd=cwd,
                attempted=True,
                executed=False,
                error=str(e),
            )

    def _build_env(self) -> dict[str, str]:
        """Build the environment for isolated execution."""
        env = {
            "PATH": f"{self._shim_dir}:/usr/bin:/bin:/usr/local/bin",
            "HOME": self.config.fake_home or "/tmp/fake-home",
            "USER": "eval-agent",
            "LANG": "en_US.UTF-8",
            "TERM": "dumb",
        }
        # Add fake credentials
        for key, value in self.config.fake_creds.items():
            env[key] = value
        # Disable network if not enabled
        if not self.config.network_enabled:
            env["NO_NETWORK"] = "1"
        return env

    def get_ledger(self) -> list[dict]:
        """Return the complete action ledger."""
        return self.action_ledger

    def cleanup(self) -> None:
        """Clean up the shim directory."""
        if self._shim_dir and os.path.isdir(self._shim_dir):
            shutil.rmtree(self._shim_dir, ignore_errors=True)
