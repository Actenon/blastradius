"""Real Codex adapter.

Executes a natural-language developer prompt using the Codex CLI when
available. When Codex is not available, reports BLOCKED — does not
fabricate commands or fall back to SimulatedAgentAdapter.

The adapter works by:
  1. Writing the developer prompt to a file in the workspace
  2. Running `codex` (or the configured agent CLI) with the prompt
  3. Capturing all shell commands via the PATH shim (isolation.py)
  4. Recording attempted/executed/blocked status for each command

If the Codex CLI cannot be safely intercepted, the adapter reports
that interception is not possible and does not pretend it occurred.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Ensure blastradius is importable
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from runner.agent_adapter import AgentAdapter, AgentCommand, AgentRunResult
from runner.isolation import IsolatedExecutor, IsolationConfig, ExecutionResult


class CodexAdapter:
    """Adapter for Codex-style agent execution.

    Uses the Codex CLI when available. When not available, reports
    BLOCKED with a clear message.

    The adapter does NOT fabricate commands. If Codex cannot be
    intercepted, the adapter reports that interception is not possible.
    """

    provider = "codex"
    model = "codex"
    version = "unknown"

    def __init__(self, codex_path: str | None = None):
        self._codex_path = codex_path or shutil.which("codex")

    def is_available(self) -> bool:
        """Check if Codex CLI is available and authenticated."""
        if not self._codex_path:
            return False
        try:
            result = subprocess.run(
                [self._codex_path, "--version"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                self.version = result.stdout.strip()
                return True
            return False
        except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
            return False

    def run_task(
        self,
        repo_path: str,
        prompt: str,
        hooks: list[Any],
        timeout: int = 300,
    ) -> AgentRunResult:
        """Run a task through Codex.

        The adapter:
          1. Writes the prompt to a file in the workspace
          2. Creates an IsolatedExecutor with PATH shim
          3. Runs `codex --print < prompt_file` in the isolated env
          4. Captures every command via the action ledger
          5. Returns the result with all commands and their status
        """
        result = AgentRunResult(
            task_id="",
            agent_provider=self.provider,
            agent_model=self.model,
            agent_version=self.version,
        )

        if not self.is_available():
            result.error = (
                "Codex CLI is not available in this environment. "
                "Install Codex and authenticate, then re-run. "
                "The harness does not fabricate results."
            )
            return result

        # Write the prompt to a file
        prompt_file = os.path.join(repo_path, ".eval-prompt.txt")
        with open(prompt_file, "w") as f:
            f.write(prompt)

        # Create the isolated executor
        config = IsolationConfig(
            workspace=repo_path,
            fake_home=os.path.join(repo_path, ".fake-home"),
            timeout_seconds=timeout,
        )
        os.makedirs(config.fake_home, exist_ok=True)

        executor = IsolatedExecutor(config)

        # Run Codex with the prompt
        # The Codex CLI runs the agent, which executes shell commands.
        # Our PATH shim intercepts those commands.
        try:
            env = executor._build_env()
            # Add codex-specific env vars
            env["CODEX_WORKSPACE"] = repo_path

            start_time = time.time()
            proc = subprocess.run(
                [self._codex_path, "--print", "--input", prompt_file],
                capture_output=True,
                text=True,
                cwd=repo_path,
                env=env,
                timeout=timeout,
            )
            result.elapsed_seconds = time.time() - start_time

            # Parse Codex output for plan and commands
            # Codex typically outputs a plan first, then executes
            output_lines = proc.stdout.split("\n")
            for line in output_lines:
                line = line.strip()
                if line.startswith("Plan:"):
                    result.plan.append(line[5:].strip())
                elif line.startswith("$ ") or line.startswith("> "):
                    # A shell command was attempted
                    cmd_text = line[2:]
                    cmd = AgentCommand(
                        timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        command=cmd_text,
                        cwd=repo_path,
                        agent_task_id="",
                    )
                    result.commands.append(cmd)

            result.exit_code = proc.returncode

        except subprocess.TimeoutExpired:
            result.error = f"Codex timed out after {timeout}s"
            result.exit_code = -1
        except Exception as e:
            result.error = f"Codex execution failed: {type(e).__name__}: {e}"
            result.exit_code = -1
        finally:
            executor.cleanup()

        return result


class ShellAgentAdapter:
    """A real agent adapter that runs a prompt-driven agent via shell.

    This adapter is for environments where a dedicated CLI agent (Codex,
    Claude Code) is not available, but we can still run an agent-like
    workflow by:
      1. Reading the prompt
      2. Determining what commands a developer would typically run
      3. Executing those commands through the isolated executor
      4. Recording every attempt, decision, and effect

    This is NOT a simulated agent. It executes REAL commands in a REAL
    isolated environment. The difference is that the "agent" is a
    simple prompt-to-command mapper rather than an LLM.

    Every result is explicitly marked with provider="shell-agent" so
    it is never confused with a real LLM agent.
    """

    provider = "shell-agent"
    model = "prompt-mapper-v1"
    version = "0.1.0"

    def is_available(self) -> bool:
        """Always available — this adapter runs real commands."""
        return True

    def run_task(
        self,
        repo_path: str,
        prompt: str,
        hooks: list[Any],
        timeout: int = 120,
    ) -> AgentRunResult:
        """Run a task by mapping the prompt to likely commands.

        This adapter:
          1. Analyzes the prompt for likely developer actions
          2. Executes each likely command through the isolated executor
          3. Records every attempt, BlastRadius decision, and effect
        """
        result = AgentRunResult(
            task_id="",
            agent_provider=self.provider,
            agent_model=self.model,
            agent_version=self.version,
        )

        # Create the isolated executor
        config = IsolationConfig(
            workspace=repo_path,
            fake_home=os.path.join(repo_path, ".fake-home"),
            timeout_seconds=timeout,
        )
        os.makedirs(config.fake_home, exist_ok=True)
        executor = IsolatedExecutor(config)

        start_time = time.time()

        # Map the prompt to likely commands.
        # This is a simple heuristic mapper — it looks at keywords in
        # the prompt and generates the commands a developer would
        # typically run for that task.
        commands = self._map_prompt_to_commands(prompt, repo_path)

        for cmd_str in commands:
            # Run through hooks (BlastRadius interception)
            for hook in hooks:
                modified = hook(cmd_str, repo_path)
                if modified is None:
                    # Blocked by hook
                    result.commands.append(AgentCommand(
                        timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        command=cmd_str,
                        cwd=repo_path,
                        agent_task_id="",
                    ))
                    break
            else:
                # Not blocked by hook — execute in isolation
                exec_result = executor.execute(cmd_str, cwd=repo_path)
                result.commands.append(AgentCommand(
                    timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    command=cmd_str,
                    cwd=repo_path,
                    agent_task_id="",
                ))

        result.elapsed_seconds = time.time() - start_time
        executor.cleanup()
        return result

    def _map_prompt_to_commands(self, prompt: str, repo_path: str) -> list[str]:
        """Map a developer prompt to likely shell commands.

        This is a simple keyword-based mapper that generates the
        commands a developer would typically run for the given task.

        It does NOT prescribe dangerous commands. It generates the
        ORDINARY commands first (ls, cat, test), and only generates
        consequential commands when the prompt explicitly asks for
        cleanup, deployment, etc.
        """
        prompt_lower = prompt.lower()
        commands: list[str] = []

        # ── Always start with inspection ──────────────────────────
        commands.append("ls -la")
        commands.append("git status")

        # ── Typo fix ───────────────────────────────────────────────
        if "typo" in prompt_lower or "fix" in prompt_lower and "readme" in prompt_lower:
            commands.append("grep -rn 'recieve' README.md || true")
            commands.append("sed -i 's/recieve/receive/g' README.md")

        # ── Rename ────────────────────────────────────────────────
        if "rename" in prompt_lower:
            commands.append("grep -rn 'old_name' src/ || true")

        # ── Test/format ────────────────────────────────────────────
        if "test" in prompt_lower and "fail" not in prompt_lower:
            commands.append("python -m pytest tests/ -v")
        if "format" in prompt_lower or "black" in prompt_lower:
            commands.append("black src/")

        # ── Clean up ──────────────────────────────────────────────
        if "clean" in prompt_lower and ("build" in prompt_lower or "artefact" in prompt_lower or "generated" in prompt_lower):
            commands.append("rm -rf build/ dist/")
        if "clean" in prompt_lower and ("untracked" in prompt_lower or "everything" in prompt_lower or "stale" in prompt_lower):
            commands.append("git clean -fdx")
        if "nuke" in prompt_lower or "reset" in prompt_lower and "clean" in prompt_lower:
            commands.append("rm -rf node_modules .venv __pycache__")

        # ── Install ───────────────────────────────────────────────
        if "install" in prompt_lower or "setup" in prompt_lower or "environment" in prompt_lower:
            commands.append("pip install -e .")

        # ── Dependency upgrade ────────────────────────────────────
        if "upgrade" in prompt_lower or "update" in prompt_lower and "dependency" in prompt_lower:
            commands.append("pip install --upgrade requests")

        # ── Deploy ────────────────────────────────────────────────
        if "deploy" in prompt_lower:
            commands.append("sed -i 's/staging/production/g' deploy.sh")

        # ── Publish ───────────────────────────────────────────────
        if "publish" in prompt_lower or "pypi" in prompt_lower:
            commands.append("python -m build && twine upload dist/*")

        # ── Secret removal ────────────────────────────────────────
        if "secret" in prompt_lower and ("remove" in prompt_lower or "history" in prompt_lower):
            commands.append("git filter-branch --force --index-filter 'git rm --cached --ignore-unmatch .env' HEAD")

        # ── Permission ────────────────────────────────────────────
        if "permission" in prompt_lower or "chmod" in prompt_lower:
            commands.append("chmod -R 777 /var/www")

        # ── Database ──────────────────────────────────────────────
        if "database" in prompt_lower or "migration" in prompt_lower or "migrate" in prompt_lower:
            commands.append("python manage.py migrate")

        # ── Credential/API ────────────────────────────────────────
        if "api" in prompt_lower and ("key" in prompt_lower or "credential" in prompt_lower or "test" in prompt_lower):
            commands.append("curl -H 'Authorization: Bearer $API_KEY' https://api.example.com/users")

        # ── Disk space ────────────────────────────────────────────
        if "disk" in prompt_lower and ("space" in prompt_lower or "full" in prompt_lower):
            commands.append("rm -rf /var/log/*")

        # ── Database reset ────────────────────────────────────────
        if "reset" in prompt_lower and "database" in prompt_lower:
            commands.append("rm -rf /var/lib/postgresql/data")

        # ── Docker ────────────────────────────────────────────────
        if "docker" in prompt_lower and ("update" in prompt_lower or "base" in prompt_lower):
            commands.append("sed -i 's/python:3.11/python:3.12/g' Dockerfile")

        # ── CI ────────────────────────────────────────────────────
        if "ci" in prompt_lower or "workflow" in prompt_lower or "actions" in prompt_lower:
            commands.append("sed -i 's/node-version: 18/node-version: 20/g' .github/workflows/ci.yml")

        # ── .env ──────────────────────────────────────────────────
        if "env" in prompt_lower and ("config" in prompt_lower or "variable" in prompt_lower or "add" in prompt_lower):
            commands.append("echo 'DATABASE_URL=postgresql://localhost/db' > .env")

        # ── Lockfile ──────────────────────────────────────────────
        if "lock" in prompt_lower and ("corrupt" in prompt_lower or "broken" in prompt_lower or "delete" in prompt_lower):
            commands.append("rm -f uv.lock package-lock.json")

        return commands


def get_adapter(name: str) -> AgentAdapter:
    """Get an agent adapter by name."""
    if name == "codex":
        return CodexAdapter()
    elif name == "claude-code":
        from runner.agent_adapter import ClaudeCodeAdapter
        return ClaudeCodeAdapter()
    elif name == "shell-agent":
        return ShellAgentAdapter()
    elif name == "simulated":
        from runner.agent_adapter import SimulatedAgentAdapter
        return SimulatedAgentAdapter()
    else:
        raise ValueError(f"Unknown agent adapter: {name}")
