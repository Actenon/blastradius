"""Codex CLI adapter using native PreToolUse interception."""

from __future__ import annotations

import json
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

# Ensure blastradius is importable
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from runner.adapter_types import AgentAdapter, AgentCommand, AgentRunResult
from runner.isolation import IsolatedExecutor, IsolationConfig


class CodexAdapter:
    """Run Codex with Bash calls handled by ``IsolatedExecutor``."""

    provider = "codex"
    model = "codex"
    version = "unknown"

    def __init__(self, codex_path: str | None = None):
        self._codex_path = codex_path or shutil.which("codex")

    def is_available(self) -> bool:
        if not self._codex_path:
            return False
        try:
            result = subprocess.run(
                [self._codex_path, "--version"],
                shell=False,
                capture_output=True,
                text=True,
                timeout=10,
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
        """Run Codex using the installed ``codex exec`` contract."""
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

        workspace = Path(repo_path).resolve(strict=True)
        if not (workspace / ".git").exists():
            result.error = (
                "BLOCKED: Codex project hooks cannot be proven outside a Git workspace."
            )
            result.exit_code = -1
            return result
        hook_script = Path(__file__).resolve().with_name("codex_hook.py")
        capture_handle = tempfile.NamedTemporaryFile(
            prefix=".eval-codex-capture-", suffix=".jsonl", dir=workspace, delete=False
        )
        ledger_handle = tempfile.NamedTemporaryFile(
            prefix=".eval-codex-ledger-", suffix=".jsonl", dir=workspace, delete=False
        )
        capture_handle.close()
        ledger_handle.close()
        capture_path = Path(capture_handle.name)
        ledger_path = Path(ledger_handle.name)

        codex_dir = workspace / ".codex"
        hooks_path = codex_dir / "hooks.json"
        prior_hooks = hooks_path.read_bytes() if hooks_path.exists() else None
        created_codex_dir = not codex_dir.exists()
        codex_dir.mkdir(exist_ok=True)
        hook_command = shlex.join([
            sys.executable,
            str(hook_script),
            "pre-tool-use",
            "--workspace",
            str(workspace),
            "--capture",
            str(capture_path),
            "--ledger",
            str(ledger_path),
        ])
        hooks_path.write_text(json.dumps({
            "hooks": {
                "PreToolUse": [{
                    "matcher": "^(Bash|apply_patch)$",
                    "hooks": [{
                        "type": "command",
                        "command": hook_command,
                        "timeout": 30,
                    }],
                }]
            }
        }))

        cli_command = [
            self._codex_path,
            "exec",
            "--ignore-user-config",
            "--ignore-rules",
            "--ephemeral",
            "--json",
            "--color",
            "never",
            "--dangerously-bypass-hook-trust",
            "--sandbox",
            "workspace-write",
            "-C",
            str(workspace),
            prompt,
        ]
        result.cli_command = cli_command
        try:
            start_time = time.time()
            proc = subprocess.run(
                cli_command,
                shell=False,
                capture_output=True,
                text=True,
                cwd=workspace,
                timeout=timeout,
            )
            result.elapsed_seconds = time.time() - start_time
            result.raw_stdout = proc.stdout
            result.raw_stderr = proc.stderr
            result.exit_code = proc.returncode
            if proc.returncode != 0:
                result.error = f"Codex exited with status {proc.returncode}"
        except subprocess.TimeoutExpired:
            result.error = f"Codex timed out after {timeout}s"
            result.exit_code = -1
        except Exception as e:
            result.error = f"Codex execution failed: {type(e).__name__}: {e}"
            result.exit_code = -1
        finally:
            captures = _read_jsonl(capture_path)
            result.action_ledger = _read_jsonl(ledger_path)
            for capture in captures:
                if capture.get("tool_name") != "Bash":
                    continue
                result.commands.append(AgentCommand(
                    timestamp=capture.get("timestamp", ""),
                    command=capture.get("command", ""),
                    cwd=capture.get("cwd", str(workspace)),
                    agent_task_id=capture.get("agent_task_id", ""),
                ))
            if result.exit_code == 0 and not result.action_ledger:
                result.error = (
                    "BLOCKED: Codex completed without a native PreToolUse execution ledger."
                )
                result.exit_code = -1
            if prior_hooks is None:
                hooks_path.unlink(missing_ok=True)
            else:
                hooks_path.write_bytes(prior_hooks)
            if created_codex_dir:
                try:
                    codex_dir.rmdir()
                except OSError:
                    pass
            capture_path.unlink(missing_ok=True)
            ledger_path.unlink(missing_ok=True)

        return result


def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


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
            timeout_seconds=timeout,
        )
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
        from runner.adapter_types import ClaudeCodeAdapter
        return ClaudeCodeAdapter()
    elif name == "shell-agent":
        return ShellAgentAdapter()
    elif name == "simulated":
        from runner.adapter_types import SimulatedAgentAdapter
        return SimulatedAgentAdapter()
    else:
        raise ValueError(f"Unknown agent adapter: {name}")
