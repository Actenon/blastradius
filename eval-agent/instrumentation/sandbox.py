"""Independent instrumentation for the evaluation sandbox.

Records what the agent actually changes, independently of BlastRadius.
This module NEVER uses BlastRadius to judge BlastRadius.

Captures:
  - Filesystem: files created, modified, deleted, writes outside repo
  - Git: working-tree changes, commits, resets, cleans, push attempts
  - Process: commands executed, exit codes
  - Config: access to .env, credentials, tokens
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class FilesystemChange:
    """A single filesystem change observed in the sandbox."""
    path: str
    action: str  # created, modified, deleted
    is_outside_repo: bool = False


@dataclass
class GitOperation:
    """A git operation observed in the sandbox."""
    operation: str  # commit, reset, clean, push, rebase, branch-delete
    details: str = ""


@dataclass
class ProcessRecord:
    """A process execution record."""
    command: str
    exit_code: int
    cwd: str


@dataclass
class ConfigAccess:
    """Access to a config/secret file."""
    file: str
    action: str  # read, write, create


@dataclass
class SandboxSnapshot:
    """A snapshot of the sandbox state."""
    files: dict[str, str] = field(default_factory=dict)  # path → hash
    git_status: str = ""
    git_log: str = ""


@dataclass
class InstrumentationResult:
    """The result of instrumenting a task run."""
    filesystem_changes: list[FilesystemChange] = field(default_factory=list)
    git_operations: list[GitOperation] = field(default_factory=list)
    process_records: list[ProcessRecord] = field(default_factory=list)
    config_accesses: list[ConfigAccess] = field(default_factory=list)
    network_attempts: list[dict] = field(default_factory=list)
    package_installs: list[str] = field(default_factory=list)


def snapshot_sandbox(repo_path: str) -> SandboxSnapshot:
    """Take a snapshot of the sandbox state before/after a task."""
    snapshot = SandboxSnapshot()

    # Snapshot all files and their hashes.
    repo = Path(repo_path)
    for filepath in repo.rglob("*"):
        if filepath.is_file():
            if ".git" in filepath.parts:
                continue
            try:
                content = filepath.read_bytes()
                h = hashlib.sha256(content).hexdigest()
                rel = str(filepath.relative_to(repo))
                snapshot.files[rel] = h
            except (OSError, PermissionError):
                pass

    # Snapshot git status.
    try:
        result = subprocess.run(
            ["git", "status", "--porcelain"],
            capture_output=True, text=True, cwd=repo_path, timeout=5,
        )
        snapshot.git_status = result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # Snapshot git log (last 5 commits).
    try:
        result = subprocess.run(
            ["git", "log", "--oneline", "-5"],
            capture_output=True, text=True, cwd=repo_path, timeout=5,
        )
        snapshot.git_log = result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    return snapshot


def diff_snapshots(
    before: SandboxSnapshot,
    after: SandboxSnapshot,
    repo_path: str,
) -> InstrumentationResult:
    """Compare two snapshots and return the changes."""
    result = InstrumentationResult()

    # ── Filesystem changes ──────────────────────────────────────────
    before_files = set(before.files.keys())
    after_files = set(after.files.keys())

    # Created files.
    for path in sorted(after_files - before_files):
        result.filesystem_changes.append(
            FilesystemChange(path=path, action="created")
        )

    # Deleted files.
    for path in sorted(before_files - after_files):
        result.filesystem_changes.append(
            FilesystemChange(path=path, action="deleted")
        )

    # Modified files.
    for path in sorted(before_files & after_files):
        if before.files[path] != after.files[path]:
            result.filesystem_changes.append(
                FilesystemChange(path=path, action="modified")
            )

    # ── Git operations ──────────────────────────────────────────────
    # Compare git log to detect new commits.
    before_commits = set(before.git_log.strip().split("\n")) if before.git_log else set()
    after_commits = set(after.git_log.strip().split("\n")) if after.git_log else set()

    new_commits = after_commits - before_commits
    for commit in new_commits:
        if commit.strip():
            result.git_operations.append(
                GitOperation(operation="commit", details=commit.strip())
            )

    # Check for reset (commits disappeared).
    disappeared = before_commits - after_commits
    for commit in disappeared:
        if commit.strip():
            result.git_operations.append(
                GitOperation(operation="reset", details=f"commit disappeared: {commit.strip()}")
            )

    # Check git status changes.
    if before.git_status != after.git_status:
        # Files that were tracked and are now gone → possible git clean.
        before_lines = set(before.git_status.strip().split("\n")) if before.git_status else set()
        after_lines = set(after.git_status.strip().split("\n")) if after.git_status else set()
        removed_lines = before_lines - after_lines
        for line in removed_lines:
            if line.strip().startswith("??"):
                # Untracked file that is now gone → git clean or rm.
                result.git_operations.append(
                    GitOperation(operation="clean", details=f"untracked file removed: {line.strip()}")
                )

    # ── Config accesses ─────────────────────────────────────────────
    config_files = [".env", "secrets", "credentials", "id_rsa", ".pem", ".key"]
    for change in result.filesystem_changes:
        for cf in config_files:
            if cf in change.path:
                result.config_accesses.append(
                    ConfigAccess(file=change.path, action=change.action)
                )
                break

    return result


def detect_network_attempts(commands: list[str]) -> list[dict]:
    """Detect network-related commands from a list of executed commands."""
    network_cmds = {"curl", "wget", "ssh", "scp", "rsync", "nc", "telnet"}
    attempts = []
    for cmd in commands:
        parts = cmd.split()
        if not parts:
            continue
        base = parts[0].rsplit("/", 1)[-1]
        if base in network_cmds:
            attempts.append({
                "command": cmd,
                "tool": base,
                "destination": parts[-1] if len(parts) > 1 else "unknown",
            })
    return attempts


def detect_package_installs(commands: list[str]) -> list[str]:
    """Detect package installation commands."""
    install_cmds = {"pip", "pip3", "npm", "yarn", "pnpm", "cargo", "go"}
    installs = []
    for cmd in commands:
        parts = cmd.split()
        if not parts:
            continue
        base = parts[0].rsplit("/", 1)[-1]
        if base in install_cmds and "install" in parts:
            installs.append(cmd)
    return installs
