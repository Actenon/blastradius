"""Must-allow suite — ordinary developer deletions that must NOT block.

A guard that blocks a legitimate rm -rf ./build gets uninstalled the
same day. These tests assert that common, safe deletions pass.

Treat a must-allow failure as more serious than a must-block failure,
because it's the one that removes the tool from the machine.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from blastradius.check import check_command
from blastradius.rules import Scope


@pytest.fixture
def repo_with_build_dirs(tmp_path):
    """Create a fake repo with build artefact directories."""
    (tmp_path / ".git").mkdir()
    for d in ("build", "dist", "node_modules", ".venv", "__pycache__", "target"):
        (tmp_path / d).mkdir()
        (tmp_path / d / "artefact.txt").write_text("build output")
    (tmp_path / "main.py").write_text("print('hello')")
    return tmp_path


class TestMustAllowBuildArtefacts:
    """Ordinary build artefact deletion must pass."""

    def test_rm_build(self, repo_with_build_dirs):
        result = check_command(
            "rm -rf build",
            cwd=str(repo_with_build_dirs),
        )
        assert result.allowed, f"Should allow rm -rf build, got: {result.first_refusal}"

    def test_rm_dist(self, repo_with_build_dirs):
        result = check_command(
            "rm -rf dist",
            cwd=str(repo_with_build_dirs),
        )
        assert result.allowed, f"Should allow rm -rf dist, got: {result.first_refusal}"

    def test_rm_node_modules(self, repo_with_build_dirs):
        result = check_command(
            "rm -rf node_modules",
            cwd=str(repo_with_build_dirs),
        )
        assert result.allowed

    def test_rm_venv(self, repo_with_build_dirs):
        result = check_command(
            "rm -rf .venv",
            cwd=str(repo_with_build_dirs),
        )
        assert result.allowed

    def test_rm_pycache(self, repo_with_build_dirs):
        result = check_command(
            "rm -rf __pycache__",
            cwd=str(repo_with_build_dirs),
        )
        assert result.allowed

    def test_rm_target(self, repo_with_build_dirs):
        result = check_command(
            "rm -rf target",
            cwd=str(repo_with_build_dirs),
        )
        assert result.allowed

    def test_rm_dot_slash_build(self, repo_with_build_dirs):
        result = check_command(
            "rm -rf ./build",
            cwd=str(repo_with_build_dirs),
        )
        assert result.allowed

    def test_rm_single_file(self, repo_with_build_dirs):
        (repo_with_build_dirs / "temp.txt").write_text("temp")
        result = check_command(
            "rm temp.txt",
            cwd=str(repo_with_build_dirs),
        )
        assert result.allowed


class TestMustAllowTmpDirs:
    """Temp directory deletion must pass (at depth ≥ 3)."""

    def test_rm_tmp_subdir(self, tmp_path):
        """rm -rf /tmp/blastradius-test/session-123 — depth 3."""
        import os
        os.makedirs("/tmp/blastradius-test/session-123", exist_ok=True)
        result = check_command(
            "rm -rf /tmp/blastradius-test/session-123",
        )
        assert result.allowed, f"Should allow /tmp depth-3, got: {result.first_refusal}"

    def test_rm_tmpdir_var(self, tmp_path, monkeypatch):
        """rm -rf $TMPDIR/session-123 — with TMPDIR set."""
        import os
        tmpdir = "/tmp/blastradius-test-tmpdir"
        os.makedirs(f"{tmpdir}/session-123", exist_ok=True)
        monkeypatch.setenv("TMPDIR", tmpdir)
        result = check_command(
            "rm -rf $TMPDIR/session-123",
        )
        assert result.allowed, f"Should allow $TMPDIR/session-123, got: {result.first_refusal}"


class TestMustAllowGitClean:
    """git clean -fdx in a repo must pass."""

    def test_git_clean_fdx(self, repo_with_build_dirs):
        result = check_command(
            "git clean -fdx",
            cwd=str(repo_with_build_dirs),
        )
        assert result.allowed, f"Should allow git clean -fdx, got: {result.first_refusal}"

    def test_git_clean_force(self, repo_with_build_dirs):
        result = check_command(
            "git clean --force -d -x",
            cwd=str(repo_with_build_dirs),
        )
        assert result.allowed


class TestMustAllowFindDelete:
    """find -delete for .pyc files must pass."""

    def test_find_pyc_delete(self, repo_with_build_dirs):
        # Create a .pyc file.
        (repo_with_build_dirs / "module.pyc").write_text("bytecode")
        result = check_command(
            "find . -name '*.pyc' -delete",
            cwd=str(repo_with_build_dirs),
        )
        assert result.allowed, f"Should allow find -delete, got: {result.first_refusal}"


class TestMustAllowTruncate:
    """truncate -s 0 for log files must pass."""

    def test_truncate_logfile(self, repo_with_build_dirs):
        (repo_with_build_dirs / "app.log").write_text("log entry")
        result = check_command(
            "truncate -s 0 app.log",
            cwd=str(repo_with_build_dirs),
        )
        assert result.allowed, f"Should allow truncate, got: {result.first_refusal}"


class TestMustAllowNonDestructive:
    """Non-destructive commands must pass (not checked at all)."""

    def test_ls(self):
        result = check_command("ls -la")
        assert result.allowed

    def test_echo(self):
        result = check_command("echo hello")
        assert result.allowed

    def test_cat(self):
        result = check_command("cat /etc/hostname")
        assert result.allowed

    def test_git_status(self, repo_with_build_dirs):
        result = check_command(
            "git status",
            cwd=str(repo_with_build_dirs),
        )
        assert result.allowed

    def test_python_script(self):
        result = check_command("python -c 'print(1+1)'")
        assert result.allowed
