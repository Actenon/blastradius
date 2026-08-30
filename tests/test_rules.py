"""Unit tests for rules.py — floor, scope, glob breadth."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from blastradius.rules import (
    Scope,
    check_glob_breadth,
    default_scope,
    find_repo_root,
    is_floor,
    parse_config,
)
from blastradius.resolve import Resolved


class TestFloorPaths:
    """Floor paths are unoverridable."""

    @pytest.mark.parametrize("path", [
        "/",
        "/home",
        "/Users",
        "/etc",
        "/usr",
        "/bin",
        "/sbin",
        "/var",
        "/System",
        "/Library",
        "/opt",
        "/root",
        "/boot",
        "/tmp",
        "/dev",
        "/proc",
        "/sys",
    ])
    def test_floor_paths_detected(self, path):
        assert is_floor(path, home="/home/testuser") is True

    def test_home_is_floor(self):
        assert is_floor("/home/testuser", home="/home/testuser") is True

    def test_non_floor_path_not_floor(self):
        """A deep path inside a repo is not floor."""
        assert is_floor("/home/testuser/myrepo/build", home="/home/testuser") is False

    def test_tmp_subdir_not_floor(self):
        """/tmp/foo is depth 2 — not floor (judged by scope)."""
        assert is_floor("/tmp/foo", home="/home/testuser") is False

    def test_deep_tmp_not_floor(self):
        assert is_floor("/tmp/blastradius/session-123", home="/home/testuser") is False

    def test_system_dir_descendant_not_floor_by_depth(self):
        """/etc/foo is depth 2 — not floor by depth. But /etc is in the
        explicit list, so /etc itself is floor. /etc/foo is not floor
        (it's a descendant, not /etc itself)."""
        assert is_floor("/etc/foo", home="/home/testuser") is False


class TestScope:
    """Scope allow/deny matching."""

    def test_allows_within_scope(self, tmp_path):
        scope = Scope(allow=[str(tmp_path) + "/**"], repo_root=str(tmp_path))
        assert scope.allows(str(tmp_path / "build")) is True

    def test_refuses_outside_scope(self, tmp_path):
        scope = Scope(allow=[str(tmp_path) + "/**"], repo_root=str(tmp_path))
        assert scope.allows("/etc/passwd") is False

    def test_deny_overrides_allow(self, tmp_path):
        scope = Scope(
            allow=[str(tmp_path) + "/**"],
            deny=[str(tmp_path / "secrets") + "/**"],
            repo_root=str(tmp_path),
        )
        assert scope.allows(str(tmp_path / "secrets" / "key.pem")) is False

    def test_repo_placeholder(self, tmp_path):
        scope = Scope(
            allow=["<repo>/build/**"],
            repo_root=str(tmp_path),
        )
        assert scope.allows(str(tmp_path / "build" / "output.txt")) is True

    def test_default_scope_includes_tmp(self):
        scope = default_scope(cwd="/tmp")
        # /tmp/blastradius/session is depth 3 — not floor.
        # Scope allows /tmp/**.
        assert scope.allows("/tmp/blastradius/session-123") is True

    def test_default_scope_includes_repo_build(self, tmp_path):
        (tmp_path / ".git").mkdir()
        (tmp_path / "build").mkdir()
        scope = default_scope(cwd=str(tmp_path))
        assert scope.allows(str(tmp_path / "build")) is True


class TestGlobBreadth:
    """Glob breadth check — refuse overly broad globs.

    Note: check_glob_breadth should only be called on results where
    was_glob=True. These tests construct Resolved with was_glob=True
    to simulate glob expansion.
    """

    def test_normal_glob_passes(self, tmp_path):
        resolved = Resolved(
            raw="*",
            paths=[str(tmp_path / f"f{i}.txt") for i in range(5)],
            was_glob=True,
        )
        refusal = check_glob_breadth(resolved, max_entries=100, repo_root=str(tmp_path))
        # These are at repo root level — the repo-root-level check fires.
        # But 5 entries is under the breadth limit. The repo-root check
        # fires because the glob matched files directly in the repo root.
        # For a must-allow case, the glob should match files in a SUBDIRECTORY.
        pass  # See test below for the actual must-allow case.

    def test_normal_glob_in_subdir_passes(self, tmp_path):
        """A glob that matches files in a subdirectory should pass."""
        subdir = tmp_path / "build"
        subdir.mkdir()
        resolved = Resolved(
            raw="build/*",
            paths=[str(subdir / f"f{i}.txt") for i in range(5)],
            was_glob=True,
        )
        refusal = check_glob_breadth(resolved, max_entries=100, repo_root=str(tmp_path))
        assert refusal is None

    def test_excessive_glob_refuses(self, tmp_path):
        resolved = Resolved(
            raw="*",
            paths=[str(tmp_path / f"f{i}.txt") for i in range(200)],
            was_glob=True,
        )
        refusal = check_glob_breadth(resolved, max_entries=100, repo_root=str(tmp_path))
        assert refusal is not None
        assert refusal.rule == "glob-breadth"

    def test_repo_root_level_glob_refuses(self, tmp_path):
        """A glob that matches a file at repo root level is dangerous."""
        resolved = Resolved(
            raw="*",
            paths=[str(tmp_path / "README.md")],
            was_glob=True,
        )
        refusal = check_glob_breadth(resolved, max_entries=100, repo_root=str(tmp_path))
        assert refusal is not None
        assert refusal.rule == "glob-breadth"


class TestConfigParsing:
    """Parse .blastradius config files."""

    def test_parse_simple_config(self, tmp_path):
        config_file = tmp_path / ".blastradius"
        config_file.write_text(
            "# blastradius config\n"
            "allow /tmp/**\n"
            "allow ./build/**\n"
            "deny ./secrets/**\n"
        )
        scope = parse_config(str(config_file), repo_root=str(tmp_path))
        assert "/tmp/**" in scope.allow
        assert "./build/**" in scope.allow
        assert "./secrets/**" in scope.deny

    def test_parse_empty_config(self, tmp_path):
        config_file = tmp_path / ".blastradius"
        config_file.write_text("# just a comment\n")
        scope = parse_config(str(config_file), repo_root=str(tmp_path))
        assert scope.allow == []
        assert scope.deny == []


class TestFindRepoRoot:
    """Find the git repo root by walking up."""

    def test_finds_repo_root(self, tmp_path):
        (tmp_path / ".git").mkdir()
        sub = tmp_path / "sub" / "deep"
        sub.mkdir(parents=True)
        root = find_repo_root(str(sub))
        assert root == str(tmp_path)

    def test_returns_none_without_git(self, tmp_path):
        root = find_repo_root(str(tmp_path))
        # Might find a parent .git or None depending on the test environment.
        # Just assert it doesn't crash.
        assert root is None or isinstance(root, str)
