"""Unit tests for resolve.py — the heart of blastradius."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from blastradius.resolve import Refusal, Resolved, resolve_target


class TestVariableExpansion:
    """Variable expansion against the real environment."""

    def test_simple_var(self):
        env = {"TMPDIR": "/tmp/test"}
        result = resolve_target("$TMPDIR/foo", env=env, cwd="/cwd")
        assert isinstance(result, Resolved)
        assert "/tmp/test/foo" in result.paths[0]
        assert "TMPDIR" in result.variables_used

    def test_braced_var(self):
        env = {"TMPDIR": "/tmp/test"}
        result = resolve_target("${TMPDIR}/foo", env=env, cwd="/cwd")
        assert isinstance(result, Resolved)
        assert "/tmp/test/foo" in result.paths[0]

    def test_multiple_vars(self):
        env = {"BASE": "/tmp", "SUB": "session"}
        result = resolve_target("$BASE/${SUB}/data", env=env, cwd="/cwd")
        assert isinstance(result, Resolved)
        assert "/tmp/session/data" in result.paths[0]
        assert "BASE" in result.variables_used
        assert "SUB" in result.variables_used

    def test_unset_var_refuses(self):
        env = {"HOME": "/home/test"}
        result = resolve_target("$UNSET_VAR/foo", env=env, cwd="/cwd")
        assert isinstance(result, Refusal)
        assert result.rule == "empty-variable-expansion"
        assert "UNSET_VAR" in result.reason

    def test_unset_braced_var_refuses(self):
        env = {}
        result = resolve_target("${UNSET}/foo", env=env, cwd="/cwd")
        assert isinstance(result, Refusal)
        assert result.rule == "empty-variable-expansion"
        assert "UNSET" in result.reason

    def test_multiple_unset_vars_all_named(self):
        env = {}
        result = resolve_target("$A/$B/$C", env=env, cwd="/cwd")
        assert isinstance(result, Refusal)
        assert result.rule == "empty-variable-expansion"
        assert "A" in result.reason
        assert "B" in result.reason
        assert "C" in result.reason

    def test_empty_string_var_refuses(self):
        """A variable set to empty string is treated as unset."""
        env = {"EMPTY": ""}
        result = resolve_target("$EMPTY/foo", env=env, cwd="/cwd")
        assert isinstance(result, Refusal)
        assert result.rule == "empty-variable-expansion"
        assert "EMPTY" in result.reason


class TestTildeHandling:
    """Tilde is refused as a deletion target."""

    def test_bare_tilde_refuses(self):
        result = resolve_target("~", env={}, cwd="/cwd")
        assert isinstance(result, Refusal)
        assert result.rule == "tilde-ambiguous"

    def test_tilde_slash_refuses(self):
        result = resolve_target("~/foo", env={"HOME": "/home/test"}, cwd="/cwd")
        assert isinstance(result, Refusal)
        assert result.rule == "tilde-ambiguous"

    def test_tilde_after_var_expansion_refuses(self):
        """$VAR that expands to ~/foo still refuses."""
        env = {"PATH_VAR": "~/data"}
        result = resolve_target("$PATH_VAR", env=env, cwd="/cwd")
        assert isinstance(result, Refusal)
        assert result.rule == "tilde-ambiguous"


class TestGlobExpansion:
    """Glob expansion against the real filesystem."""

    def test_glob_expands(self, tmp_path):
        (tmp_path / "a.txt").write_text("a")
        (tmp_path / "b.txt").write_text("b")
        result = resolve_target("*.txt", env={}, cwd=str(tmp_path))
        assert isinstance(result, Resolved)
        assert len(result.paths) == 2

    def test_glob_no_match_refuses(self, tmp_path):
        result = resolve_target("*.nonexistent", env={}, cwd=str(tmp_path))
        assert isinstance(result, Refusal)
        assert result.rule == "glob-no-match"

    def test_glob_recursive(self, tmp_path):
        (tmp_path / "sub").mkdir()
        (tmp_path / "sub" / "file.txt").write_text("x")
        result = resolve_target("**/*.txt", env={}, cwd=str(tmp_path))
        assert isinstance(result, Resolved)
        assert len(result.paths) >= 1

    def test_absolute_glob(self, tmp_path):
        (tmp_path / "a.log").write_text("log")
        pattern = str(tmp_path / "*.log")
        result = resolve_target(pattern, env={}, cwd="/cwd")
        assert isinstance(result, Resolved)
        assert len(result.paths) == 1


class TestCanonicalisation:
    """Resolve .., symlinks, produce absolute real paths."""

    def test_relative_path_resolved(self, tmp_path):
        result = resolve_target("./foo", env={}, cwd=str(tmp_path))
        assert isinstance(result, Resolved)
        assert os.path.isabs(result.paths[0])

    def test_dot_dot_resolved(self, tmp_path):
        sub = tmp_path / "sub"
        sub.mkdir()
        result = resolve_target("../foo", env={}, cwd=str(sub))
        assert isinstance(result, Resolved)
        # Should resolve to tmp_path/foo (parent of sub).
        assert result.paths[0] == str(tmp_path / "foo")

    def test_symlink_resolved(self, tmp_path):
        """A symlink is resolved to its real target."""
        real_dir = tmp_path / "real"
        real_dir.mkdir()
        link = tmp_path / "link"
        link.symlink_to(real_dir)
        result = resolve_target("link/file", env={}, cwd=str(tmp_path))
        assert isinstance(result, Resolved)
        # realpath should resolve the symlink.
        assert "real" in result.paths[0]

    def test_absolute_path_unchanged(self, tmp_path):
        result = resolve_target(str(tmp_path / "foo"), env={}, cwd="/cwd")
        assert isinstance(result, Resolved)
        assert result.paths[0] == str(tmp_path / "foo")


class TestEmptyTarget:
    """Empty string targets refuse."""

    def test_empty_string_refuses(self):
        result = resolve_target("", env={}, cwd="/cwd")
        assert isinstance(result, Refusal)
        assert result.rule == "empty-target"
