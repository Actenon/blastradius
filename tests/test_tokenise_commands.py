"""Unit tests for tokenise.py and commands.py."""

from __future__ import annotations

import pytest

from blastradius.tokenise import tokenise
from blastradius.commands import identify_destructive


class TestTokeniser:
    """Tokeniser — quoting, splitting, refusal."""

    def test_simple_split(self):
        result = tokenise("rm -rf /tmp/foo")
        assert result.tokens == ["rm", "-rf", "/tmp/foo"]

    def test_single_quotes(self):
        result = tokenise("rm -rf '/tmp/my dir'")
        assert result.tokens == ["rm", "-rf", "/tmp/my dir"]

    def test_double_quotes(self):
        result = tokenise('rm -rf "/tmp/my dir"')
        assert result.tokens == ["rm", "-rf", "/tmp/my dir"]

    def test_escaped_space(self):
        result = tokenise("rm /tmp/my\\ dir")
        assert result.tokens == ["rm", "/tmp/my dir"]

    def test_empty_command(self):
        result = tokenise("")
        assert result.tokens is None or result.tokens == []

    def test_semicolon_refuses(self):
        result = tokenise("rm /tmp/foo; rm /tmp/bar")
        assert result.tokens is None
        assert result.refusal is not None
        assert "semicolon" in result.refusal.rule

    def test_logical_and_refuses(self):
        result = tokenise("cd /tmp && rm foo")
        assert result.tokens is None
        assert result.refusal is not None
        assert "logical-and" in result.refusal.rule

    def test_pipe_refuses(self):
        result = tokenise("rm /tmp/foo | cat")
        assert result.tokens is None
        assert result.refusal is not None
        assert "pipe" in result.refusal.rule

    def test_command_substitution_refuses(self):
        result = tokenise("rm $(find /tmp -name foo)")
        assert result.tokens is None
        assert result.refusal is not None
        assert "command-substitution" in result.refusal.rule

    def test_backtick_refuses(self):
        result = tokenise("rm `find /tmp`")
        assert result.tokens is None
        assert result.refusal is not None
        assert "backtick" in result.refusal.rule

    def test_subshell_refuses(self):
        result = tokenise("(rm /tmp/foo)")
        assert result.tokens is None
        assert result.refusal is not None
        assert "subshell" in result.refusal.rule

    def test_eval_refuses(self):
        result = tokenise("eval 'rm -rf /tmp'")
        assert result.tokens is None
        assert result.refusal is not None
        assert "eval" in result.refusal.rule


class TestCommandIdentification:
    """Identify which commands are destructive and extract targets."""

    def test_rm(self):
        action = identify_destructive(["rm", "-rf", "/tmp/foo"])
        assert action is not None
        assert action.command == "rm"
        assert "/tmp/foo" in action.targets

    def test_rmdir(self):
        action = identify_destructive(["rmdir", "/tmp/empty"])
        assert action is not None
        assert action.command == "rmdir"

    def test_shred(self):
        action = identify_destructive(["shred", "/tmp/secret"])
        assert action is not None
        assert action.command == "shred"

    def test_truncate(self):
        action = identify_destructive(["truncate", "-s", "0", "/tmp/log"])
        assert action is not None
        assert action.command == "truncate"
        assert "/tmp/log" in action.targets

    def test_dd(self):
        action = identify_destructive(["dd", "if=/dev/zero", "of=/tmp/disk", "bs=1M"])
        assert action is not None
        assert action.command == "dd"
        assert "/tmp/disk" in action.targets

    def test_find_delete(self):
        action = identify_destructive(["find", ".", "-name", "*.pyc", "-delete"])
        assert action is not None
        assert action.command == "find"
        assert "." in action.targets

    def test_find_exec_rm(self):
        action = identify_destructive(["find", "/tmp", "-exec", "rm", "{}", ";"])
        assert action is not None
        assert action.command == "find"
        assert "/tmp" in action.targets

    def test_git_clean(self):
        action = identify_destructive(["git", "clean", "-fdx"])
        assert action is not None
        assert action.command == "git"

    def test_git_reset_hard(self):
        action = identify_destructive(["git", "reset", "--hard"])
        assert action is not None
        assert action.command == "git"

    def test_non_destructive(self):
        action = identify_destructive(["ls", "-la"])
        assert action is None

    def test_cat_not_destructive(self):
        action = identify_destructive(["cat", "/etc/passwd"])
        assert action is None

    def test_bin_rm_stripped(self):
        """Full path to rm is stripped to just 'rm'."""
        action = identify_destructive(["/bin/rm", "-rf", "/tmp/foo"])
        assert action is not None
        assert action.command == "rm"

    def test_rm_multiple_targets(self):
        action = identify_destructive(["rm", "-rf", "/tmp/a", "/tmp/b", "/tmp/c"])
        assert action is not None
        assert len(action.targets) == 3
