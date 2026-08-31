"""Adversarial regression tests — one per bug found in the diligence round.

Every bug in the audit gets a regression test that would fail without
the fix. These tests are the proof that the fix works and the proof
that the bug doesn't come back.

Bug list (severity, description, fix):

  BUG 1 (critical): Tokeniser refused ; | && even inside quotes.
    Fix: quote-aware scan replaces raw regex.
  BUG 2 (critical): Newline bypass — echo foo\\nrm -rf $HOME allowed.
    Fix: newlines treated as command separators (refused).
  BUG 3 (low): Backslash-newline line continuation not handled.
    Fix: \\<newline> is removed during tokenisation.
  BUG 4 (medium): rm -- -foo misclassified -foo as a flag.
    Fix: -- end-of-flags separator tracked in command parsing.
  BUG 5 (medium): rm -rf with no targets was allowed.
    Fix: destructive commands with zero targets are refused.
  BUG 7 (medium): os.execvp crash on command-not-found showed traceback.
    Fix: catch FileNotFoundError, print clean error, exit 127.
  BUG 8 (medium): /path/** did not match /path itself.
    Fix: ** regex matches zero path components.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from blastradius.check import check_command
from blastradius.commands import identify_destructive
from blastradius.rules import Scope, _match_scope
from blastradius.tokenise import tokenise


# ─────────────────────────────────────────────────────────────────────
# BUG 1: Quoted metacharacters should NOT trigger refusal
# ─────────────────────────────────────────────────────────────────────


class TestBug1QuotedMetacharacters:
    """The tokeniser must not refuse ; | && inside quotes.

    v0.3.0: &&, ||, ;, | are now SPLIT into segments rather than
    refused. Quoted versions are still treated as literals.
    """

    def test_quoted_semicolon_not_split(self):
        """rm -rf "foo;bar" — semicolon inside quotes is a literal."""
        result = tokenise('rm -rf "foo;bar"')
        assert result.segments is not None
        assert len(result.segments) == 1  # one segment, not split
        assert "foo;bar" in result.segments[0]

    def test_quoted_pipe_not_split(self):
        """rm -rf "foo|bar" — pipe inside quotes is a literal."""
        result = tokenise('rm -rf "foo|bar"')
        assert result.segments is not None
        assert len(result.segments) == 1
        assert "foo|bar" in result.segments[0]

    def test_quoted_logical_and_not_split(self):
        """rm -rf "foo&&bar" — && inside quotes is a literal."""
        result = tokenise('rm -rf "foo&&bar"')
        assert result.segments is not None
        assert len(result.segments) == 1
        assert "foo&&bar" in result.segments[0]

    def test_single_quoted_semicolon_not_split(self):
        """rm -rf 'foo;bar' — single quotes too."""
        result = tokenise("rm -rf 'foo;bar'")
        assert result.segments is not None
        assert len(result.segments) == 1
        assert "foo;bar" in result.segments[0]

    def test_unquoted_semicolon_splits(self):
        """rm -rf foo;bar — unquoted semolon SPLITS into two segments."""
        result = tokenise("rm -rf foo;bar")
        assert result.segments is not None
        assert len(result.segments) == 2
        assert result.separators == [";"]

    def test_unquoted_pipe_splits(self):
        """rm -rf foo|bar — unquoted pipe SPLITS into two segments."""
        result = tokenise("rm -rf foo|bar")
        assert result.segments is not None
        assert len(result.segments) == 2
        assert result.separators == ["|"]

    def test_escaped_semicolon_not_split(self):
        """rm -rf foo\\;bar — backslash-escaped semicolon is a literal."""
        result = tokenise(r"rm -rf foo\;bar")
        assert result.segments is not None
        assert len(result.segments) == 1
        assert "foo;bar" in result.segments[0]


# ─────────────────────────────────────────────────────────────────────
# BUG 2: Newline bypass — the most critical bug
# ─────────────────────────────────────────────────────────────────────


class TestBug2NewlineBypass:
    """Newline in a command string is a command separator.

    Before the fix, `echo hello\\nrm -rf $HOME` was ALLOWED because:
      1. The tokeniser treated \\n as whitespace, producing
         ['echo', 'hello', 'rm', '-rf', '$HOME']
      2. The command identifier saw 'echo' as the first token (non-
         destructive) and returned None.
      3. The second 'rm' was never checked.

    An agent could bypass every check by sending a newline in the
    command string. This is the most serious bug in the repo.
    """

    def test_newline_refused(self):
        """A newline in the command is refused."""
        result = tokenise("echo hello\nrm -rf $HOME")
        assert result.refusal is not None
        assert "newline" in result.refusal.rule

    def test_newline_bypass_blocked(self):
        """echo hello\\nrm -rf $HOME must NOT be allowed."""
        env = {"HOME": "/home/test", "PATH": "/usr/bin"}
        scope = Scope(allow=[], repo_root=None)
        result = check_command(
            "echo hello\nrm -rf $HOME",
            env=env,
            scope=scope,
        )
        assert not result.allowed
        assert result.first_refusal is not None
        assert "newline" in result.first_refusal.rule

    def test_newline_in_quotes_not_refused(self):
        """A newline inside quotes is a literal, not a separator."""
        result = tokenise('rm -rf "foo\nbar"')
        # The newline is inside double quotes — it's a literal.
        # This should NOT be refused.
        assert result.refusal is None
        assert result.segments is not None
        assert "foo\nbar" in result.segments[0]


# ─────────────────────────────────────────────────────────────────────
# BUG 3: Backslash-newline line continuation
# ─────────────────────────────────────────────────────────────────────


class TestBug3LineContinuation:
    """Backslash-newline (line continuation) should be removed, not
    produce a literal newline in the token.
    """

    def test_line_continuation_removed(self):
        """rm -rf /tmp/foo\\<newline>bar → rm -rf /tmp/foobar"""
        result = tokenise("rm -rf /tmp/foo\\\nbar")
        assert result.segments is not None
        # The backslash-newline is removed, joining foo and bar.
        assert "/tmp/foobar" in result.segments[0]

    def test_line_continuation_in_double_quotes(self):
        """Inside double quotes, \\<newline> is also a line continuation."""
        result = tokenise('rm -rf "foo\\\nbar"')
        assert result.segments is not None
        assert "foobar" in result.segments[0]


# ─────────────────────────────────────────────────────────────────────
# BUG 4: -- end-of-flags separator
# ─────────────────────────────────────────────────────────────────────


class TestBug4DoubleDashSeparator:
    """rm -- -foo must treat -foo as a target, not a flag.

    Before the fix, -foo was misclassified as a flag because it
    starts with -. This meant a file named -foo (or -rf) inside
    scope would not be checked.
    """

    def test_double_dash_makes_flag_like_arg_a_target(self):
        """rm -- -foo → -foo is a target."""
        action = identify_destructive(["rm", "--", "-foo"])
        assert action is not None
        assert "-foo" in action.targets
        assert "--" not in action.targets  # -- itself is not a target

    def test_double_dash_with_rf_flag(self):
        """rm -rf -- -foo → -foo is a target, -rf is a flag."""
        action = identify_destructive(["rm", "-rf", "--", "-foo"])
        assert action is not None
        assert "-foo" in action.targets
        assert "-rf" in action.flags

    def test_double_dash_multiple_targets(self):
        """rm -- -foo -bar -baz → all are targets."""
        action = identify_destructive(["rm", "--", "-foo", "-bar", "-baz"])
        assert action is not None
        assert "-foo" in action.targets
        assert "-bar" in action.targets
        assert "-baz" in action.targets

    def test_no_double_dash_flag_still_flag(self):
        """rm -foo (without --) → -foo is a flag (existing behaviour)."""
        action = identify_destructive(["rm", "-foo"])
        assert action is not None
        # Without --, -foo is a flag. targets is empty → no-targets refusal.
        assert action.targets == []


# ─────────────────────────────────────────────────────────────────────
# BUG 5: Destructive command with no targets
# ─────────────────────────────────────────────────────────────────────


class TestBug5NoTargets:
    """rm -rf with no targets must be refused.

    Before the fix, rm -rf (no targets) was allowed because the
    target list was empty, so no refusals were generated. This is
    suspicious — the intent is unclear and it may be a misparsed
    command.
    """

    def test_rm_no_targets_refused(self):
        env = {"HOME": "/home/test", "PATH": "/usr/bin"}
        result = check_command("rm -rf", env=env, scope=Scope(allow=[]))
        assert not result.allowed
        assert result.first_refusal.rule == "no-targets"

    def test_rm_only_flags_refused(self):
        env = {"HOME": "/home/test", "PATH": "/usr/bin"}
        result = check_command("rm --force --recursive", env=env, scope=Scope(allow=[]))
        assert not result.allowed
        assert result.first_refusal.rule == "no-targets"


# ─────────────────────────────────────────────────────────────────────
# BUG 7: Command-not-found crash
# ─────────────────────────────────────────────────────────────────────


class TestBug7CommandNotFound:
    """os.execvp on a non-existent command should not crash with a
    Python traceback. It should print a clean error and exit 127.
    """

    def test_nonexistent_command_clean_error(self):
        result = subprocess.run(
            [sys.executable, "-m", "blastradius", "--", "nonexistent-cmd-12345"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 127
        assert "command not found" in result.stderr
        assert "Traceback" not in result.stderr


# ─────────────────────────────────────────────────────────────────────
# BUG 8: /path/** should match /path itself
# ─────────────────────────────────────────────────────────────────────


class TestBug8DoubleStarMatchesRoot:
    """/tmp/blast_repo/** must match /tmp/blast_repo itself.

    Before the fix, ** required at least one path component after the
    prefix, so `rm -rf /tmp/blast_repo` (the repo root itself) was
    out-of-scope even though the scope allowed `/tmp/blast_repo/**`.
    This was a false positive.
    """

    def test_double_star_matches_root(self):
        scope = Scope(allow=["/tmp/blast_repo/**"], repo_root=None)
        assert scope.allows("/tmp/blast_repo") is True

    def test_double_star_matches_descendant(self):
        scope = Scope(allow=["/tmp/blast_repo/**"], repo_root=None)
        assert scope.allows("/tmp/blast_repo/foo") is True

    def test_double_star_matches_deep_descendant(self):
        scope = Scope(allow=["/tmp/blast_repo/**"], repo_root=None)
        assert scope.allows("/tmp/blast_repo/a/b/c") is True

    def test_double_star_with_trailing_slash(self):
        scope = Scope(allow=["/tmp/blast_repo/**"], repo_root=None)
        assert scope.allows("/tmp/blast_repo/") is True

    def test_double_star_does_not_match_sibling(self):
        scope = Scope(allow=["/tmp/blast_repo/**"], repo_root=None)
        assert scope.allows("/tmp/other_repo") is False

    def test_rm_repo_root_itself_allowed(self):
        """rm -rf /tmp/blast_repo (the root itself) should be allowed
        when scope allows /tmp/blast_repo/**."""
        import os
        os.makedirs("/tmp/blast_repo8", exist_ok=True)
        env = {"HOME": "/home/test", "PATH": "/usr/bin"}
        scope = Scope(allow=["/tmp/blast_repo8/**"], repo_root="/tmp/blast_repo8")
        result = check_command(
            "rm -rf /tmp/blast_repo8",
            env=env,
            scope=scope,
        )
        assert result.allowed, f"Should allow repo root deletion, got: {result.first_refusal}"


# ─────────────────────────────────────────────────────────────────────
# Additional adversarial: .. escape from scope
# ─────────────────────────────────────────────────────────────────────


class TestDotDotEscape:
    """../ escape from inside scope to outside must be caught."""

    def test_dotdot_escape_to_floor(self):
        """/tmp/repo/sub/../../../home/test → /home/test (floor)."""
        env = {"HOME": "/home/test", "PATH": "/usr/bin"}
        os.makedirs("/tmp/blast_dd/sub", exist_ok=True)
        scope = Scope(allow=["/tmp/blast_dd/**"], repo_root="/tmp/blast_dd")
        result = check_command(
            "rm -rf /tmp/blast_dd/sub/../../../home/test",
            env=env,
            scope=scope,
        )
        assert not result.allowed
        assert result.first_refusal.rule == "floor-path"

    def test_dotdot_escape_to_outside_scope(self):
        """/tmp/repo/sub/../../outside → /tmp/outside (out-of-scope)."""
        env = {"HOME": "/home/test", "PATH": "/usr/bin"}
        os.makedirs("/tmp/blast_dd2/sub", exist_ok=True)
        os.makedirs("/tmp/blast_outside", exist_ok=True)
        scope = Scope(allow=["/tmp/blast_dd2/**"], repo_root="/tmp/blast_dd2")
        result = check_command(
            "rm -rf /tmp/blast_dd2/sub/../../blast_outside",
            env=env,
            scope=scope,
        )
        assert not result.allowed
        assert result.first_refusal.rule == "out-of-scope"
