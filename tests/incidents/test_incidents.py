"""The six public incidents — reconstructed. Each must block.

These are the failure cases blastradius exists to prevent. Every one
of these tests must pass (i.e. the command must be blocked with the
correct rule) or the tool is not doing its job.

The incidents:

  1. Guillemot (Aug 2026): variable collision — rm -rf "$CLEANUP_DIR"
     where CLEANUP_DIR is unset. The model's safety test and the
     cleanup step reused the same variable name. 700GB deleted.
  2. Claude Code #49464 (Apr 2026): rm -f ~/ — cleaning a file
     literally named ~.
  3. Claude Code #12637 (Nov 2025): glob expansion caught a directory
     named ~.
  4. Claude Code #10077 (Oct 2025): rm -rf $HOME — home directory
     deletion.
  5. Dec 2025 Mac wipe: rm -rf ~/Library — wiped Mac including
     Keychain.
  6. Aug 2026 backup typo: rm -rf $HOME/ .profile — extra space made
     rm target $HOME/ (the whole home dir) instead of $HOME/.profile.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from blastradius.check import check_command
from blastradius.rules import Scope


# ─────────────────────────────────────────────────────────────────────
# Incident 1: Guillemot (Aug 2026)
# ─────────────────────────────────────────────────────────────────────


class TestGuillemotIncident:
    """The variable collision that deleted 700GB.

    The model's safety test and the cleanup step reused the same
    variable name. The safety check correctly identified the home
    directory as dangerous. The cleanup then deleted it because
    the variable was empty.
    """

    def test_unset_variable_in_path_blocks(self):
        """rm -rf $UNSET_VAR/subdir — empty expansion produces /subdir."""
        env = {"HOME": "/home/test", "PATH": "/usr/bin"}
        result = check_command(
            'rm -rf "$UNSET_VAR/session-data"',
            env=env,
            scope=Scope(allow=[], repo_root=None),
        )
        assert not result.allowed
        refusal = result.first_refusal
        assert refusal is not None
        assert refusal.rule == "empty-variable-expansion"
        assert "UNSET_VAR" in refusal.reason

    def test_unset_variable_bare_blocks(self):
        """rm -rf $UNSET_VAR — bare empty variable."""
        env = {"HOME": "/home/test", "PATH": "/usr/bin"}
        result = check_command(
            "rm -rf $UNSET_VAR",
            env=env,
            scope=Scope(allow=[], repo_root=None),
        )
        assert not result.allowed
        refusal = result.first_refusal
        assert refusal is not None
        assert refusal.rule == "empty-variable-expansion"
        assert "UNSET_VAR" in refusal.reason

    def test_two_unset_variables_both_named(self):
        """rm -rf "$AGENT_TMP/session-$SID" — both unset, both named."""
        env = {"HOME": "/home/test", "PATH": "/usr/bin"}
        result = check_command(
            'rm -rf "$AGENT_TMP/session-$SID"',
            env=env,
            scope=Scope(allow=[], repo_root=None),
        )
        assert not result.allowed
        refusal = result.first_refusal
        assert refusal is not None
        assert refusal.rule == "empty-variable-expansion"
        assert "AGENT_TMP" in refusal.reason
        assert "SID" in refusal.reason

    def test_guillemot_pattern_resolves_to_root(self):
        """The specific Guillemot pattern: empty var + / prefix = root."""
        env = {"HOME": "/home/test", "PATH": "/usr/bin"}
        # CLEANUP_DIR is unset. "$CLEANUP_DIR" expands to "".
        # rm -rf "" is rm -rf CWD.
        result = check_command(
            'rm -rf "$CLEANUP_DIR"',
            env=env,
            scope=Scope(allow=[], repo_root=None),
        )
        assert not result.allowed
        refusal = result.first_refusal
        assert refusal is not None
        assert refusal.rule == "empty-variable-expansion"
        assert "CLEANUP_DIR" in refusal.reason


# ─────────────────────────────────────────────────────────────────────
# Incident 2: Claude Code #49464 (Apr 2026)
# ─────────────────────────────────────────────────────────────────────


class TestIncident49464:
    """rm -f ~/ — cleaning a file literally named ~.

    The developer intended to clean a file called ~ but the shell
    expanded ~ to $HOME, deleting the home directory.
    """

    def test_tilde_target_blocks(self):
        """rm -f ~/ — tilde as target."""
        env = {"HOME": "/home/test", "PATH": "/usr/bin"}
        result = check_command(
            "rm -f ~/",
            env=env,
            scope=Scope(allow=[], repo_root=None),
        )
        assert not result.allowed
        refusal = result.first_refusal
        assert refusal is not None
        assert refusal.rule == "tilde-ambiguous"

    def test_bare_tilde_blocks(self):
        """rm -rf ~ — bare tilde."""
        env = {"HOME": "/home/test", "PATH": "/usr/bin"}
        result = check_command(
            "rm -rf ~",
            env=env,
            scope=Scope(allow=[], repo_root=None),
        )
        assert not result.allowed
        refusal = result.first_refusal
        assert refusal is not None
        assert refusal.rule == "tilde-ambiguous"


# ─────────────────────────────────────────────────────────────────────
# Incident 3: Claude Code #12637 (Nov 2025)
# ─────────────────────────────────────────────────────────────────────


class TestIncident12637:
    """Glob expansion caught a directory named ~.

    A glob like rm -rf * expanded to include a directory named ~,
    which was then deleted.
    """

    def test_glob_containing_tilde_named_dir(self, tmp_path):
        """rm -rf * where a directory named ~ exists in CWD."""
        # Create a directory named ~ in tmp_path.
        tilde_dir = tmp_path / "~"
        tilde_dir.mkdir()
        (tilde_dir / "important.txt").write_text("data")

        env = {"HOME": "/home/test", "PATH": "/usr/bin"}
        result = check_command(
            "rm -rf *",
            env=env,
            scope=Scope(allow=[str(tmp_path) + "/**"], repo_root=str(tmp_path)),
            cwd=str(tmp_path),
        )
        # The glob * expands to include ~ — blastradius should refuse
        # because the ~ directory resolves to a path that looks like
        # home (or at minimum is suspicious).
        # Actually, the resolved path is tmp_path/~, which is not $HOME.
        # But the floor check doesn't catch it. The scope check allows
        # it (it's under tmp_path/**).
        #
        # This incident is about the ~ in the filename. Our tilde-ambiguous
        # rule catches ~ at the START of a target. A glob * that expands
        # to ~ is a different vector. We catch it via glob-breadth if
        # it's at repo root level.
        assert not result.allowed
        refusal = result.first_refusal
        assert refusal is not None
        # Should be blocked by glob-breadth (repo root level entry).
        assert refusal.rule == "glob-breadth"


# ─────────────────────────────────────────────────────────────────────
# Incident 4: Claude Code #10077 (Oct 2025)
# ─────────────────────────────────────────────────────────────────────


class TestIncident10077:
    """rm -rf $HOME — direct home directory deletion."""

    def test_home_directory_blocks(self):
        """rm -rf $HOME — floor rule (home directory)."""
        env = {"HOME": "/home/test", "PATH": "/usr/bin"}
        result = check_command(
            "rm -rf $HOME",
            env=env,
            scope=Scope(allow=[], repo_root=None),
        )
        assert not result.allowed
        refusal = result.first_refusal
        assert refusal is not None
        assert refusal.rule == "floor-path"
        assert "home" in refusal.reason.lower() or "protected" in refusal.reason.lower()

    def test_home_directory_literal_blocks(self):
        """rm -rf /home/test — floor rule (explicit $HOME path)."""
        env = {"HOME": "/home/test", "PATH": "/usr/bin"}
        result = check_command(
            "rm -rf /home/test",
            env=env,
            scope=Scope(allow=[], repo_root=None),
        )
        assert not result.allowed
        refusal = result.first_refusal
        assert refusal is not None
        # /home/test equals $HOME → floor.
        assert refusal.rule == "floor-path"

    def test_home_directory_cannot_be_overridden_by_scope(self):
        """Even if scope allows $HOME, floor wins."""
        env = {"HOME": "/home/test", "PATH": "/usr/bin"}
        result = check_command(
            "rm -rf $HOME",
            env=env,
            scope=Scope(allow=["/home/**"], repo_root=None),
        )
        assert not result.allowed
        refusal = result.first_refusal
        assert refusal is not None
        assert refusal.rule == "floor-path"


# ─────────────────────────────────────────────────────────────────────
# Incident 5: Dec 2025 Mac wipe
# ─────────────────────────────────────────────────────────────────────


class TestMacWipeIncident:
    """rm -rf ~/Library — wiped Mac including Keychain."""

    def test_tilde_library_blocks(self):
        """rm -rf ~/Library/Keychains — tilde-ambiguous."""
        env = {"HOME": "/Users/test", "PATH": "/usr/bin"}
        result = check_command(
            "rm -rf ~/Library/Keychains",
            env=env,
            scope=Scope(allow=[], repo_root=None),
        )
        assert not result.allowed
        refusal = result.first_refusal
        assert refusal is not None
        assert refusal.rule == "tilde-ambiguous"

    def test_explicit_library_blocks(self):
        """rm -rf /Users/test/Library — floor if $HOME=/Users/test."""
        env = {"HOME": "/Users/test", "PATH": "/usr/bin"}
        # /Users/test is $HOME → floor. But /Users/test/Library is a
        # descendant — NOT floor. It's out of scope → refused by scope.
        result = check_command(
            "rm -rf /Users/test/Library",
            env=env,
            scope=Scope(allow=[], repo_root=None),
        )
        assert not result.allowed
        refusal = result.first_refusal
        assert refusal is not None
        # Out of scope.
        assert refusal.rule == "out-of-scope"

    def test_users_directory_blocks(self):
        """rm -rf /Users — floor (explicit list)."""
        env = {"HOME": "/Users/test", "PATH": "/usr/bin"}
        result = check_command(
            "rm -rf /Users",
            env=env,
            scope=Scope(allow=[], repo_root=None),
        )
        assert not result.allowed
        refusal = result.first_refusal
        assert refusal is not None
        assert refusal.rule == "floor-path"


# ─────────────────────────────────────────────────────────────────────
# Incident 6: Aug 2026 backup typo
# ─────────────────────────────────────────────────────────────────────


class TestBackupTypoIncident:
    """rm -rf $HOME/ .profile — extra space made rm target $HOME/.

    The developer intended `rm -rf $HOME/.profile` but typed a space
    after the slash, making rm delete $HOME/ (the whole home dir)
    and .profile as separate targets.
    """

    def test_home_with_trailing_slash_blocks(self):
        """rm -rf $HOME/ — trailing slash, still $HOME."""
        env = {"HOME": "/home/test", "PATH": "/usr/bin"}
        result = check_command(
            "rm -rf $HOME/",
            env=env,
            scope=Scope(allow=[], repo_root=None),
        )
        assert not result.allowed
        refusal = result.first_refusal
        assert refusal is not None
        assert refusal.rule == "floor-path"

    def test_typo_with_two_targets_blocks(self):
        """rm -rf $HOME/ .profile — first target is $HOME."""
        env = {"HOME": "/home/test", "PATH": "/usr/bin"}
        result = check_command(
            "rm -rf $HOME/ .profile",
            env=env,
            scope=Scope(allow=[], repo_root=None),
        )
        assert not result.allowed
        # The first target ($HOME/) should be refused.
        refusal = result.first_refusal
        assert refusal is not None
        assert refusal.rule == "floor-path"


# ─────────────────────────────────────────────────────────────────────
# Floor rule — cannot be overridden by any configuration
# ─────────────────────────────────────────────────────────────────────


class TestFloorUnoverridable:
    """The floor rules cannot be configured away. Not by a flag, not by
    a config file, not by an environment variable."""

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
        "/tmp",
        "/opt",
        "/root",
        "/boot",
    ])
    def test_floor_paths_refused_regardless_of_scope(self, path):
        """Every floor path is refused even when scope explicitly allows it."""
        env = {"HOME": "/home/test", "PATH": "/usr/bin"}
        result = check_command(
            f"rm -rf {path}",
            env=env,
            scope=Scope(allow=[f"{path}/**", path], repo_root=None),
        )
        assert not result.allowed
        refusal = result.first_refusal
        assert refusal is not None
        assert refusal.rule == "floor-path"
