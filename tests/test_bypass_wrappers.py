"""Adversarial bypass regression tests (audit round v0.5).

Each test encodes a confirmed bypass where a destructive command whose
resolved target is a floor path (or otherwise unmodellable) was ALLOWED
on main. The fix must make every one of these fail closed — a BLOCK.

Findings covered:

  F1 (critical): wrapper-prefix bypass. identify_destructive only
    inspected tokens[0], so any command runner in front of rm hid it:
    ``sudo rm -rf /etc``, ``env rm -rf /etc``, ``xargs rm -rf /etc``,
    ``timeout 5 rm -rf /etc``, ``nice/nohup/ionice/stdbuf/setsid/exec/
    command/doas/busybox rm ...`` all ran unchecked.

  F2 (high): git global-option bypass. The subcommand check required
    args[0] == "clean"/"reset", so ``git -C / reset --hard`` and
    ``git --git-dir=... --work-tree=/ reset --hard`` slipped through.

  F3 (high): unmodelled expansion fail-open. resolve only expands
    plain $VAR / ${VAR}. Forms it does not model — ``${VAR:-/}``,
    ``${VAR:=/}``, ``$1``, ``$$``, ``$@``, ``${#VAR}``, ``${VAR%/*}``
    — were passed through as literals instead of being refused. In a
    real shell ``rm -rf ${UNSET:-/}`` deletes ``/``.

  F4 (medium): ``find ... -execdir rm`` was not detected (only -exec).

  F5 (minor): ``truncate -s0 FILE`` (glued size flag) was not detected.
"""

from __future__ import annotations

from blastradius.check import check_command
from blastradius.commands import identify_destructive
from blastradius.tokenise import tokenise


def _tokens(cmd: str) -> list[str]:
    res = tokenise(cmd)
    assert res.segments is not None, f"unexpected tokenise refusal for {cmd!r}"
    assert len(res.segments) == 1
    return res.segments[0]


def _block(cmd: str, cwd, *, env=None):
    e = {"HOME": "/nonexistent-home", "PATH": "/usr/bin:/bin"}
    if env:
        e.update(env)
    result = check_command(cmd, cwd=str(cwd), env=e)
    assert not result.allowed, f"expected BLOCK for {cmd!r}, got ALLOW"
    return result


# ─────────────────────────────────────────────────────────────────────
# F1: wrapper-prefix bypass
# ─────────────────────────────────────────────────────────────────────

WRAPPER_RM_FLOOR = [
    "sudo rm -rf /etc",
    "sudo -u root rm -rf /etc",
    "doas rm -rf /etc",
    "env rm -rf /etc",
    "env -i rm -rf /etc",
    "env FOO=bar rm -rf /etc",
    "command rm -rf /etc",
    "exec rm -rf /etc",
    "nice rm -rf /etc",
    "nice -n 19 rm -rf /etc",
    "nohup rm -rf /etc",
    "setsid rm -rf /etc",
    "ionice -c3 rm -rf /etc",
    "stdbuf -oL rm -rf /etc",
    "timeout 5 rm -rf /etc",
    "timeout -s KILL 5 rm -rf /etc",
    "time rm -rf /etc",
    "busybox rm -rf /etc",
    "xargs rm -rf /etc",
]


class TestF1WrapperPrefixBypass:
    def test_each_wrapper_blocks_floor(self, tmp_path):
        (tmp_path / ".git").mkdir()
        for cmd in WRAPPER_RM_FLOOR:
            result = _block(cmd, tmp_path)
            assert result.first_refusal is not None

    def test_nested_wrappers(self, tmp_path):
        (tmp_path / ".git").mkdir()
        _block("sudo nice rm -rf /etc", tmp_path)

    def test_identify_unwraps(self):
        action = identify_destructive(_tokens("sudo rm -rf /etc"))
        assert action is not None
        assert action.command == "rm"
        assert "/etc" in action.targets

    def test_wrapper_on_inscope_still_allows(self, tmp_path):
        """Unwrapping must not over-block: sudo rm of an in-scope dir is fine."""
        (tmp_path / ".git").mkdir()
        (tmp_path / "build").mkdir()
        result = check_command(
            "sudo rm -rf build",
            cwd=str(tmp_path),
            env={"HOME": "/nonexistent-home", "PATH": "/usr/bin:/bin"},
        )
        assert result.allowed, f"got: {result.first_refusal}"

    def test_non_destructive_wrapper_still_allows(self, tmp_path):
        (tmp_path / ".git").mkdir()
        result = check_command(
            "sudo apt-get install cowsay",
            cwd=str(tmp_path),
            env={"HOME": "/nonexistent-home", "PATH": "/usr/bin:/bin"},
        )
        assert result.allowed


# ─────────────────────────────────────────────────────────────────────
# F2: git global-option bypass
# ─────────────────────────────────────────────────────────────────────


class TestF2GitGlobalOptionBypass:
    def test_git_C_reset_hard(self, tmp_path):
        (tmp_path / ".git").mkdir()
        _block("git -C /home reset --hard", tmp_path)

    def test_git_dir_worktree_reset(self, tmp_path):
        (tmp_path / ".git").mkdir()
        _block("git --git-dir=/x --work-tree=/ reset --hard", tmp_path)

    def test_git_C_clean(self, tmp_path):
        (tmp_path / ".git").mkdir()
        _block("git -C / clean -fdx", tmp_path)


# ─────────────────────────────────────────────────────────────────────
# F3: unmodelled expansion fail-open
# ─────────────────────────────────────────────────────────────────────

UNMODELLED_EXPANSIONS = [
    "rm -rf ${UNSET:-/}",
    "rm -rf ${UNSET:=/}",
    "rm -rf ${UNSET:+/etc}",
    "rm -rf $1",
    "rm -rf $$",
    "rm -rf $@",
    "rm -rf ${#HOME}",
    "rm -rf ${HOME%/*}",
]


class TestF3UnmodelledExpansionFailClosed:
    def test_unmodelled_expansions_refuse(self, tmp_path):
        (tmp_path / ".git").mkdir()
        for cmd in UNMODELLED_EXPANSIONS:
            result = _block(cmd, tmp_path, env={"HOME": "/nonexistent-home"})
            assert result.first_refusal is not None

    def test_plain_var_still_expands(self, tmp_path):
        """A modelled $VAR must still expand and be allowed when in scope."""
        (tmp_path / ".git").mkdir()
        (tmp_path / "build").mkdir()
        result = check_command(
            "rm -rf $TARGET/build",
            cwd=str(tmp_path),
            env={"HOME": "/nonexistent-home", "TARGET": str(tmp_path)},
        )
        assert result.allowed, f"got: {result.first_refusal}"


# ─────────────────────────────────────────────────────────────────────
# F4: find -execdir
# ─────────────────────────────────────────────────────────────────────


class TestF4FindExecdir:
    def test_find_execdir_rm_floor(self, tmp_path):
        (tmp_path / ".git").mkdir()
        _block("find /etc -execdir rm -rf {} +", tmp_path)


# ─────────────────────────────────────────────────────────────────────
# F5: truncate glued size flag
# ─────────────────────────────────────────────────────────────────────


class TestF5TruncateGluedSize:
    def test_truncate_s0_glued(self, tmp_path):
        (tmp_path / ".git").mkdir()
        _block("truncate -s0 /etc/passwd", tmp_path)
