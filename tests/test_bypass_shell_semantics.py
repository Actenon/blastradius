"""Adversarial bypass regression tests — shell-semantics round.

Every BLOCK case below was ALLOWED on 04059ad even though, run by a real
shell, it deletes or truncates a floor / out-of-scope path (or its target
cannot be determined). Every ALLOW case is ordinary in-scope work that must
not be blocked by the fixes.

Classes covered:
  W  wrapper robustness — unknown options / leading positionals / missing
     wrappers (sudo -D, chrt PRIO, taskset MASK, flock FILE, watch, ...),
     plus the fallback scan for a destructive command after a wrapper.
  S  command strings — <shell> -c, env -S, su/runuser/script/flock -c, sg,
     watch, find -exec sh -c, xargs sh -c, here-strings — checked
     recursively with the same cwd/env/scope, depth-capped.
  U  unlink.
  R  output redirection (>, >|, &>, N>) judged as a truncate target;
     tee likewise; appends / fd dups / /dev/null exempt; redirections never
     treated as rm targets.
  P  parsing: & and |& are separators, ( ) anywhere is a subshell, shell
     keywords and NAME=VAL prefixes before a command, $CMD as the command
     word, brace expansion, $'..' ANSI-C quoting, $( ) / backticks inside
     double quotes, eval anywhere.
  F  flow: cd / pushd changing the cwd of later segments, variables assigned
     earlier in the same command, variable values that word-split.
"""

from __future__ import annotations

import shlex

import pytest

from blastradius.check import check_command
from blastradius.tokenise import tokenise


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repo"
    (root / ".git").mkdir(parents=True)
    (root / "build").mkdir()
    (root / "build" / "a.o").write_text("x")
    (root / "file").write_text("x")
    # HOME outside every default scope entry (tmp_path lives under /tmp).
    home = "/nonexistent-blastradius-home"
    tmpd = tmp_path / "tmpd"
    tmpd.mkdir()
    env = {"HOME": str(home), "TMPDIR": str(tmpd), "PATH": "/usr/bin:/bin"}
    return root, env


def _run(cmd, repo, extra_env=None):
    root, env = repo
    e = dict(env)
    if extra_env:
        e.update(extra_env)
    return check_command(cmd, cwd=str(root), env=e)


def _nest(inner: str, n: int) -> str:
    for _ in range(n):
        inner = "sh -c " + shlex.quote(inner)
    return inner


MUST_BLOCK = [
    # W — wrappers
    "sudo -D / rm -rf /etc",
    "sudo -D / rm -rf etc",
    "env -C / rm -rf etc",
    "chrt 99 rm -rf /etc",
    "chrt -f 99 rm -rf /etc",
    "taskset 1 rm -rf /etc",
    "taskset -c 0 rm -rf /etc",
    "flock /tmp/l rm -rf /etc",
    "watch rm -rf /etc",
    "unbuffer rm -rf /etc",
    "caffeinate rm -rf /etc",
    "systemd-run rm -rf /etc",
    "systemd-run rm -rf etc",
    "exec -a foo rm -rf /etc",
    "builtin cd / && rm -rf etc",
    "pkexec rm -rf /etc",
    "chroot / rm -rf /etc",
    "uv run rm -rf /etc",
    "nice " * 40 + "rm -rf /etc",
    "sudo grep -r rm /etc",  # accepted false-positive class (fallback scan)
    # S — command strings
    "env -S 'rm -rf /etc'",
    "env --split-string='rm -rf /etc'",
    "bash -c 'rm -rf /etc'",
    'sh -c "rm -rf $HOME"',
    "zsh -c 'rm -rf /'",
    "bash -lc 'rm -rf /etc'",
    "dash -c -- 'rm -rf /etc'",
    "sudo sh -c 'rm -rf /etc'",
    "busybox sh -c 'rm -rf /etc'",
    "su -c 'rm -rf /etc'",
    "su root -c 'rm -rf /etc'",
    "runuser -u root -- rm -rf /etc",
    "runuser -c 'rm -rf /etc' root",
    "script -c 'rm -rf /etc' /dev/null",
    "flock /tmp/l -c 'rm -rf /etc'",
    "sg root 'rm -rf /etc'",
    "watch 'rm -rf /etc'",
    "xargs sh -c 'rm -rf /etc'",
    "find . -exec sh -c 'rm -rf /etc' \\;",
    "find . -execdir bash -c 'rm -rf /etc' \\;",
    "bash <<< 'rm -rf /etc'",
    "sh -c \"sh -c 'rm -rf /etc'\"",
    _nest("true", 8),  # nesting depth cap -> fail closed
    "sh -c 'rm -rf \"$1\"' _ build",  # positional params are not modelled
    # U — unlink
    "unlink /etc/passwd",
    "sudo unlink /etc/hosts",
    # R — redirection / tee
    ": > /etc/passwd",
    "echo x > /etc/passwd",
    "echo x >/etc/passwd",
    "cat /dev/null > /etc/hosts",
    "true >| /etc/passwd",
    "echo x &> /etc/passwd",
    "echo x 2> /etc/passwd",
    "echo x 1>/etc/passwd",
    "echo x >& /etc/passwd",
    "> /etc/passwd",
    "echo x > ~/.bashrc",
    "echo x > \"$HOME/.bashrc\"",
    "echo x > $UNSET_VAR/f",
    "echo x | tee /etc/passwd",
    "echo x | sudo tee /etc/hosts",
    "find . -fprint /etc/passwd",
    "rm -rf build > /etc/passwd",
    # P — parsing
    "FOO=bar rm -rf /etc",
    "sleep 1 & rm -rf /etc",
    "true |& rm -rf /etc",
    "true && (rm -rf /etc)",
    "! rm -rf /etc",
    "{ rm -rf /etc; }",
    "if true; then rm -rf /etc; fi",
    "while true; do rm -rf /etc; done",
    "true && eval 'rm -rf /etc'",
    "function f { rm -rf /etc; }; f",
    "rm -rf {/etc,build}",
    "rm -rf build{,/../../../../../../../../etc}",
    "{rm,x} -rf /etc",
    "echo $'\\'' ; rm -rf /etc #'",
    "echo \"$(rm -rf /etc)\"",
    "echo \"`rm -rf /etc`\"",
    "rm -rf \"unterminated",
    "rm -rf ${X:-\"/\"}",
    "echo {1..100000}",
    # F — flow
    "cd / && rm -rf etc",
    "cd / ; rm -rf etc",
    "cd / || true && rm -rf etc",
    "pushd / && rm -rf etc",
    "cd - && rm -rf x",
    "source ./env.sh && rm -rf x",
    "true | xargs -I{} rm -rf {}",
    "xargs rm -rf build",
]

MUST_BLOCK_ENV = [
    ("$RM -rf /etc", {"RM": "rm"}),
    ("\"$RM\" -rf /etc", {"RM": "/bin/rm"}),
    ("$CMD", {"CMD": "rm -rf /etc"}),
    ("X=/etc; rm -rf \"$X\"", {"X": "build"}),
    ("export X=/etc && rm -rf \"$X\"", {"X": "build"}),
    ("unset D; rm -rf \"$D\"/*", {"D": "build"}),
    ("read X; rm -rf $X", {"X": "build"}),
    ("rm -rf $X", {"X": "build /etc"}),
    ("X=/etc sh -c 'rm -rf $X'", None),
    ("env X=/etc sh -c 'rm -rf $X'", None),
    ("sh -c 'rm -rf $X'", {"X": "/etc"}),
    ("sudo sh -c 'rm -rf \"$D\"'", {"D": "/etc"}),
    ("cd $D && rm -rf etc", {"D": "/"}),
]

MUST_ALLOW = [
    "rm -rf build",
    "rm -rf build 2>/dev/null",
    "rm -rf build >/dev/null 2>&1",
    "rm -rf build &>/dev/null",
    "ls > build/out.txt",
    "pytest > /tmp/log",
    "pytest > $TMPDIR/log",
    "make 2>&1",
    "make >&2",
    "echo \"a > b\"",
    "grep '>' file",
    "echo hi >> ~/.bashrc",
    "echo hi | tee -a /etc/hosts",
    "make 2>&1 | tee build/log.txt",
    "cd build && rm -rf *",
    "cd build && rm -rf a.o",
    "rm -rf build/{a.o,b.o}",
    "sudo rm -rf build",
    "sudo apt-get install cowsay",
    "command -v rm",
    "timeout 60 pytest",
    "nohup python server.py &",
    "bash -c 'rm -rf build'",
    "sh -c 'ls -la'",
    "find . -name '*.pyc' -delete",
    "find . -exec rm {} +",
    "python -m build && twine upload dist/*",
    "git status; git diff",
    "echo '(not a subshell)'",
    "rm -rf \"$TMPDIR/x\"",
    "bash script.sh",
    "python -c 'import shutil; shutil.rmtree(\"/etc\")'",
]


@pytest.mark.parametrize("cmd", MUST_BLOCK)
def test_must_block(cmd, repo):
    result = _run(cmd, repo)
    assert not result.allowed, f"expected BLOCK for {cmd!r}"
    assert result.first_refusal is not None and result.first_refusal.rule


@pytest.mark.parametrize("cmd,extra", MUST_BLOCK_ENV)
def test_must_block_with_env(cmd, extra, repo):
    result = _run(cmd, repo, extra)
    assert not result.allowed, f"expected BLOCK for {cmd!r} with {extra}"


@pytest.mark.parametrize("cmd", MUST_ALLOW)
def test_must_allow(cmd, repo):
    result = _run(cmd, repo)
    assert result.allowed, f"expected ALLOW for {cmd!r}, got {result.refusals}"


class TestLegibility:
    def test_nested_block_carries_inner_rule(self, repo):
        result = _run("bash -c 'rm -rf /etc'", repo)
        assert result.first_refusal.rule == "floor-path"
        assert result.first_refusal.resolved == "/etc"
        assert "bash -c" in result.first_refusal.reason

    def test_redirect_refusal_names_redirect(self, repo):
        result = _run(": > /etc/passwd", repo)
        ref = result.first_refusal
        assert ref.rule == "out-of-scope"
        assert ref.resolved == "/etc/passwd"
        assert ref.raw.startswith(">")
        assert "redirection" in ref.reason

    def test_redirect_not_treated_as_rm_target(self, repo):
        result = _run("rm -rf build > /etc/passwd", repo)
        raws = [r.raw for r, _ in result.refusals]
        assert raws == [">/etc/passwd"], raws


class TestTokeniserRedirections:
    def test_redirections_stripped_from_argv(self):
        result = tokenise("rm -rf build 2>/dev/null >out.txt")
        assert result.segments == [["rm", "-rf", "build"]]
        kinds = [(r.fd, r.op, r.target, r.kind) for r in result.redirections[0]]
        assert kinds == [("2", ">", "/dev/null", "truncate"),
                         (None, ">", "out.txt", "truncate")]

    def test_fd_dup_is_not_a_file(self):
        result = tokenise("make 2>&1")
        assert result.segments == [["make"]]
        assert result.redirections[0][0].kind == "dup"

    def test_quoted_gt_is_literal(self):
        result = tokenise("echo \"a > b\" '>'")
        assert result.segments == [["echo", "a > b", ">"]]
        assert result.redirections == [[]]

    def test_ampersand_separates(self):
        result = tokenise("sleep 1 & rm x")
        assert result.segments == [["sleep", "1"], ["rm", "x"]]
        assert result.separators == ["&"]

    def test_brace_expansion(self):
        result = tokenise("rm {a,b}/x c{1..3} '{q,r}' {}")
        assert result.segments == [["rm", "a/x", "b/x", "c1", "c2", "c3", "{q,r}", "{}"]]


class TestWrapperModeQuoting:
    def test_argv_quoting_preserved(self, capsys, monkeypatch, repo):
        """Wrapper mode must re-quote argv; ' '.join lost the -c string."""
        from blastradius.cli import main

        root, env = repo
        monkeypatch.chdir(root)
        for k, v in env.items():
            monkeypatch.setenv(k, v)
        rc = main(["--", "sh", "-c", "rm -rf /etc"])  # blocked: never execs
        err = capsys.readouterr().err
        assert rc == 1
        assert "floor-path" in err and "/etc" in err
