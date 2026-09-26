"""Core check function — the decision pipeline.

v0.3.0: Two-tier checking:

  TIER 1 (BLOCK): filesystem-destruction commands are checked against
    floor rules and scope. If a target is floor or out-of-scope, the
    command is BLOCKED (exit 1).

  TIER 2 (WARN): non-filesystem consequential actions (pip install,
    curl, git push, twine, chmod -R, .env access, deployment) produce
    WARNINGS that are printed to stderr but do not block. The developer
    decides whether to proceed.

The command is also split on &&, ||, ;, | — each segment is checked
independently. A compound command is blocked if ANY segment is blocked.

On ALLOW, the checker prints a one-line summary so the developer knows
what was checked and what wasn't — silence is never the output.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from .commands import (
    DestructiveAction,
    RiskWarning,
    extract_command_strings,
    identify_destructive,
    wrapper_cwds,
    identify_risks,
)
from .resolve import Refusal, Resolved, expand_target, resolve_target
from .rules import (
    DEFAULT_MAX_GLOB_BREADTH,
    Scope,
    check_glob_breadth,
    is_floor,
    floor_refusal,
    load_scope,
)
from .tokenise import tokenise


@dataclass
class CheckResult:
    """The result of checking a command."""

    allowed: bool
    refusals: list[tuple[Refusal, str]] = field(default_factory=list)
    warnings: list[RiskWarning] = field(default_factory=list)
    command: str = ""
    actions: list[DestructiveAction] = field(default_factory=list)
    segments_checked: int = 0

    @property
    def first_refusal(self) -> Refusal | None:
        return self.refusals[0][0] if self.refusals else None

    @property
    def blocked(self) -> bool:
        return not self.allowed

    @property
    def has_warnings(self) -> bool:
        return len(self.warnings) > 0


# Maximum recursion depth for inner command strings (shell -c, env -S, ...).
_MAX_DEPTH = 5

# Redirection targets that are never real files to truncate.
_REDIRECT_EXEMPT = {
    "/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty", "/dev/zero",
    "/dev/console", "/dev/full",
}

# Prefixes stripped when looking for a `cd`/`pushd` in a segment.
_CD_PREFIXES = {"builtin", "command", "exec"}


def check_command(
    command: str,
    *,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
    scope: Scope | None = None,
    max_glob_breadth: int = DEFAULT_MAX_GLOB_BREADTH,
    _depth: int = 0,
) -> CheckResult:
    """Check a command string. Returns CheckResult.

    TIER 1: If any segment is a filesystem-destruction command with a
    target that is floor or out-of-scope, the command is BLOCKED. This
    includes commands hidden behind wrappers (``sudo rm``), inside shell
    strings (``bash -c '...'``, ``env -S '...'``), and output redirections
    that truncate a file (``: > /etc/passwd``).

    TIER 2: If any segment contains a consequential non-filesystem
    action, a WARNING is added. Warnings do not block.

    On ALLOW, the result includes a summary of what was checked.
    """
    if cwd is None:
        cwd = os.getcwd()
    if env is None:
        env = dict(os.environ)
    if scope is None:
        scope = load_scope(cwd)

    if _depth > _MAX_DEPTH:
        # Too many nested shell strings to model — fail closed.
        return CheckResult(
            allowed=False,
            refusals=[(Refusal(
                rule="recursion-depth",
                reason=(
                    "nested shell command strings exceed the modelling "
                    "depth — blastradius cannot resolve the target with "
                    "certainty and refuses. Run it yourself outside the agent."
                ),
                raw=command,
            ), command)],
            command=command,
        )

    # ── Step 1: Tokenise (splits on &&, ||, ;, |, &, |&) ───────────
    tok_result = tokenise(command)
    if tok_result.refusal:
        return CheckResult(
            allowed=False,
            refusals=[(tok_result.refusal, command)],
            command=command,
        )

    segments = tok_result.segments or []
    redirections = tok_result.redirections or [[] for _ in segments]

    all_refusals: list[tuple[Refusal, str]] = []
    all_warnings: list[RiskWarning] = []
    all_actions: list[DestructiveAction] = []

    # Running state threaded across ; && || segments (sequential shell).
    run_env = dict(env)
    run_cwd = cwd
    cwd_known = True

    for seg_index, seg_tokens in enumerate(segments):
        seg_redirs = redirections[seg_index] if seg_index < len(redirections) else []

        # ── Leading NAME=VALUE assignments (and export/unset/read) ──
        assigns, rest = _split_leading_assignments(seg_tokens)
        seg_env = dict(run_env)
        for name, value in assigns:
            if value is None:
                seg_env.pop(name, None)          # unset / read → unknown
            else:
                exp = expand_target(value, seg_env, cwd=run_cwd)
                if isinstance(exp, Refusal):
                    seg_env.pop(name, None)      # unresolved value → unknown
                else:
                    seg_env[name] = exp[0]
        rest = _strip_leading_keywords(rest)
        if not rest:
            if assigns:
                # Assignments persist for later segments.
                run_env = seg_env
            # A bare redirection (``> file``) still truncates its target.
            for redir in seg_redirs:
                ref = _judge_redirect(redir, run_cwd, seg_env, scope,
                                      cwd_known=cwd_known)
                if ref is not None:
                    all_refusals.append((ref, redir.display))
            continue

        # ``function NAME { ...; }`` defines code that a later word may run.
        if rest[0] == "function":
            all_refusals.append((Refusal(
                rule="unparseable-command-function",
                reason=("command defines a shell function — blastradius "
                        "refuses to model function definitions. If this is "
                        "intentional, run it yourself outside the agent."),
                raw=command,
            ), command))
            continue

        # ``$CMD args``: the command word itself is an expansion.
        if "$" in rest[0]:
            exp = expand_target(rest[0], seg_env, cwd=run_cwd)
            if isinstance(exp, Refusal):
                all_refusals.append((Refusal(
                    rule="unresolvable-expansion",
                    reason=("the command name is a shell expansion that "
                            "cannot be resolved — blastradius cannot tell "
                            "what will run, so it refuses."),
                    raw=rest[0], resolved=exp.resolved,
                ), rest[0]))
                continue
            rest = exp[0].split() + rest[1:]
            if not rest:
                continue

        # ── cd / pushd: update the cwd of later segments ───────────
        cd_target = _cd_target(rest)
        if cd_target is not None:
            new_cwd, known = _resolve_cwd(cd_target, run_cwd, seg_env)
            run_cwd, cwd_known = new_cwd, known
            # A cd segment carries no destructive action of its own.
            continue
        if _makes_state_unknown(rest):
            cwd_known = False

        seg_display = " ".join(rest)

        # ── Tier 2: Risk warnings (non-filesystem) ─────────────────
        all_warnings.extend(identify_risks(rest))

        # ── Recurse into inner shell command strings ───────────────
        for inner in extract_command_strings(rest):
            sub = check_command(
                inner, cwd=run_cwd, env=seg_env, scope=scope,
                max_glob_breadth=max_glob_breadth, _depth=_depth + 1,
            )
            for ref, raw in sub.refusals:
                all_refusals.append((_wrap_inner(ref, seg_display), raw))
            all_warnings.extend(sub.warnings)
            all_actions.extend(sub.actions)

        # ── Here-string / here-doc fed to a shell is a command string ─
        head = _unwrap_head(rest)
        if head in _SHELL_NAMES:
            for redir in seg_redirs:
                if redir.kind == "herestring" and redir.target:
                    sub = check_command(
                        redir.target, cwd=run_cwd, env=seg_env, scope=scope,
                        max_glob_breadth=max_glob_breadth, _depth=_depth + 1,
                    )
                    for ref, raw in sub.refusals:
                        all_refusals.append((_wrap_inner(ref, seg_display), raw))

        # ── Judge output redirections that truncate a file ─────────
        for redir in seg_redirs:
            ref = _judge_redirect(
                redir, run_cwd, seg_env, scope, cwd_known=cwd_known,
            )
            if ref is not None:
                all_refusals.append((ref, redir.display))

        # ── Tier 1: Filesystem destruction ─────────────────────────
        action = identify_destructive(rest)
        if action is None:
            continue
        all_actions.append(action)

        if action.stdin_targets:
            all_refusals.append((Refusal(
                rule="stdin-targets",
                reason=(
                    f"'{action.command}' runs under xargs/parallel, which "
                    f"appends targets read from stdin — blastradius cannot "
                    f"resolve them, so it refuses (fail closed)."
                ),
                raw=command,
            ), command))

        if not action.targets:
            all_refusals.append((Refusal(
                rule="no-targets",
                reason=(
                    f"destructive command '{action.command}' has no "
                    f"targets — intent is unclear, refusing to proceed"
                ),
                raw=command,
            ), command))
            continue

        # Wrappers such as sudo -D DIR / env -C DIR / systemd-run change
        # where relative targets land: judge against those dirs as well.
        extra_cwds = wrapper_cwds(rest)
        if not cwd_known or None in extra_cwds:
            all_refusals.append((Refusal(
                rule="ambiguous-cwd",
                reason=(
                    f"destructive command '{action.command}' runs after a "
                    f"directory change blastradius could not resolve — the "
                    f"target directory is unknown, so it refuses. Run it "
                    f"yourself outside the agent."
                ),
                raw=command,
            ), command))
            continue

        judge_cwds = [run_cwd] + [
            os.path.realpath(os.path.join(run_cwd, d)) for d in extra_cwds if d
        ]
        seen: set[tuple[str, str | None]] = set()
        for raw_target in action.targets:
            for jcwd in judge_cwds:
                found: list[tuple[Refusal, str]] = []
                _judge_target(
                    raw_target, jcwd, seg_env, scope, max_glob_breadth, found,
                )
                for ref, raw in found:
                    key = (ref.rule, ref.resolved)
                    if key not in seen:
                        seen.add(key)
                        all_refusals.append((ref, raw))

    return CheckResult(
        allowed=len(all_refusals) == 0,
        refusals=all_refusals,
        warnings=all_warnings,
        command=command,
        actions=all_actions,
        segments_checked=len(segments),
    )


# ─────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────


def _judge_target(
    raw_target: str,
    cwd: str,
    env: dict,
    scope: Scope,
    max_glob_breadth: int,
    out: list[tuple[Refusal, str]],
) -> None:
    """Resolve one target and append any refusal to ``out``."""
    result = resolve_target(raw_target, cwd=cwd, env=env)
    if isinstance(result, Refusal):
        out.append((result, raw_target))
        return
    for path in result.paths:
        if is_floor(path, home=env.get("HOME", "")):
            out.append((floor_refusal(path, raw_target), raw_target))
            continue
        if not scope.allows(path):
            out.append((scope.refusal(path, raw_target), raw_target))
            continue
    if result.was_glob:
        breadth_refusal = check_glob_breadth(
            result, max_entries=max_glob_breadth, repo_root=scope.repo_root,
        )
        if breadth_refusal:
            out.append((breadth_refusal, raw_target))


def _judge_redirect(redir, cwd, env, scope, *, cwd_known) -> Refusal | None:
    """Judge an output redirection as a truncate target."""
    if redir.kind != "truncate":
        return None  # append / dup / input / heredoc do not truncate
    target = redir.target
    if target == "":
        return None  # missing target — a shell syntax error, not deletion
    if target in _REDIRECT_EXEMPT or target.startswith("/dev/fd/"):
        return None
    if not cwd_known:
        return Refusal(
            rule="ambiguous-cwd",
            reason=("output redirection follows a directory change "
                    "blastradius could not resolve — refusing."),
            raw=redir.display,
        )
    tmp: list[tuple[Refusal, str]] = []
    _judge_target(target, cwd, env, scope, DEFAULT_MAX_GLOB_BREADTH, tmp)
    if not tmp:
        return None
    ref = tmp[0][0]
    return Refusal(
        rule=ref.rule,
        reason=(f"output redirection {redir.display} truncates a file — "
                f"{ref.reason}"),
        raw=redir.display,
        resolved=ref.resolved,
        variables_checked=ref.variables_checked,
    )


def _wrap_inner(ref: Refusal, seg_display: str) -> Refusal:
    """Re-label a refusal that came from an inner shell command string."""
    return Refusal(
        rule=ref.rule,
        reason=(f"{ref.reason}\n            "
                f"(inside inner command string of: {seg_display})"),
        raw=ref.raw,
        resolved=ref.resolved,
        variables_checked=ref.variables_checked,
    )


def _split_leading_assignments(
    tokens: list[str],
) -> tuple[list[tuple[str, str | None]], list[str]]:
    """Peel leading NAME=VAL / export / unset / read declarations.

    Returns (assignments, rest). Each assignment is (name, value) or
    (name, None) when the value is unknowable (unset / read).
    """
    assigns: list[tuple[str, str | None]] = []
    i = 0
    n = len(tokens)
    while i < n:
        t = tokens[i]
        if _is_assign(t):
            name, _, value = t.partition("=")
            assigns.append((name, value))
            i += 1
            continue
        if t in ("export", "declare", "local", "typeset", "readonly"):
            i += 1
            while i < n and _is_assign(tokens[i]):
                name, _, value = tokens[i].partition("=")
                assigns.append((name, value))
                i += 1
            # `export NAME` (no value) leaves NAME as-is; stop peeling.
            break
        if t in ("unset", "read", "mapfile", "readarray"):
            for name in tokens[i + 1:]:
                if not name.startswith("-") and name.isidentifier():
                    assigns.append((name, None))
            return assigns, []
        break
    return assigns, tokens[i:]


_LEADING_KEYWORDS = {
    "!", "{", "}", "if", "then", "elif", "else", "fi", "while", "until",
    "do", "done",
}
_SHELL_NAMES = {"sh", "bash", "zsh", "dash", "ksh", "mksh", "ash"}


def _strip_leading_keywords(tokens: list[str]) -> list[str]:
    """Drop shell reserved words that precede the real command."""
    i = 0
    while i < len(tokens) and tokens[i] in _LEADING_KEYWORDS:
        i += 1
    return tokens[i:]


def _unwrap_head(tokens: list[str]) -> str:
    from .commands import _strip_path, _unwrap_wrappers
    toks = _unwrap_wrappers(list(tokens))
    return _strip_path(toks[0]) if toks else ""


def _is_assign(tok: str) -> bool:
    if "=" not in tok or tok.startswith("-"):
        return False
    name = tok.split("=", 1)[0]
    return name.isidentifier()


def _cd_target(tokens: list[str]) -> str | None:
    """Return the directory of a leading cd/pushd, '' for bare cd, else None."""
    i = 0
    while i < len(tokens) and tokens[i] in _CD_PREFIXES:
        i += 1
    if i >= len(tokens) or tokens[i] not in ("cd", "pushd"):
        return None
    for a in tokens[i + 1:]:
        if a in ("-L", "-P", "-e", "-@", "-n"):
            continue
        return a
    return ""  # bare cd → home directory


def _makes_state_unknown(tokens: list[str]) -> bool:
    """True for commands that can change cwd/env in ways we cannot track."""
    if not tokens:
        return False
    head = tokens[0]
    base = head.rsplit("/", 1)[-1]
    return base in ("source", ".", "popd", "dirs")


def _resolve_cwd(target: str, cwd: str, env: dict) -> tuple[str, bool]:
    """Resolve a cd target to an absolute path. Returns (cwd, known)."""
    if target in ("", "-", "~") or target.startswith("~"):
        return cwd, False
    exp = expand_target(target, env, cwd=cwd)
    if isinstance(exp, Refusal):
        return cwd, False
    path = exp[0]
    if "$" in path or path == "":
        return cwd, False
    if not os.path.isabs(path):
        path = os.path.join(cwd, path)
    return os.path.realpath(path), True


__all__ = ["check_command", "CheckResult"]
