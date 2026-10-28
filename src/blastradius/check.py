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
import shlex
from collections.abc import Sequence
from dataclasses import dataclass, field

from .commands import (
    DestructiveAction,
    RiskWarning,
    _strip_path,
    identify_destructive,
    identify_risks,
)
from .resolve import Refusal, Resolved, resolve_target
from .rules import (
    DEFAULT_MAX_GLOB_BREADTH,
    Scope,
    check_glob_breadth,
    floor_refusal,
    is_floor,
    load_scope,
)
from .tokenise import tokenise

_NESTED_SHELLS: set[str] = {"sh", "bash", "zsh", "dash", "ksh", "ash", "csh", "tcsh"}


def _detect_unmodellable_wrapper_or_shell(
    seg_tokens: list[str], raw_command: str
) -> tuple[Refusal | None, str | None]:
    """Check for working-directory changing wrappers (`env -C`) or nested `sh -c` scripts.

    Returns (refusal, nested_shell_script).
    """
    i = 0
    while i < len(seg_tokens):
        tok = seg_tokens[i]
        cmd = _strip_path(tok)
        if cmd == "env":
            j = i + 1
            while j < len(seg_tokens):
                arg = seg_tokens[j]
                if arg == "--":
                    j += 1
                    break
                if arg in ("-C", "--chdir", "-S", "--split-string") or arg.startswith(
                    ("-C", "--chdir=", "-S", "--split-string=")
                ):
                    return (
                        Refusal(
                            rule="unparseable-command-chdir",
                            reason=(
                                f"command uses 'env {arg}' which changes working directory "
                                "or splits arguments at runtime — blastradius refuses to "
                                "model runtime working-directory mutations."
                            ),
                            raw=raw_command,
                        ),
                        None,
                    )
                if arg in ("-u", "--unset") and j + 1 < len(seg_tokens):
                    j += 2
                    continue
                if arg.startswith("-") and arg != "-":
                    j += 1
                    continue
                if "=" in arg and not arg.startswith("-"):
                    j += 1
                    continue
                break
            i = j
            continue

        if cmd in _NESTED_SHELLS:
            rest = seg_tokens[i + 1 :]
            for idx, arg in enumerate(rest):
                if arg == "--":
                    break
                if arg == "-c" or (arg.startswith("-") and not arg.startswith("--") and "c" in arg[1:]):
                    if idx + 1 < len(rest):
                        return None, rest[idx + 1]
                    return (
                        Refusal(
                            rule="unparseable-command-subshell",
                            reason=f"nested shell '{cmd} {arg}' has no command string — refusing.",
                            raw=raw_command,
                        ),
                        None,
                    )
            break

        if cmd in ("sudo", "doas", "command", "exec", "nice", "nohup", "setsid", "ionice", "stdbuf", "time", "timeout", "chrt", "taskset", "eatmydata", "proxychains", "proxychains4", "catchsegv", "busybox", "nocache", "xargs"):
            i += 1
            continue
        break
    return None, None


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


def check_command(
    command: str,
    *,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
    scope: Scope | None = None,
    max_glob_breadth: int = DEFAULT_MAX_GLOB_BREADTH,
) -> CheckResult:
    """Check a command string. Returns CheckResult.

    TIER 1: If any segment is a filesystem-destruction command with a
    target that is floor or out-of-scope, the command is BLOCKED.

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

    # ── Step 1: Tokenise and refuse unquoted compound commands ──────
    tok_result = tokenise(command)
    if tok_result.refusal:
        return CheckResult(
            allowed=False,
            refusals=[(tok_result.refusal, command)],
            command=command,
        )

    if tok_result.separators:
        sep_list = ", ".join(repr(s) for s in tok_result.separators)
        return CheckResult(
            allowed=False,
            refusals=[
                (
                    Refusal(
                        rule="unparseable-command-compound",
                        reason=(
                            f"command contains unquoted compound operator ({sep_list}) — "
                            "blastradius conservatively refuses compound shell commands in "
                            "raw-shell mode because earlier segments (such as 'cd') can "
                            "change working directory or shell state before destructive "
                            "commands run. Run the commands separately."
                        ),
                        raw=command,
                    ),
                    command,
                )
            ],
            command=command,
        )

    segments = tok_result.segments or []
    return _check_segments(
        segments,
        raw_command=command,
        cwd=cwd,
        env=env,
        scope=scope,
        max_glob_breadth=max_glob_breadth,
    )


def check_argv(
    argv: Sequence[str],
    *,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
    scope: Scope | None = None,
    max_glob_breadth: int = DEFAULT_MAX_GLOB_BREADTH,
) -> CheckResult:
    """Check an execvp argument vector directly (wrapper mode).

    Unlike ``check_command`` (which parses a raw shell string), ``check_argv``
    evaluates the exact ``argv`` list that ``os.execvp`` will execute without
    joining arguments with spaces or splitting on shell separators inside
    individual argv items. If ``argv`` invokes a nested shell (`sh -c ...`,
    `bash -c ...`), the inner script is validated with ``check_command``.
    """
    if cwd is None:
        cwd = os.getcwd()
    if env is None:
        env = dict(os.environ)
    if scope is None:
        scope = load_scope(cwd)

    tokens = list(argv)
    display_cmd = shlex.join(tokens) if tokens else ""
    if not tokens:
        return CheckResult(allowed=True, command=display_cmd, segments_checked=0)

    return _check_segments(
        [tokens],
        raw_command=display_cmd,
        cwd=cwd,
        env=env,
        scope=scope,
        max_glob_breadth=max_glob_breadth,
    )


def _check_segments(
    segments: list[list[str]],
    *,
    raw_command: str,
    cwd: str,
    env: dict[str, str],
    scope: Scope,
    max_glob_breadth: int,
) -> CheckResult:
    # ── Step 2: Check each segment ──────────────────────────────────
    all_refusals: list[tuple[Refusal, str]] = []
    all_warnings: list[RiskWarning] = []
    all_actions: list[DestructiveAction] = []

    for seg_tokens in segments:
        wrapper_refusal, nested_script = _detect_unmodellable_wrapper_or_shell(
            seg_tokens, raw_command
        )
        if wrapper_refusal is not None:
            all_refusals.append((wrapper_refusal, raw_command))
            continue
        if nested_script is not None:
            nested_res = check_command(
                nested_script,
                cwd=cwd,
                env=env,
                scope=scope,
                max_glob_breadth=max_glob_breadth,
            )
            all_warnings.extend(nested_res.warnings)
            all_actions.extend(nested_res.actions)
            all_refusals.extend(nested_res.refusals)
            continue

        # ── Tier 2: Risk warnings (non-filesystem) ─────────────────
        seg_warnings = identify_risks(seg_tokens)
        all_warnings.extend(seg_warnings)

        # ── Tier 1: Filesystem destruction ─────────────────────────
        action = identify_destructive(seg_tokens)
        if action is None:
            continue

        all_actions.append(action)

        # No targets → refuse.
        if not action.targets:
            all_refusals.append((
                Refusal(
                    rule="no-targets",
                    reason=(
                        f"destructive command '{action.command}' has no "
                        f"targets — intent is unclear, refusing to proceed"
                    ),
                    raw=raw_command,
                ),
                raw_command,
            ))
            continue

        # Check each target.
        for raw_target in action.targets:
            result = resolve_target(raw_target, cwd=cwd, env=env)

            if isinstance(result, Refusal):
                all_refusals.append((result, raw_target))
                continue

            for path in result.paths:
                if is_floor(path, home=env.get("HOME", "")):
                    all_refusals.append((floor_refusal(path, raw_target), raw_target))
                    continue
                if not scope.allows(path):
                    all_refusals.append((scope.refusal(path, raw_target), raw_target))
                    continue

            if result.was_glob:
                breadth_refusal = check_glob_breadth(
                    result,
                    max_entries=max_glob_breadth,
                    repo_root=scope.repo_root,
                )
                if breadth_refusal:
                    all_refusals.append((breadth_refusal, raw_target))

    return CheckResult(
        allowed=len(all_refusals) == 0,
        refusals=all_refusals,
        warnings=all_warnings,
        command=raw_command,
        actions=all_actions,
        segments_checked=len(segments),
    )


__all__ = ["CheckResult", "check_argv", "check_command"]
