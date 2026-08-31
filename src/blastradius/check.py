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

from .commands import DestructiveAction, RiskWarning, identify_destructive, identify_risks
from .resolve import Refusal, Resolved, resolve_target
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

    # ── Step 1: Tokenise (splits on &&, ||, ;, |) ──────────────────
    tok_result = tokenise(command)
    if tok_result.refusal:
        return CheckResult(
            allowed=False,
            refusals=[(tok_result.refusal, command)],
            command=command,
        )

    segments = tok_result.segments or []

    # ── Step 2: Check each segment ──────────────────────────────────
    all_refusals: list[tuple[Refusal, str]] = []
    all_warnings: list[RiskWarning] = []
    all_actions: list[DestructiveAction] = []

    for seg_tokens in segments:
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
                    raw=command,
                ),
                command,
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
        command=command,
        actions=all_actions,
        segments_checked=len(segments),
    )


__all__ = ["check_command", "CheckResult"]
