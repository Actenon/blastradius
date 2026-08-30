"""Core check function — the decision pipeline.

Given a command string, run it through:
  1. Tokeniser (refuse unparseable)
  2. Command identifier (is it destructive?)
  3. Target resolver (variables → tilde → globs → canonical)
  4. Floor rules (unoverridable)
  5. Scope check
  6. Glob breadth

Returns either a list of refusals (block) or an empty list (allow).
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from .commands import DestructiveAction, identify_destructive
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
    refusals: list[tuple[Refusal, str]]  # (refusal, target_raw)
    command: str
    action: DestructiveAction | None = None

    @property
    def first_refusal(self) -> Refusal | None:
        return self.refusals[0][0] if self.refusals else None


def check_command(
    command: str,
    *,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
    scope: Scope | None = None,
    max_glob_breadth: int = DEFAULT_MAX_GLOB_BREADTH,
) -> CheckResult:
    """Check a command string. Returns CheckResult.

    If the command is not destructive, returns allowed=True.
    If the command is destructive and all targets pass, returns allowed=True.
    If any target is refused, returns allowed=False with the refusals.
    """
    if cwd is None:
        cwd = os.getcwd()
    if env is None:
        env = dict(os.environ)
    if scope is None:
        scope = load_scope(cwd)

    # ── Step 1: Tokenise ────────────────────────────────────────────
    tok_result = tokenise(command)
    if tok_result.refusal:
        return CheckResult(
            allowed=False,
            refusals=[(tok_result.refusal, command)],
            command=command,
        )

    tokens = tok_result.tokens or []

    # ── Step 2: Identify destructive command ────────────────────────
    action = identify_destructive(tokens)
    if action is None:
        # Not destructive — allow.
        return CheckResult(allowed=True, refusals=[], command=command)

    # ── Step 3-6: Resolve and check each target ─────────────────────
    refusals: list[tuple[Refusal, str]] = []

    for raw_target in action.targets:
        result = resolve_target(raw_target, cwd=cwd, env=env)

        if isinstance(result, Refusal):
            refusals.append((result, raw_target))
            continue

        # Resolved — check each path.
        for path in result.paths:
            # Floor check (unoverridable).
            if is_floor(path, home=env.get("HOME", "")):
                refusals.append((floor_refusal(path, raw_target), raw_target))
                continue

            # Scope check.
            if not scope.allows(path):
                refusals.append((scope.refusal(path, raw_target), raw_target))
                continue

        # Glob breadth check — only for glob-expanded targets.
        if result.was_glob:
            breadth_refusal = check_glob_breadth(
                result,
                max_entries=max_glob_breadth,
                repo_root=scope.repo_root,
            )
            if breadth_refusal:
                refusals.append((breadth_refusal, raw_target))

    return CheckResult(
        allowed=len(refusals) == 0,
        refusals=refusals,
        command=command,
        action=action,
    )


__all__ = ["check_command", "CheckResult"]
