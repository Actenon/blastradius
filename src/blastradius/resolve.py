"""Resolve a shell target argument to its actual absolute path.

This is the heart of blastradius. Everything else is packaging.

The resolution pipeline, in order:

  1. Variable expansion against the real environment.
     If any variable expands to empty → REFUSE (empty-variable-expansion).
     This is the Guillemot bug: ``rm -rf "$CLEANUP_DIR"`` where
     CLEANUP_DIR is unset expands to ``rm -rf ""`` which is CWD or root.

  2. Tilde handling. A bare or leading ``~`` is refused (tilde-ambiguous).
     ``~`` is uniquely dangerous because it means both "home directory"
     and "a file literally called tilde." Require an explicit absolute path.

  3. Glob expansion against the real filesystem, from the correct CWD.
     No matches → REFUSE (glob-no-match). Fail closed.

  4. Canonicalisation. ``os.path.realpath`` resolves ``..`` and symlinks.
     A target inside scope that symlinks outside it is outside it.

Every refusal names a rule ID and the specific variable or pattern that
caused it.
"""

from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass, field
from pathlib import Path


# ─────────────────────────────────────────────────────────────────────
# Result types
# ─────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Refusal:
    """A resolution refusal — the target could not be safely resolved."""

    rule: str
    reason: str
    raw: str
    resolved: str | None = None
    variables_checked: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Resolved:
    """A successfully resolved target — one or more absolute real paths."""

    raw: str
    paths: list[str]
    variables_used: list[str] = field(default_factory=list)
    was_glob: bool = False


ResolveResult = Resolved | Refusal


# ─────────────────────────────────────────────────────────────────────
# Variable expansion
# ─────────────────────────────────────────────────────────────────────

# Match $VAR and ${VAR} patterns. Variable names are [A-Za-z_][A-Za-z0-9_]*.
_VAR_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)")


def _find_variables(s: str) -> list[str]:
    """Return all variable names referenced in the string."""
    names = []
    for m in _VAR_PATTERN.finditer(s):
        names.append(m.group(1) or m.group(2))
    return names


def _expand_variables(s: str, env: dict[str, str]) -> tuple[str, list[str], list[str]]:
    """Expand $VAR and ${VAR} against env.

    Returns (expanded_string, variables_used, unset_variables).
    Unset variables are expanded to empty string (matching bash default),
    but the caller should check the unset list and refuse.
    """
    variables_used = []
    unset = []

    def replacer(m: re.Match) -> str:
        name = m.group(1) or m.group(2)
        variables_used.append(name)
        val = env.get(name, "")
        if val == "":
            unset.append(name)
        return val

    expanded = _VAR_PATTERN.sub(replacer, s)
    return expanded, variables_used, unset


# ─────────────────────────────────────────────────────────────────────
# Glob detection
# ─────────────────────────────────────────────────────────────────────


def _has_glob_chars(s: str) -> bool:
    """True if the string contains shell glob characters."""
    return any(c in s for c in ("*", "?", "["))


# ─────────────────────────────────────────────────────────────────────
# Core resolver
# ─────────────────────────────────────────────────────────────────────


def resolve_target(
    raw: str,
    *,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
) -> ResolveResult:
    """Resolve a single target argument to its absolute real path(s).

    Args:
        raw: The raw argument string as it appears in the command.
        cwd: The working directory to resolve relative paths from.
            Defaults to os.getcwd().
        env: The environment for variable expansion. Defaults to os.environ.

    Returns:
        Resolved on success (with one or more real paths).
        Refusal on failure (with a rule ID and reason).
    """
    if cwd is None:
        cwd = os.getcwd()
    if env is None:
        env = dict(os.environ)

    # ── Step 1: Variable expansion ──────────────────────────────────
    expanded, variables_used, unset = _expand_variables(raw, env)

    if unset:
        # The Guillemot failure: a variable expanded to empty.
        # Build a clear reason listing every unset variable.
        parts = []
        for var in unset:
            parts.append(f"{var} is unset — expansion produced an empty string")
        reason = "\n            ".join(parts)

        # Try to show what it would have resolved to, for context.
        # After empty expansion, the path might be empty, relative, or
        # start with / (if the var was a prefix like $VAR/foo).
        tentative = expanded.strip()
        if tentative == "":
            resolved_hint = f"{cwd} (current working directory — empty expansion)"
        elif tentative.startswith("/"):
            resolved_hint = tentative
        else:
            resolved_hint = os.path.join(cwd, tentative)

        return Refusal(
            rule="empty-variable-expansion",
            reason=reason,
            raw=raw,
            resolved=resolved_hint,
            variables_checked=unset,
        )

    # ── Step 2: Tilde handling ──────────────────────────────────────
    # Refuse any target that starts with ~. The ~ is ambiguous: it
    # could be $HOME or a file literally named ~. Require an explicit
    # absolute path.
    if expanded.startswith("~"):
        return Refusal(
            rule="tilde-ambiguous",
            reason=(
                "target starts with ~ — tilde is ambiguous (could be "
                "$HOME or a file literally named ~). Use an explicit "
                "absolute path."
            ),
            raw=raw,
            resolved=expanded,
            variables_checked=variables_used,
        )

    # ── Step 3: Empty target after expansion ────────────────────────
    if expanded == "":
        return Refusal(
            rule="empty-target",
            reason="target is an empty string after expansion — would resolve to CWD",
            raw=raw,
            resolved=cwd,
            variables_checked=variables_used,
        )

    # ── Step 4: Glob expansion or direct resolution ─────────────────
    if _has_glob_chars(expanded):
        return _resolve_glob(expanded, cwd=cwd, raw=raw, variables_used=variables_used)
    else:
        return _resolve_single(expanded, cwd=cwd, raw=raw, variables_used=variables_used)


def _resolve_single(
    path: str,
    *,
    cwd: str,
    raw: str,
    variables_used: list[str],
) -> ResolveResult:
    """Resolve a non-glob path to its absolute real path."""
    if not os.path.isabs(path):
        path = os.path.join(cwd, path)
    real = os.path.realpath(path)
    return Resolved(
        raw=raw,
        paths=[real],
        variables_used=variables_used,
        was_glob=False,
    )


def _resolve_glob(
    pattern: str,
    *,
    cwd: str,
    raw: str,
    variables_used: list[str],
) -> ResolveResult:
    """Expand a glob pattern against the real filesystem."""
    # Build the full pattern relative to cwd if needed.
    if not os.path.isabs(pattern):
        pattern = os.path.join(cwd, pattern)

    # Use glob.glob with recursive=True to handle ** patterns.
    # Python 3.10+ supports root_dir parameter.
    import glob

    matches = glob.glob(pattern, recursive=True)

    if not matches:
        return Refusal(
            rule="glob-no-match",
            reason=f"glob pattern {pattern!r} matched no files — refusing to guess intent",
            raw=raw,
            resolved=pattern,
            variables_checked=variables_used,
        )

    # Canonicalise each match.
    real_paths = [os.path.realpath(m) for m in matches]

    return Resolved(
        raw=raw,
        paths=real_paths,
        variables_used=variables_used,
        was_glob=True,
    )


# ─────────────────────────────────────────────────────────────────────
# Batch resolver — resolve multiple targets at once
# ─────────────────────────────────────────────────────────────────────


def resolve_targets(
    raws: list[str],
    *,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
) -> list[ResolveResult]:
    """Resolve multiple target arguments. Returns one result per target."""
    return [resolve_target(r, cwd=cwd, env=env) for r in raws]


__all__ = [
    "Refusal",
    "Resolved",
    "ResolveResult",
    "resolve_target",
    "resolve_targets",
]
