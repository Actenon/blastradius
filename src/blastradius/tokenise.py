"""Minimal shell tokeniser.

Zero dependencies. Handles quoting (single, double, escaped) and
splits a command string into tokens.

v1 REFUSES any command containing:
  - ; (command separator)
  - && or || (conditional execution)
  - | (pipeline)
  - $(...) or backticks (command substitution)
  - <(...) or >(...) (process substitution)
  - eval
  - Leading ( (subshell)

This is intentionally conservative. The build order says: "start by
refusing anything with ;, && or | and widen carefully from there."

A command that is refused by the tokeniser gets the
``unparseable-command`` rule. The user is told to run it themselves
outside the agent.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .resolve import Refusal


@dataclass(frozen=True)
class TokeniseResult:
    """Result of tokenising a command string."""

    tokens: list[str] | None  # None if refused
    refusal: Refusal | None = None


# Patterns that cause an outright refusal in v1.
_REFUSE_PATTERNS: list[tuple[str, str, str]] = [
    # (regex, rule_suffix, description)
    (r";", "semicolon", "command contains ; (command separator)"),
    (r"&&", "logical-and", "command contains && (conditional execution)"),
    (r"\|\|", "logical-or", "command contains || (conditional execution)"),
    (r"\|", "pipe", "command contains | (pipeline)"),
    (r"\$\(", "command-substitution", "command contains $(...) (command substitution)"),
    (r"`", "backtick", "command contains backticks (command substitution)"),
    (r"<\(", "process-substitution", "command contains <(...) (process substitution)"),
    (r">\(", "process-substitution", "command contains >(...) (process substitution)"),
]

_REFUSE_REGEXES = [(re.compile(p), suffix, desc) for p, suffix, desc in _REFUSE_PATTERNS]


def tokenise(command: str) -> TokeniseResult:
    """Tokenise a command string.

    Returns TokeniseResult with tokens on success, or with a Refusal
    if the command contains constructs we refuse to parse.
    """
    # ── Check for refused patterns ──────────────────────────────────
    for regex, suffix, desc in _REFUSE_REGEXES:
        if regex.search(command):
            return TokeniseResult(
                tokens=None,
                refusal=Refusal(
                    rule=f"unparseable-command-{suffix}",
                    reason=(
                        f"{desc} — blastradius v1 refuses to model this. "
                        f"If this is intentional, run it yourself outside "
                        f"the agent."
                    ),
                    raw=command,
                ),
            )

    # Check for leading subshell.
    stripped = command.strip()
    if stripped.startswith("("):
        return TokeniseResult(
            tokens=None,
            refusal=Refusal(
                rule="unparseable-command-subshell",
                reason=(
                    "command starts with ( (subshell) — blastradius v1 "
                    "refuses to model subshells. If this is intentional, "
                    "run it yourself outside the agent."
                ),
                raw=command,
            ),
        )

    # Check for eval.
    if stripped.startswith("eval ") or stripped == "eval":
        return TokeniseResult(
            tokens=None,
            refusal=Refusal(
                rule="unparseable-command-eval",
                reason=(
                    "command uses eval — blastradius refuses to model "
                    "eval. If this is intentional, run it yourself "
                    "outside the agent."
                ),
                raw=command,
            ),
        )

    # ── Tokenise ────────────────────────────────────────────────────
    tokens = _split_tokens(command)
    return TokeniseResult(tokens=tokens if tokens else None)


def _split_tokens(s: str) -> list[str]:
    """Split a command string into tokens, respecting quotes.

    Handles:
      - Single quotes: literal everything
      - Double quotes: allow $VAR but keep as one token
      - Backslash escapes: space, asterisk, quote, etc.
      - Whitespace separation
    """
    tokens: list[str] = []
    current: list[str] = []
    i = 0
    in_single = False
    in_double = False
    has_content = False

    while i < len(s):
        c = s[i]

        if in_single:
            if c == "'":
                in_single = False
            else:
                current.append(c)
            i += 1
            continue

        if in_double:
            if c == '"':
                in_double = False
            elif c == "\\" and i + 1 < len(s):
                # In double quotes, backslash escapes only $ ` " \ newline
                next_c = s[i + 1]
                if next_c in ("$", "`", '"', "\\", "\n"):
                    current.append(next_c)
                    i += 2
                    continue
                else:
                    current.append(c)
                    i += 1
                    continue
            else:
                current.append(c)
            i += 1
            continue

        # Not in any quotes.
        if c == "'":
            in_single = True
            has_content = True
            i += 1
            continue

        if c == '"':
            in_double = True
            has_content = True
            i += 1
            continue

        if c == "\\" and i + 1 < len(s):
            # Backslash escape outside quotes: take next char literally.
            current.append(s[i + 1])
            has_content = True
            i += 2
            continue

        if c in (" ", "\t", "\n"):
            if has_content:
                tokens.append("".join(current))
                current = []
                has_content = False
            i += 1
            continue

        current.append(c)
        has_content = True
        i += 1

    if has_content:
        tokens.append("".join(current))

    return tokens


__all__ = ["tokenise", "TokeniseResult"]
