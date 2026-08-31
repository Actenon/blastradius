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
  - Newlines (treated as command separators — same threat as ;)

CRITICAL: the refusal check is quote-aware. A ``;`` inside single
or double quotes is a literal character, not a command separator.
The tokeniser first walks the string respecting quotes, and only
flags metacharacters that appear in an unquoted context. This
prevents false positives on filenames containing ``;``, ``|``, etc.

A command that is refused by the tokeniser gets the
``unparseable-command`` rule. The user is told to run it themselves
outside the agent.
"""

from __future__ import annotations

from dataclasses import dataclass

from .resolve import Refusal


@dataclass(frozen=True)
class TokeniseResult:
    """Result of tokenising a command string."""

    tokens: list[str] | None  # None if refused
    refusal: Refusal | None = None


def tokenise(command: str) -> TokeniseResult:
    """Tokenise a command string.

    Returns TokeniseResult with tokens on success, or with a Refusal
    if the command contains constructs we refuse to parse.

    The refusal check is quote-aware: metacharacters inside single or
    double quotes are treated as literals and do not trigger a refusal.
    """
    # ── Check for leading subshell ──────────────────────────────────
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

    # ── Check for eval ──────────────────────────────────────────────
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

    # ── Quote-aware scan for refused metacharacters ─────────────────
    # We walk the string character by character, tracking quote state.
    # Only unquoted metacharacters trigger a refusal. This prevents
    # false positives on filenames like "foo;bar" or "a|b".
    refusal = _scan_for_metacharacters(command)
    if refusal:
        return TokeniseResult(tokens=None, refusal=refusal)

    # ── Tokenise ────────────────────────────────────────────────────
    tokens = _split_tokens(command)
    return TokeniseResult(tokens=tokens if tokens else None)


def _scan_for_metacharacters(s: str) -> Refusal | None:
    """Walk the string respecting quotes, looking for refused patterns.

    Returns a Refusal if an unquoted metacharacter is found, else None.

    This is the quote-aware replacement for the v0 regex approach,
    which fired on quoted metacharacters (false positives on
    filenames like "foo;bar").
    """
    i = 0
    in_single = False
    in_double = False

    while i < len(s):
        c = s[i]

        if in_single:
            # Everything is literal inside single quotes until the
            # closing single quote.
            if c == "'":
                in_single = False
            i += 1
            continue

        if in_double:
            # Inside double quotes, backslash escapes only $ ` " \ newline.
            if c == "\\" and i + 1 < len(s):
                next_c = s[i + 1]
                if next_c in ("$", "`", '"', "\\", "\n"):
                    i += 2
                    continue
                # Otherwise backslash is literal — just advance.
                i += 1
                continue
            if c == '"':
                in_double = False
            i += 1
            continue

        # Unquoted context.
        if c == "'":
            in_single = True
            i += 1
            continue

        if c == '"':
            in_double = True
            i += 1
            continue

        if c == "\\" and i + 1 < len(s):
            # Backslash escape: next char is literal. Skip both.
            i += 2
            continue

        # ── Check for refused metacharacters (unquoted only) ────────

        # Newline — treated as a command separator (same threat as ;).
        # This closes the "echo foo\nrm -rf $HOME" bypass.
        if c == "\n":
            return Refusal(
                rule="unparseable-command-newline",
                reason=(
                    "command contains a newline — blastradius treats "
                    "newlines as command separators (same threat as ;). "
                    "If this is intentional, run the commands separately "
                    "outside the agent."
                ),
                raw=s,
            )

        # Semicolon.
        if c == ";":
            return Refusal(
                rule="unparseable-command-semicolon",
                reason=(
                    "command contains ; (command separator) in an "
                    "unquoted context — blastradius v1 refuses to model "
                    "this. If this is intentional, run it yourself outside "
                    "the agent."
                ),
                raw=s,
            )

        # && or ||.
        if c == "&" and i + 1 < len(s) and s[i + 1] == "&":
            return Refusal(
                rule="unparseable-command-logical-and",
                reason=(
                    "command contains && (conditional execution) — "
                    "blastradius v1 refuses to model this. If this is "
                    "intentional, run it yourself outside the agent."
                ),
                raw=s,
            )
        if c == "|" and i + 1 < len(s) and s[i + 1] == "|":
            return Refusal(
                rule="unparseable-command-logical-or",
                reason=(
                    "command contains || (conditional execution) — "
                    "blastradius v1 refuses to model this. If this is "
                    "intentional, run it yourself outside the agent."
                ),
                raw=s,
            )

        # Single | (pipeline).
        if c == "|":
            return Refusal(
                rule="unparseable-command-pipe",
                reason=(
                    "command contains | (pipeline) in an unquoted "
                    "context — blastradius v1 refuses to model this. "
                    "If this is intentional, run it yourself outside "
                    "the agent."
                ),
                raw=s,
            )

        # $(...) command substitution.
        if c == "$" and i + 1 < len(s) and s[i + 1] == "(":
            return Refusal(
                rule="unparseable-command-command-substitution",
                reason=(
                    "command contains $(...) (command substitution) — "
                    "blastradius v1 refuses to model this. If this is "
                    "intentional, run it yourself outside the agent."
                ),
                raw=s,
            )

        # Backtick command substitution.
        if c == "`":
            return Refusal(
                rule="unparseable-command-backtick",
                reason=(
                    "command contains backticks (command substitution) — "
                    "blastradius v1 refuses to model this. If this is "
                    "intentional, run it yourself outside the agent."
                ),
                raw=s,
            )

        # <(...) or >(...) process substitution.
        if c == "<" and i + 1 < len(s) and s[i + 1] == "(":
            return Refusal(
                rule="unparseable-command-process-substitution",
                reason=(
                    "command contains <(...) (process substitution) — "
                    "blastradius v1 refuses to model this. If this is "
                    "intentional, run it yourself outside the agent."
                ),
                raw=s,
            )
        if c == ">" and i + 1 < len(s) and s[i + 1] == "(":
            return Refusal(
                rule="unparseable-command-process-substitution",
                reason=(
                    "command contains >(...) (process substitution) — "
                    "blastradius v1 refuses to model this. If this is "
                    "intentional, run it yourself outside the agent."
                ),
                raw=s,
            )

        i += 1

    return None


def _split_tokens(s: str) -> list[str]:
    """Split a command string into tokens, respecting quotes.

    Handles:
      - Single quotes: literal everything
      - Double quotes: allow $VAR but keep as one token
      - Backslash escapes: space, asterisk, quote, etc.
      - Backslash-newline: line continuation (removed)
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
                # In double quotes, backslash escapes only $ ` " \ newline.
                next_c = s[i + 1]
                if next_c in ("$", "`", '"', "\\", "\n"):
                    if next_c == "\n":
                        # Line continuation inside double quotes: skip.
                        i += 2
                        continue
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
            next_c = s[i + 1]
            if next_c == "\n":
                # Line continuation: backslash-newline is removed.
                i += 2
                continue
            # Backslash escape: take next char literally.
            current.append(next_c)
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
