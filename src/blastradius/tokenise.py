"""Minimal shell tokeniser with compound-command splitting.

v0.3.0: Instead of refusing compound commands (``&&``, ``||``, ``;``,
``|``), the tokeniser now SPLITS them into segments and the checker
evaluates each segment independently. This removes the #1 false
positive from the evaluation (``python -m build && twine upload``
was refused) while still checking every segment for destructive
operations.

Still REFUSES (cannot safely model):
  - $(...) or backticks (command substitution)
  - <(...) or >(...) (process substitution)
  - eval
  - Leading ( (subshell)
  - Newlines (treated as command separators — same threat as ;)

The refusal check is quote-aware: metacharacters inside single or
double quotes are literals and do not trigger a refusal.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .resolve import Refusal


@dataclass(frozen=True)
class TokeniseResult:
    """Result of tokenising a command string."""

    # A list of command segments. Each segment is a token list.
    # For a simple command "rm -rf /tmp/foo", segments = [["rm", "-rf", "/tmp/foo"]].
    # For "cd /tmp && rm foo", segments = [["cd", "/tmp"], ["rm", "foo"]].
    segments: list[list[str]] | None  # None if refused
    refusal: Refusal | None = None
    # The separators between segments (for display): ["&&"], [";"], etc.
    separators: list[str] = field(default_factory=list)


# Separators we split on (instead of refusing).
_SPLIT_SEPARATORS = {"&&", "||", ";", "|"}


def tokenise(command: str) -> TokeniseResult:
    """Tokenise a command string, splitting on compound operators.

    Returns TokeniseResult with segments on success, or with a Refusal
    if the command contains constructs we still refuse to model.

    The refusal check is quote-aware: metacharacters inside single or
    double quotes are treated as literals and do not trigger a refusal.
    """
    # ── Check for leading subshell ──────────────────────────────────
    stripped = command.strip()
    if stripped.startswith("("):
        return TokeniseResult(
            segments=None,
            refusal=Refusal(
                rule="unparseable-command-subshell",
                reason=(
                    "command starts with ( (subshell) — blastradius "
                    "refuses to model subshells. If this is intentional, "
                    "run it yourself outside the agent."
                ),
                raw=command,
            ),
        )

    # ── Check for eval ──────────────────────────────────────────────
    if stripped.startswith("eval ") or stripped == "eval":
        return TokeniseResult(
            segments=None,
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
    # Still refuse: newlines, $(...), backticks, <(...), >(...)
    # But NO LONGER refuse: &&, ||, ;, | — we split on those instead.
    refusal = _scan_for_metacharacters(command)
    if refusal:
        return TokeniseResult(segments=None, refusal=refusal)

    # ── Split into segments on &&, ||, ;, | ─────────────────────────
    segments, separators = _split_into_segments(command)
    if not segments:
        return TokeniseResult(segments=None)
    return TokeniseResult(segments=segments, separators=separators)


def _scan_for_metacharacters(s: str) -> Refusal | None:
    """Walk the string respecting quotes, looking for refused patterns.

    Still refuses: newlines, $(...), backticks, <(...), >(...)
    No longer refuses: &&, ||, ;, | (we split on those instead).
    """
    i = 0
    in_single = False
    in_double = False

    while i < len(s):
        c = s[i]

        if in_single:
            if c == "'":
                in_single = False
            i += 1
            continue

        if in_double:
            if c == "\\" and i + 1 < len(s):
                next_c = s[i + 1]
                if next_c in ("$", "`", '"', "\\", "\n"):
                    i += 2
                    continue
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
            i += 2
            continue

        # Newline — still refused (command separator bypass).
        if c == "\n":
            return Refusal(
                rule="unparseable-command-newline",
                reason=(
                    "command contains a newline — blastradius treats "
                    "newlines as command separators. If this is "
                    "intentional, run the commands separately outside "
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
                    "blastradius refuses to model this. If this is "
                    "intentional, run it yourself outside the agent."
                ),
                raw=s,
            )

        # Backtick command substitution.
        if c == "`":
            return Refusal(
                rule="unparseable-command-backtick",
                reason=(
                    "command contains backticks (command substitution) "
                    "— blastradius refuses to model this. If this is "
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
                    "blastradius refuses to model this. If this is "
                    "intentional, run it yourself outside the agent."
                ),
                raw=s,
            )
        if c == ">" and i + 1 < len(s) and s[i + 1] == "(":
            return Refusal(
                rule="unparseable-command-process-substitution",
                reason=(
                    "command contains >(...) (process substitution) — "
                    "blastradius refuses to model this. If this is "
                    "intentional, run it yourself outside the agent."
                ),
                raw=s,
            )

        i += 1

    return None


def _split_into_segments(s: str) -> tuple[list[list[str]], list[str]]:
    """Split a command string on &&, ||, ;, | (respecting quotes).

    Returns (segments, separators) where segments is a list of token
    lists and separators is the list of operators between them.

    Example:
      "cd /tmp && rm foo" → ([["cd", "/tmp"], ["rm", "foo"]], ["&&"])
      "rm -rf /tmp/foo"   → ([["rm", "-rf", "/tmp/foo"]], [])
    """
    # First, find the split points (quote-aware).
    split_points: list[tuple[int, int, str]] = []  # (start, end, separator)
    i = 0
    in_single = False
    in_double = False

    while i < len(s):
        c = s[i]

        if in_single:
            if c == "'":
                in_single = False
            i += 1
            continue

        if in_double:
            if c == "\\" and i + 1 < len(s):
                next_c = s[i + 1]
                if next_c in ("$", "`", '"', "\\", "\n"):
                    i += 2
                    continue
                i += 1
                continue
            if c == '"':
                in_double = False
            i += 1
            continue

        if c == "'":
            in_single = True
            i += 1
            continue

        if c == '"':
            in_double = True
            i += 1
            continue

        if c == "\\" and i + 1 < len(s):
            i += 2
            continue

        # Check for two-char operators: &&, ||
        if i + 1 < len(s):
            two = s[i:i + 2]
            if two in ("&&", "||"):
                split_points.append((i, i + 2, two))
                i += 2
                continue

        # Check for single-char operators: ;, |
        if c in (";", "|"):
            split_points.append((i, i + 1, c))
            i += 1
            continue

        i += 1

    if not split_points:
        # No separators — single command.
        tokens = _tokenise_segment(s)
        return ([tokens] if tokens else [], [])

    # Split the string at each split point and tokenise each segment.
    segments: list[list[str]] = []
    separators: list[str] = []
    last_end = 0

    for start, end, sep in split_points:
        segment_str = s[last_end:start].strip()
        if segment_str:
            tokens = _tokenise_segment(segment_str)
            if tokens:
                segments.append(tokens)
        separators.append(sep)
        last_end = end

    # Last segment after the final separator.
    final_segment = s[last_end:].strip()
    if final_segment:
        tokens = _tokenise_segment(final_segment)
        if tokens:
            segments.append(tokens)

    return segments, separators


def _tokenise_segment(s: str) -> list[str]:
    """Tokenise a single command segment (no separators).

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
                next_c = s[i + 1]
                if next_c in ("$", "`", '"', "\\", "\n"):
                    if next_c == "\n":
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
                i += 2
                continue
            current.append(next_c)
            has_content = True
            i += 2
            continue

        if c in (" ", "\t"):
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
