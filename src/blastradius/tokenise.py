"""Quote-aware shell lexer: split a command line into simple commands.

v0.5.0: one lexer is the single source of truth for quote state, so the
refusal scan, the segment split and the word split can never disagree
about what is quoted (a disagreement is a bypass: ``echo $'\\'' ; rm ...``).

Each simple command (segment) yields:
  - its argv words, after quote removal and brace expansion, with
    redirections REMOVED (so ``2>/dev/null`` is never an rm target);
  - its redirections (``>``, ``>|``, ``>>``, ``&>``, ``N>``, ``>&N``, ``<``,
    ``<<<`` ...), each with the dequoted target word;
  - the separator that precedes it (``&&``, ``||``, ``;``, ``|``, ``|&``,
    ``&``), so the checker can model control flow (``cd / && rm -rf etc``).

Still REFUSES (cannot safely model):
  - $(...) or backticks (command substitution), also inside double quotes
  - <(...) or >(...) (process substitution)
  - eval (a leading eval here; eval anywhere else in commands.py)
  - ( or ) anywhere unquoted (subshell, function definition, case pattern)
  - Newlines (treated as command separators — same threat as ;)
  - Unterminated quotes, and ${...} containing quotes or nested expansions
  - Brace expansions that produce more than MAX_BRACE_WORDS words

Metacharacters inside single or double quotes are literals.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .resolve import Refusal

MAX_BRACE_WORDS = 1024

_SEPARATOR_CHARS = ";&|"
_BLANKS = " \t"


@dataclass(frozen=True)
class Redirection:
    """One redirection of a simple command."""

    op: str  # '>', '>|', '>>', '&>', '&>>', '>&', '<', '<&', '<>', '<<', '<<<'
    target: str  # dequoted target word ('' if missing)
    fd: str | None = None  # explicit fd prefix, e.g. '2' in 2>file
    # truncate | append | dup | input | readwrite | herestring | heredoc
    kind: str = "truncate"

    @property
    def display(self) -> str:
        return f"{self.fd or ''}{self.op}{self.target}"


@dataclass(frozen=True)
class TokeniseResult:
    """Result of tokenising a command string."""

    # One argv list per simple command. None if refused.
    segments: list[list[str]] | None
    refusal: Refusal | None = None
    # Every separator encountered, in order: ["&&"], [";"], ["&"], ...
    separators: list[str] = field(default_factory=list)
    # Redirections of each segment (aligned with segments).
    redirections: list[list[Redirection]] = field(default_factory=list)
    # The separator immediately preceding each segment (None for the first).
    segment_separators: list[str | None] = field(default_factory=list)


class _Refuse(Exception):
    def __init__(self, rule: str, reason: str) -> None:
        super().__init__(rule)
        self.rule = rule
        self.reason = reason


def _refuse_cmdsubst() -> _Refuse:
    return _Refuse(
        "unparseable-command-command-substitution",
        "command contains $(...) (command substitution) — blastradius "
        "refuses to model this. If this is intentional, run it yourself "
        "outside the agent.",
    )


def _refuse_backtick() -> _Refuse:
    return _Refuse(
        "unparseable-command-backtick",
        "command contains backticks (command substitution) — blastradius "
        "refuses to model this. If this is intentional, run it yourself "
        "outside the agent.",
    )


def _refuse_subshell() -> _Refuse:
    return _Refuse(
        "unparseable-command-subshell",
        "command contains an unquoted ( or ) (subshell, function "
        "definition, case pattern or arithmetic) — blastradius refuses to "
        "model this. If this is intentional, run it yourself outside the "
        "agent.",
    )


def _refuse_procsubst(c: str) -> _Refuse:
    return _Refuse(
        "unparseable-command-process-substitution",
        f"command contains {c}(...) (process substitution) — blastradius "
        "refuses to model this. If this is intentional, run it yourself "
        "outside the agent.",
    )


def _refuse_newline() -> _Refuse:
    return _Refuse(
        "unparseable-command-newline",
        "command contains a newline — blastradius treats newlines as "
        "command separators. If this is intentional, run the commands "
        "separately outside the agent.",
    )


def _refuse_unterminated(q: str) -> _Refuse:
    return _Refuse(
        "unparseable-command-unterminated-quote",
        f"command has an unterminated {q} quote — the shell would reject "
        "or misread it; blastradius refuses to guess.",
    )


def tokenise(command: str) -> TokeniseResult:
    """Tokenise a command string into simple commands.

    Returns TokeniseResult with segments on success, or with a Refusal if
    the command contains constructs we refuse to model.
    """
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

    lexer = _Lexer(command)
    try:
        lexer.run()
    except _Refuse as r:
        return TokeniseResult(
            segments=None,
            refusal=Refusal(rule=r.rule, reason=r.reason, raw=command),
        )

    if not lexer.segments:
        return TokeniseResult(segments=None, separators=lexer.separators)
    return TokeniseResult(
        segments=lexer.segments,
        separators=lexer.separators,
        redirections=lexer.redirections,
        segment_separators=lexer.segment_separators,
    )


# A word is a list of (char, quoted) pairs; quoted chars never take part in
# brace expansion or fd-number detection.
_Word = list[tuple[str, bool]]


class _Lexer:
    def __init__(self, s: str) -> None:
        self.s = s
        self.n = len(s)
        self.i = 0
        self.segments: list[list[str]] = []
        self.redirections: list[list[Redirection]] = []
        self.segment_separators: list[str | None] = []
        self.separators: list[str] = []
        self._words: list[str] = []
        self._redirs: list[Redirection] = []
        self._sep_before: str | None = None

    # ── driver ──────────────────────────────────────────────────────

    def run(self) -> None:
        s = self.s
        while True:
            self._skip_blanks()
            if self.i >= self.n:
                break
            c = s[self.i]
            if c == "\n":
                raise _refuse_newline()
            if c in "()":
                raise _refuse_subshell()
            sep = self._match_separator()
            if sep is not None:
                self._end_segment(sep)
                continue
            if c in "<>" or s.startswith("&>", self.i):
                self._read_redirect(fd=None)
                continue
            word = self._read_word()
            if (
                self.i < self.n
                and s[self.i] in "<>"
                and word
                and all(ch.isdigit() and not q for ch, q in word)
            ):
                self._read_redirect(fd="".join(ch for ch, _ in word))
                continue
            self._words.extend(_brace_expand(word))
        self._end_segment(None)

    def _skip_blanks(self) -> None:
        while self.i < self.n and self.s[self.i] in _BLANKS:
            self.i += 1

    def _match_separator(self) -> str | None:
        s, i = self.s, self.i
        c = s[i]
        if c == ";":
            self.i += 1
            return ";"
        if c == "&":
            if s.startswith("&&", i):
                self.i += 2
                return "&&"
            if s.startswith("&>", i):
                return None  # redirection
            self.i += 1
            return "&"
        if c == "|":
            if s.startswith("||", i):
                self.i += 2
                return "||"
            if s.startswith("|&", i):
                self.i += 2
                return "|&"
            self.i += 1
            return "|"
        return None

    def _end_segment(self, sep: str | None) -> None:
        if self._words or self._redirs:
            self.segments.append(self._words)
            self.redirections.append(self._redirs)
            self.segment_separators.append(self._sep_before)
        self._words = []
        self._redirs = []
        if sep is not None:
            self.separators.append(sep)
            self._sep_before = sep

    # ── words ───────────────────────────────────────────────────────

    def _at_word_end(self) -> bool:
        if self.i >= self.n:
            return True
        c = self.s[self.i]
        return c in _BLANKS or c in _SEPARATOR_CHARS or c in "<>\n()"

    def _read_word(self) -> _Word:
        """Read one word starting at self.i (not a blank or operator)."""
        s = self.s
        word: _Word = []
        while self.i < self.n:
            c = s[self.i]
            if c in _BLANKS or c in _SEPARATOR_CHARS or c in "<>":
                break
            if c == "\n":
                raise _refuse_newline()
            if c in "()":
                raise _refuse_subshell()
            if c == "\\":
                if self.i + 1 >= self.n:
                    word.append(("\\", True))
                    self.i += 1
                    continue
                nxt = s[self.i + 1]
                self.i += 2
                if nxt != "\n":  # backslash-newline is a line continuation
                    word.append((nxt, True))
                continue
            if c == "'":
                self._read_single(word)
                continue
            if c == '"':
                self.i += 1
                self._read_double(word)
                continue
            if c == "`":
                raise _refuse_backtick()
            if c == "$":
                self._read_dollar(word, in_double=False)
                continue
            word.append((c, False))
            self.i += 1
        return word

    def _read_single(self, word: _Word) -> None:
        end = self.s.find("'", self.i + 1)
        if end < 0:
            raise _refuse_unterminated("single")
        for ch in self.s[self.i + 1:end]:
            word.append((ch, True))
        self.i = end + 1

    def _read_double(self, word: _Word) -> None:
        """Read a double-quoted body; self.i is just past the opening quote."""
        s = self.s
        while True:
            if self.i >= self.n:
                raise _refuse_unterminated("double")
            c = s[self.i]
            if c == '"':
                self.i += 1
                return
            if c == "\\" and self.i + 1 < self.n:
                nxt = s[self.i + 1]
                if nxt in ("$", "`", '"', "\\"):
                    word.append((nxt, True))
                    self.i += 2
                    continue
                if nxt == "\n":
                    self.i += 2
                    continue
                word.append(("\\", True))
                self.i += 1
                continue
            if c == "`":
                raise _refuse_backtick()
            if c == "$":
                self._read_dollar(word, in_double=True)
                continue
            word.append((c, True))
            self.i += 1

    def _read_dollar(self, word: _Word, *, in_double: bool) -> None:
        """Handle a '$' at self.i."""
        s, i = self.s, self.i
        nxt = s[i + 1] if i + 1 < self.n else ""
        if nxt == "(":
            raise _refuse_cmdsubst()
        if nxt == "{":
            # ${...}: copied verbatim (the resolver expands or refuses it).
            # Quotes, escapes or nested expansions inside make the end of
            # the expansion ambiguous for a simple lexer — fail closed.
            end = i + 2
            while end < self.n and s[end] != "}":
                if s[end] in "'\"\\`${\n":
                    raise _Refuse(
                        "unparseable-command-parameter-expansion",
                        "command contains a ${...} expansion with quotes, "
                        "escapes or nested expansions inside — blastradius "
                        "refuses to model it.",
                    )
                end += 1
            if end >= self.n:
                raise _refuse_unterminated("${")
            for ch in s[i:end + 1]:
                word.append((ch, True))
            self.i = end + 1
            return
        if not in_double and nxt == "'":
            # ANSI-C quoting $'...': a backslash escapes the next character,
            # including a quote. Kept verbatim (with its '$') so the
            # resolver refuses it — escape sequences are not decoded.
            j = i + 2
            while j < self.n:
                if s[j] == "\\":
                    j += 2
                    continue
                if s[j] == "'":
                    break
                j += 1
            if j >= self.n:
                raise _refuse_unterminated("$'")
            for ch in s[i:j + 1]:
                word.append((ch, True))
            self.i = j + 1
            return
        if not in_double and nxt == '"':
            # Locale-translated string $"...": parsed as double quotes but
            # with a literal '$"' marker kept so it is never silently
            # resolved as something else.
            word.append(("$", True))
            word.append(('"', True))
            self.i = i + 2
            self._read_double(word)
            word.append(('"', True))
            return
        word.append(("$", in_double))
        self.i += 1

    # ── redirections ────────────────────────────────────────────────

    def _read_redirect(self, fd: str | None) -> None:
        s, i = self.s, self.i
        if s.startswith("&>>", i):
            op, kind = "&>>", "append"
        elif s.startswith("&>", i):
            op, kind = "&>", "truncate"
        elif s.startswith(">(", i):
            raise _refuse_procsubst(">")
        elif s.startswith("<(", i):
            raise _refuse_procsubst("<")
        elif s.startswith(">>", i):
            op, kind = ">>", "append"
        elif s.startswith(">|", i):
            op, kind = ">|", "truncate"
        elif s.startswith(">&", i):
            op, kind = ">&", "truncate"
        elif s.startswith(">", i):
            op, kind = ">", "truncate"
        elif s.startswith("<<<", i):
            op, kind = "<<<", "herestring"
        elif s.startswith("<<-", i):
            op, kind = "<<-", "heredoc"
        elif s.startswith("<<", i):
            op, kind = "<<", "heredoc"
        elif s.startswith("<>", i):
            op, kind = "<>", "readwrite"
        elif s.startswith("<&", i):
            op, kind = "<&", "input"
        else:
            op, kind = "<", "input"
        self.i = i + len(op)
        self._skip_blanks()
        if self._at_word_end():
            # Missing target: a shell syntax error. Recorded so an output
            # redirection is still judged (and refused as an empty target).
            self._redirs.append(Redirection(op=op, target="", fd=fd, kind=kind))
            return
        word = self._read_word()
        if op in (">&", "<&"):
            text = "".join(ch for ch, _ in word)
            if re.fullmatch(r"\d+-?|-", text):
                kind = "dup"
        for target in _brace_expand(word):
            self._redirs.append(Redirection(op=op, target=target, fd=fd, kind=kind))


# ─────────────────────────────────────────────────────────────────────
# Brace expansion ({a,b}, {1..3}) — applied to unquoted braces only
# ─────────────────────────────────────────────────────────────────────


def _too_many() -> _Refuse:
    return _Refuse(
        "unparseable-command-brace-expansion",
        f"a brace expansion produces more than {MAX_BRACE_WORDS} words — "
        "blastradius refuses to model it.",
    )


def _brace_expand(word: _Word) -> list[str]:
    results = _expand(word)
    if len(results) > MAX_BRACE_WORDS:
        raise _too_many()
    return ["".join(ch for ch, _ in w) for w in results]


def _expand(chars: _Word) -> list[_Word]:
    n = len(chars)
    i = 0
    while i < n:
        c, q = chars[i]
        if c == "{" and not q:
            depth = 0
            commas: list[int] = []
            j = i
            while j < n:
                cj, qj = chars[j]
                if not qj:
                    if cj == "{":
                        depth += 1
                    elif cj == "}":
                        depth -= 1
                        if depth == 0:
                            break
                    elif cj == "," and depth == 1:
                        commas.append(j)
                j += 1
            if j < n:
                pre, body, post = chars[:i], chars[i + 1:j], chars[j + 1:]
                alts: list[_Word] | None = None
                if commas:
                    alts = []
                    start = i + 1
                    for k in commas + [j]:
                        alts.extend(_expand(chars[start:k]))
                        start = k + 1
                        if len(alts) > MAX_BRACE_WORDS:
                            raise _too_many()
                elif body and all(not qq for _, qq in body):
                    seq = _sequence("".join(ch for ch, _ in body))
                    if seq is not None:
                        alts = [[(ch, True) for ch in item] for item in seq]
                if alts is not None:
                    posts = _expand(post)
                    if len(alts) * len(posts) > MAX_BRACE_WORDS:
                        raise _too_many()
                    return [pre + a + p for a in alts for p in posts]
        i += 1
    return [chars]


_SEQ_INT = re.compile(r"^(-?\d+)\.\.(-?\d+)(?:\.\.(-?\d+))?$")
_SEQ_CHR = re.compile(r"^([A-Za-z])\.\.([A-Za-z])(?:\.\.(-?\d+))?$")


def _sequence(body: str) -> list[str] | None:
    m = _SEQ_INT.match(body)
    if m:
        a, b = int(m.group(1)), int(m.group(2))
        step = abs(int(m.group(3))) if m.group(3) else 1
        step = step or 1
        if abs(b - a) // step + 1 > MAX_BRACE_WORDS:
            raise _too_many()
        width = 0
        if any(len(g.lstrip("-")) > 1 and g.lstrip("-").startswith("0")
               for g in (m.group(1), m.group(2))):
            width = max(len(m.group(1)), len(m.group(2)))
        rng = range(a, b + 1, step) if a <= b else range(a, b - 1, -step)
        return [str(v).zfill(width) if width else str(v) for v in rng]
    m = _SEQ_CHR.match(body)
    if m:
        a, b = ord(m.group(1)), ord(m.group(2))
        step = abs(int(m.group(3))) if m.group(3) else 1
        step = step or 1
        rng = range(a, b + 1, step) if a <= b else range(a, b - 1, -step)
        return [chr(v) for v in rng]
    return None


__all__ = ["tokenise", "TokeniseResult", "Redirection", "MAX_BRACE_WORDS"]
