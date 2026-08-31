"""Floor rules, scope, and glob-breadth checks.

Floor rules are absolute — no configuration can override them. They
protect /, $HOME, system directories, and shallow paths from root.
The floor check runs BEFORE scope. If a path is floor, it is refused
regardless of what the scope says.

Scope comes from .blastradius in the repo root, or sensible defaults.
Anything outside the allow list is refused.

Glob breadth: a glob that expands to more than N entries is refused
even inside scope, because a broad deletion is dangerous regardless
of where it points.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from .resolve import Refusal, Resolved, ResolveResult


# ─────────────────────────────────────────────────────────────────────
# Floor paths — absolute, unoverridable
# ─────────────────────────────────────────────────────────────────────

# These exact paths are always refused. No config, no flag, no env var
# can override. Adding $HOME to this list at runtime (via the home()
# function) makes it dynamic per-machine.
#
# Note: on modern Linux, /bin → /usr/bin, /sbin → /usr/sbin, etc.
# We include both the symlink and the target to catch both.
FLOOR_EXACT: set[str] = {
    "/",
    "/home",
    "/Users",
    "/etc",
    "/usr",
    "/usr/bin",
    "/usr/sbin",
    "/usr/lib",
    "/usr/lib64",
    "/usr/lib32",
    "/usr/local",
    "/usr/share",
    "/usr/include",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/lib32",
    "/var",
    "/var/lib",
    "/var/log",
    "/var/cache",
    "/var/spool",
    "/var/tmp",
    "/System",
    "/Library",
    "/opt",
    "/private",  # macOS /private symlink target
    "/root",
    "/boot",
    "/dev",
    "/proc",
    "/sys",
    # Windows
    "C:\\Windows",
    "C:\\Users",
    "C:\\Program Files",
    "C:\\Program Files (x86)",
}


def _path_depth(path: str) -> int:
    """Depth from filesystem root.

    / has depth 0.
    /tmp has depth 1.
    /tmp/foo has depth 2.

    On Windows, C:\\ has depth 0, C:\\Users has depth 1, etc.
    """
    # Normalise separators.
    p = path.replace("\\", "/")
    # Remove trailing slashes.
    p = p.rstrip("/")
    if p == "" or p == "/" or (len(p) == 2 and p[1] == ":"):
        return 0
    # Count path components.
    parts = [p for p in p.split("/") if p and p != ":"]
    # Remove drive letter if present (e.g. "C:" becomes nothing).
    if parts and len(parts[0]) == 2 and parts[0][1] == ":":
        parts = parts[1:]
    return len(parts)


def is_floor(path: str, *, home: str | None = None) -> bool:
    """True if this path is on the unoverridable floor.

    Floor if:
      - path is $HOME (the user's home directory itself)
      - path is in FLOOR_EXACT
      - path is at depth ≤ 1 from root (/, /single-component)

    Paths at depth ≥ 2 are NOT automatically floor — they're judged
    by scope. This allows /tmp/foo (depth 2) to be allowed by scope
    while /tmp (depth 1) is refused.

    Note: $HOME itself is floor, but $HOME/projects/myrepo/build is
    NOT floor (it's a descendant of $HOME, not $HOME itself). Scope
    decides on descendants.
    """
    if home is None:
        home = os.path.expanduser("~")

    real = os.path.realpath(path)

    # $HOME itself.
    if real == os.path.realpath(home):
        return True

    # Explicit floor list.
    if real in FLOOR_EXACT:
        return True

    # Also check the un-realpath'd version (in case realpath resolves
    # a symlink to a floor path — e.g. /private/etc → /etc on macOS).
    if path in FLOOR_EXACT:
        return True

    # Depth ≤ 1 from root: / or /single-component.
    depth = _path_depth(real)
    if depth <= 1:
        return True

    return False


def floor_refusal(path: str, raw: str) -> Refusal:
    """Build a refusal for a floor path."""
    return Refusal(
        rule="floor-path",
        reason=(
            f"target {path} is a protected system path "
            f"(root, home directory, or depth ≤ 1 from root) — "
            f"this rule cannot be overridden by any configuration"
        ),
        raw=raw,
        resolved=path,
    )


# ─────────────────────────────────────────────────────────────────────
# Scope
# ─────────────────────────────────────────────────────────────────────


@dataclass
class Scope:
    """The declared allow/deny scope for destructive operations."""

    allow: list[str] = field(default_factory=list)
    deny: list[str] = field(default_factory=list)
    repo_root: str | None = None

    def allows(self, path: str) -> bool:
        """True if the path is within the allowed scope."""
        real = os.path.realpath(path)

        # Check deny first — deny always wins.
        for pattern in self.deny:
            if _match_scope(pattern, real, self.repo_root):
                return False

        # Check allow.
        for pattern in self.allow:
            if _match_scope(pattern, real, self.repo_root):
                return True

        return False

    def refusal(self, path: str, raw: str) -> Refusal:
        return Refusal(
            rule="out-of-scope",
            reason=f"target {path} is not within any allowed scope entry",
            raw=raw,
            resolved=path,
        )


def _match_scope(pattern: str, path: str, repo_root: str | None) -> bool:
    """Match a scope pattern against a path.

    Patterns support:
      - <repo> as a placeholder for the git repo root
      - ** glob (matches any number of path components)
      - * glob (matches within a single path component)
      - $VAR expansion (already done before matching)
    """
    # Expand <repo> placeholder.
    if "<repo>" in pattern or "<git repo root>" in pattern:
        if repo_root is None:
            return False  # can't match without a repo root
        pattern = pattern.replace("<repo>", repo_root)
        pattern = pattern.replace("<git repo root>", repo_root)

    # Normalise pattern to absolute.
    if not os.path.isabs(pattern):
        if repo_root:
            pattern = os.path.join(repo_root, pattern)
        else:
            pattern = os.path.join(os.getcwd(), pattern)

    pattern_real = os.path.realpath(pattern)
    path_real = os.path.realpath(path)

    # Handle ** patterns. fnmatch doesn't handle ** across path
    # separators correctly, so we do it manually.
    if "**" in pattern_real:
        # Convert ** to a regex that matches any number of path components,
        # INCLUDING ZERO. This means /tmp/blast_repo/** matches both
        # /tmp/blast_repo/foo AND /tmp/blast_repo itself.
        #
        # The key insight: /tmp/blast_repo/** splits into:
        #   segment[0] = "/tmp/blast_repo/"  (ends with /)
        #   segment[1] = ""                  (empty)
        # The ** between them should match: nothing, or "foo", or "a/b/c".
        # So the regex for ** after a trailing / is: (?:.*)?  which matches
        # zero or more chars. But we also need the preceding / to be
        # optional, so /tmp/blast_repo (no trailing /) also matches.
        #
        # We handle this by making the trailing / before ** optional:
        #   /tmp/blast_repo/ + (?:.*)?  →  /tmp/blast_repo(?:/.*)?
        import re

        segments = pattern_real.split("**")
        regex_parts = []
        for i, segment in enumerate(segments):
            if i > 0:
                # ** matches zero or more path components.
                prev_seg = segments[i - 1]
                if prev_seg.endswith("/"):
                    # Make the trailing / optional: /tmp/ + (?:.*)?
                    # becomes /tmp(?:/.*)? so /tmp itself matches.
                    # We do this by removing the trailing / from the
                    # previous segment's regex and adding (?:/.*)?
                    # instead of (?:.*)?
                    if regex_parts:
                        # Remove the trailing / from the last regex part.
                        last = regex_parts[-1]
                        if last.endswith("/"):
                            regex_parts[-1] = last[:-1]
                    regex_parts.append("(?:/.*)?")
                else:
                    # /tmp**/foo → /tmp(?:/.*)?/foo — need the slash.
                    regex_parts.append("(?:/.*)?")
            # Within a segment, * matches within a component.
            seg_regex = re.escape(segment).replace(r"\*", "[^/]*").replace(r"\?", ".")
            regex_parts.append(seg_regex)
        regex = "^" + "".join(regex_parts) + "$"

        # Try matching with and without trailing slash.
        if re.match(regex, path_real):
            return True
        if re.match(regex, path_real.rstrip("/")):
            return True
        return False

    # Simple glob match (no **).
    import fnmatch

    if fnmatch.fnmatch(path_real, pattern_real):
        return True
    # Also check if path is under the pattern directory.
    if path_real.startswith(pattern_real.rstrip("/") + "/"):
        return True

    return False


def find_repo_root(cwd: str | None = None) -> str | None:
    """Walk up from cwd looking for .git. Return the repo root or None."""
    if cwd is None:
        cwd = os.getcwd()
    current = os.path.realpath(cwd)
    while True:
        if os.path.isdir(os.path.join(current, ".git")):
            return current
        parent = os.path.dirname(current)
        if parent == current:
            return None
        current = parent


def default_scope(cwd: str | None = None) -> Scope:
    """Build the default scope: repo root + /tmp + $TMPDIR + common build dirs."""
    repo_root = find_repo_root(cwd)
    allow: list[str] = []

    if repo_root:
        allow.append(f"{repo_root}/**")
        for build_dir in ("build", "dist", "target", ".venv", "node_modules",
                          "__pycache__", ".pytest_cache", ".mypy_cache",
                          ".ruff_cache", ".tox", ".eggs", "htmlcov"):
            allow.append(os.path.join(repo_root, build_dir))

    # /tmp — but only at depth ≥ 2 (depth ≤ 1 is floor).
    # The ** ensures we match /tmp/foo/bar and deeper.
    allow.append("/tmp/**")

    # $TMPDIR.
    tmpdir = os.environ.get("TMPDIR", "")
    if tmpdir:
        allow.append(os.path.join(tmpdir.rstrip("/"), "**"))

    return Scope(allow=allow, repo_root=repo_root)


def load_scope(cwd: str | None = None) -> Scope:
    """Load scope from .blastradius in the repo root, or use defaults."""
    repo_root = find_repo_root(cwd)
    config_path = None
    if repo_root:
        candidate = os.path.join(repo_root, ".blastradius")
        if os.path.isfile(candidate):
            config_path = candidate

    if config_path is None:
        return default_scope(cwd)

    scope = parse_config(config_path, repo_root=repo_root)
    return scope


def parse_config(path: str, *, repo_root: str | None = None) -> Scope:
    """Parse a .blastradius config file.

    Format (simple, no YAML dependency):
      # comment
      allow /tmp/**
      allow ./build/**
      deny ./secrets
      allow <repo>/node_modules

    Each line is either 'allow <pattern>' or 'deny <pattern>'.
    Lines starting with # are comments. Blank lines are ignored.
    """
    allow: list[str] = []
    deny: list[str] = []

    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if len(parts) != 2:
                continue
            keyword, pattern = parts
            if keyword == "allow":
                allow.append(pattern)
            elif keyword == "deny":
                deny.append(pattern)

    return Scope(allow=allow, deny=deny, repo_root=repo_root)


# ─────────────────────────────────────────────────────────────────────
# Glob breadth
# ─────────────────────────────────────────────────────────────────────


DEFAULT_MAX_GLOB_BREADTH = 100


def check_glob_breadth(
    resolved: Resolved,
    *,
    max_entries: int = DEFAULT_MAX_GLOB_BREADTH,
    repo_root: str | None = None,
) -> Refusal | None:
    """Check if a glob expanded to too many entries.

    Returns a Refusal if the breadth is dangerous, None if OK.
    """
    if len(resolved.paths) > max_entries:
        return Refusal(
            rule="glob-breadth",
            reason=(
                f"glob expanded to {len(resolved.paths)} entries "
                f"(max {max_entries}) — broad deletions are dangerous "
                f"even inside scope"
            ),
            raw=resolved.raw,
            resolved=f"{len(resolved.paths)} paths",
        )

    # Check if any match is at repo root level (depth 1 from repo root).
    if repo_root:
        repo_real = os.path.realpath(repo_root)
        for p in resolved.paths:
            parent = os.path.dirname(p)
            if parent == repo_real:
                return Refusal(
                    rule="glob-breadth",
                    reason=(
                        f"glob matched {p} which is at repo root level — "
                        f"deleting top-level repo entries via glob is dangerous"
                    ),
                    raw=resolved.raw,
                    resolved=p,
                )

    return None


__all__ = [
    "Scope",
    "is_floor",
    "floor_refusal",
    "find_repo_root",
    "default_scope",
    "load_scope",
    "parse_config",
    "check_glob_breadth",
    "DEFAULT_MAX_GLOB_BREADTH",
]
