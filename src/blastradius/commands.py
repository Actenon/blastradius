"""Identify destructive commands and extract their target arguments.

Not just rm. The corpus of ways to destroy data:

  - rm, rmdir, shred, srm
  - find ... -delete and find ... -exec rm
  - git clean -fdx
  - dd of=<path>
  - truncate -s 0 <path>
  - mv <path> /dev/null
  - > file (output redirection that truncates)
  - chmod -R / chown -R (destructive in practice)

v1 starts with: rm, find -delete, git clean, dd, truncate, shred.
Everything else is a later addition.
"""

from __future__ import annotations

from dataclasses import dataclass


# Commands that are always destructive when they appear.
DESTRUCTIVE_COMMANDS: set[str] = {
    "rm",
    "rmdir",
    "shred",
    "srm",
    "truncate",
    "dd",
}

# Commands that are destructive only with specific flags.
# find -delete, find -exec rm, git clean -fdx, etc.
CONDITIONAL_COMMANDS: set[str] = {
    "find",
    "git",
}


@dataclass(frozen=True)
class DestructiveAction:
    """A detected destructive operation within a command."""

    command: str  # e.g. "rm", "find", "git"
    targets: list[str]  # raw target argument strings
    flags: list[str]  # flags passed to the command
    source: str  # human-readable description of what's destructive


# Find flags that take an argument (the next token is NOT a search path).
_FIND_FLAGS_WITH_ARG: set[str] = {
    "-name", "-iname", "-type", "-size", "-user", "-group", "-perm",
    "-mtime", "-ctime", "-atime", "-newer", "-path", "-regex",
    "-links", "-inum", "-mindepth", "-maxdepth", "-fstype", "-context",
    "-uid", "-gid", "-printf", "-fprint", "-fprintf",
}


def _find_search_paths(args: list[str]) -> list[str]:
    """Extract search paths from find arguments.

    The search path is the first non-flag argument that isn't an
    argument to a find flag like -name, -type, etc.
    If no path is given, find defaults to "." (CWD).
    """
    targets: list[str] = []
    skip_next = False
    for a in args:
        if skip_next:
            skip_next = False
            continue
        if a in _FIND_FLAGS_WITH_ARG:
            skip_next = True
            continue
        if a.startswith("-"):
            continue
        # This is a search path (or an argument to -exec, but -exec
        # is handled separately by the caller).
        targets.append(a)
    if not targets:
        targets = ["."]
    return targets


def identify_destructive(tokens: list[str]) -> DestructiveAction | None:
    """Check if a tokenised command is destructive.

    Returns a DestructiveAction if destructive, None if not.

    tokens is the output of the tokeniser: ["rm", "-rf", "/tmp/foo"].
    """
    if not tokens:
        return None

    cmd = tokens[0]

    # Strip leading command paths: /bin/rm → rm
    if "/" in cmd:
        cmd = cmd.rsplit("/", 1)[-1]
    if "\\" in cmd:
        cmd = cmd.rsplit("\\", 1)[-1]

    args = tokens[1:]
    flags = [a for a in args if a.startswith("-")]
    non_flags = [a for a in args if not a.startswith("-")]

    # ── rm, rmdir, shred, srm ───────────────────────────────────────
    if cmd in ("rm", "rmdir", "shred", "srm"):
        return DestructiveAction(
            command=cmd,
            targets=non_flags,
            flags=flags,
            source=f"{cmd} — direct filesystem deletion",
        )

    # ── truncate ─────────────────────────────────────────────────────
    if cmd == "truncate":
        # truncate -s 0 <file>  or  truncate --size 0 <file>
        # The -s flag takes an argument (the size), which is NOT a target.
        if "-s" in flags or "--size" in " ".join(flags):
            # Re-parse: skip the argument to -s/--size.
            targets = []
            skip_next = False
            for a in args:
                if skip_next:
                    skip_next = False
                    continue
                if a == "-s" or a == "--size":
                    skip_next = True  # next arg is the size value
                    continue
                if a.startswith("-s") and len(a) > 2:
                    # -s0 (combined flag + value)
                    continue
                if a.startswith("--size="):
                    continue
                if a.startswith("-"):
                    continue
                targets.append(a)
            if targets:
                return DestructiveAction(
                    command=cmd,
                    targets=targets,
                    flags=flags,
                    source="truncate — truncates file to zero or specified size",
                )

    # ── dd ───────────────────────────────────────────────────────────
    if cmd == "dd":
        # dd of=<path> — the of= argument is the target.
        targets = []
        for a in args:
            if a.startswith("of="):
                targets.append(a[3:])
        if targets:
            return DestructiveAction(
                command=cmd,
                targets=targets,
                flags=flags,
                source="dd — writes to of= target, overwriting existing data",
            )

    # ── find ... -delete ─────────────────────────────────────────────
    if cmd == "find":
        if "-delete" in args:
            # The target is the search path — the first non-flag arg
            # that isn't an argument to a find flag like -name, -type, etc.
            # If no path given, it's "." (CWD).
            return DestructiveAction(
                command=cmd,
                targets=_find_search_paths(args),
                flags=flags,
                source="find -delete — deletes matched files",
            )
        # find ... -exec rm
        if "-exec" in args:
            exec_idx = args.index("-exec")
            exec_cmd = args[exec_idx + 1] if exec_idx + 1 < len(args) else ""
            if exec_cmd in ("rm", "rmdir", "shred") or exec_cmd.endswith("/rm"):
                return DestructiveAction(
                    command=cmd,
                    targets=_find_search_paths(args),
                    flags=flags,
                    source=f"find -exec {exec_cmd} — deletes matched files",
                )

    # ── git clean -fdx ───────────────────────────────────────────────
    if cmd == "git" and len(args) >= 1 and args[0] == "clean":
        # git clean removes untracked files.
        # -f is required (force), -d removes directories, -x ignores gitignore.
        if "-f" in " ".join(flags) or "--force" in " ".join(flags):
            # The target is effectively the CWD (the git repo).
            # If a path is given, it's the last non-flag arg.
            targets = non_flags[1:] if len(non_flags) > 1 else ["."]
            return DestructiveAction(
                command=cmd,
                targets=targets,
                flags=flags,
                source="git clean -f — removes untracked files",
            )

    # ── git reset --hard ─────────────────────────────────────────────
    if cmd == "git" and len(args) >= 1 and args[0] == "reset":
        if "--hard" in args:
            targets = non_flags[1:] if len(non_flags) > 1 else ["."]
            return DestructiveAction(
                command=cmd,
                targets=targets,
                flags=flags,
                source="git reset --hard — discards working tree changes",
            )

    return None


__all__ = [
    "DESTRUCTIVE_COMMANDS",
    "CONDITIONAL_COMMANDS",
    "DestructiveAction",
    "identify_destructive",
]
