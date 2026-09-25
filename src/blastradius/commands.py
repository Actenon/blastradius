"""Identify destructive and risky commands, and extract their targets.

v0.3.0: Two tiers of detection:

  TIER 1 — BLOCK (filesystem destruction, same as before):
    rm, rmdir, shred, srm, truncate, dd
    find -delete, find -exec rm
    git clean -f, git reset --hard

  TIER 2 — WARN (consequential but not filesystem destruction):
    pip install / pip3 install (arbitrary code execution)
    npm install / yarn install (arbitrary code execution)
    curl / wget (network request, potential credential exfiltration)
    git filter-branch / git push --force (irreversible git operations)
    chmod -R / chown -R (recursive permission changes)
    twine upload (irreversible PyPI publish)
    ssh / scp / rsync (remote system access)
    docker run (container with potential host mounts)
    .env / secrets file access (config/credential exposure)
    production deployment indicators (deploy.sh, production, staging→prod)

Tier 2 commands are not blocked by default — they produce a WARNING
that tells the developer what kind of risk is present. The developer
decides whether to proceed.
"""

from __future__ import annotations

from dataclasses import dataclass, field


# ─────────────────────────────────────────────────────────────────────
# Tier 1: Filesystem destruction (BLOCK)
# ─────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class DestructiveAction:
    """A detected destructive filesystem operation."""

    command: str
    targets: list[str]
    flags: list[str]
    source: str


# ─────────────────────────────────────────────────────────────────────
# Tier 2: Risky but not filesystem-destruction (WARN)
# ─────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class RiskWarning:
    """A warning about a consequential but non-filesystem-destruction action."""

    category: str  # "network", "package", "git", "permission", "publish", "config", "deployment"
    command: str
    reason: str
    severity: str  # "high", "medium"


# Find flags that take an argument (the next token is NOT a search path).
_FIND_FLAGS_WITH_ARG: set[str] = {
    "-name", "-iname", "-type", "-size", "-user", "-group", "-perm",
    "-mtime", "-ctime", "-atime", "-newer", "-path", "-regex",
    "-links", "-inum", "-mindepth", "-maxdepth", "-fstype", "-context",
    "-uid", "-gid", "-printf", "-fprint", "-fprintf",
}


def _find_search_paths(args: list[str]) -> list[str]:
    """Extract search paths from find arguments."""
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
        targets.append(a)
    if not targets:
        targets = ["."]
    return targets


def _strip_path(cmd: str) -> str:
    """Strip leading command paths: /bin/rm → rm"""
    if "/" in cmd:
        cmd = cmd.rsplit("/", 1)[-1]
    if "\\" in cmd:
        cmd = cmd.rsplit("\\", 1)[-1]
    return cmd


def _parse_flags_targets(args: list[str]) -> tuple[list[str], list[str]]:
    """Parse args into (flags, non_flags) respecting -- separator."""
    flags: list[str] = []
    non_flags: list[str] = []
    seen_dd = False
    for a in args:
        if seen_dd:
            non_flags.append(a)
        elif a == "--":
            seen_dd = True
        elif a.startswith("-") and a != "-":
            flags.append(a)
        else:
            non_flags.append(a)
    return flags, non_flags


# ─────────────────────────────────────────────────────────────────────
# Command-runner wrappers
# ─────────────────────────────────────────────────────────────────────
#
# identify_destructive only inspects the first token, so any program
# that runs another command hides an ``rm`` behind it: ``sudo rm``,
# ``env rm``, ``xargs rm``, ``timeout 5 rm`` … These must be unwrapped
# so the real command is checked.

_WRAPPERS: set[str] = {
    "sudo", "doas", "env", "command", "exec", "nice", "nohup", "setsid",
    "ionice", "stdbuf", "time", "timeout", "chrt", "taskset", "eatmydata",
    "proxychains", "proxychains4", "catchsegv", "busybox", "nocache",
    "xargs",
}

# Per-wrapper options that consume a *separate* following argument when
# given un-glued (``nice -n 19``, ``sudo -u root``). Glued forms
# (``-n19``, ``-c3``, ``-oL``) carry their value inline and take no
# extra token. Options not listed are assumed to take no separate arg.
_WRAPPER_OPTS_WITH_ARG: dict[str, set[str]] = {
    "sudo": {"-u", "--user", "-g", "--group", "-C", "--close-from",
             "-p", "--prompt", "-r", "--role", "-t", "--type",
             "-U", "--other-user", "-h", "--host"},
    "doas": {"-u", "-C"},
    "env": {"-u", "--unset", "-C", "--chdir", "-S", "--split-string"},
    "nice": {"-n", "--adjustment"},
    "ionice": {"-c", "--class", "-n", "--classdata", "-p", "--pid"},
    "stdbuf": {"-i", "--input", "-o", "--output", "-e", "--error"},
    "timeout": {"-s", "--signal", "-k", "--kill-after"},
    "taskset": {"-c", "--cpu-list", "-p", "--pid"},
    "chrt": {"-p"},
    "xargs": {"-n", "--max-args", "-P", "--max-procs", "-s", "--max-chars",
              "-d", "--delimiter", "-E", "-I", "--replace", "-a",
              "--arg-file", "-L", "--max-lines"},
}

# Wrappers that eat a positional argument BEFORE the command
# (``timeout DURATION cmd``).
_WRAPPER_LEADING_POSITIONAL: dict[str, int] = {"timeout": 1}


def _is_assignment(tok: str) -> bool:
    """True for env/sudo NAME=VALUE assignment tokens."""
    if "=" not in tok or tok.startswith("-"):
        return False
    name = tok.split("=", 1)[0]
    return name.isidentifier()


def _unwrap_wrappers(tokens: list[str]) -> list[str]:
    """Strip leading command-runner wrappers so the real command shows.

    ``sudo rm -rf /etc`` → ``rm -rf /etc``. Handles nested wrappers
    (``sudo nice rm ...``). Wrapper options, their arguments, and
    ``env``/``sudo`` NAME=VAL assignments are consumed. If the inner
    command cannot be located the original tokens are returned unchanged
    (callers then find nothing — identical to the pre-unwrap behaviour),
    so unwrapping can only ever ADD a block, never remove one.
    """
    guard = 0
    while tokens and guard < 16:
        guard += 1
        w = _strip_path(tokens[0])
        if w not in _WRAPPERS:
            break
        rest = tokens[1:]
        opts_with_arg = _WRAPPER_OPTS_WITH_ARG.get(w, set())
        leading_positional = _WRAPPER_LEADING_POSITIONAL.get(w, 0)
        i = 0
        while i < len(rest):
            a = rest[i]
            if a == "--":
                i += 1
                break
            if a.startswith("-") and a != "-":
                if a in opts_with_arg and i + 1 < len(rest):
                    i += 2
                else:
                    i += 1
                continue
            if w in ("env", "sudo") and _is_assignment(a):
                i += 1
                continue
            if leading_positional > 0:
                leading_positional -= 1
                i += 1
                continue
            break
        new_tokens = rest[i:]
        if not new_tokens:
            return tokens
        tokens = new_tokens
    return tokens


def identify_destructive(tokens: list[str]) -> DestructiveAction | None:
    """Check if a tokenised command is a filesystem-destruction command.

    Returns a DestructiveAction if destructive, None if not.
    """
    if not tokens:
        return None

    tokens = _unwrap_wrappers(tokens)
    if not tokens:
        return None

    cmd = _strip_path(tokens[0])
    args = tokens[1:]
    flags, non_flags = _parse_flags_targets(args)

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
        # Detect the size flag in every form: ``-s N``, ``-s0`` (glued),
        # ``--size N``, ``--size=0``.
        has_size = any(
            f == "-s" or f.startswith("-s")
            or f == "--size" or f.startswith("--size=")
            for f in flags
        )
        if has_size:
            targets = []
            skip_next = False
            seen_dd = False
            for a in args:
                if seen_dd:
                    if a.startswith("-s") and len(a) > 2 and not skip_next:
                        continue
                    if a == "-s" or a == "--size":
                        skip_next = True
                        continue
                    if a.startswith("--size="):
                        continue
                    if a.startswith("-") and a != "-":
                        continue
                    targets.append(a)
                    continue
                if skip_next:
                    skip_next = False
                    continue
                if a == "--":
                    seen_dd = True
                    continue
                if a == "-s" or a == "--size":
                    skip_next = True
                    continue
                if a.startswith("-s") and len(a) > 2:
                    continue
                if a.startswith("--size="):
                    continue
                if a.startswith("-"):
                    continue
                targets.append(a)
            if targets:
                return DestructiveAction(
                    command=cmd, targets=targets, flags=flags,
                    source="truncate — truncates file to zero or specified size",
                )

    # ── dd ───────────────────────────────────────────────────────────
    if cmd == "dd":
        targets = [a[3:] for a in args if a.startswith("of=")]
        if targets:
            return DestructiveAction(
                command=cmd, targets=targets, flags=flags,
                source="dd — writes to of= target, overwriting existing data",
            )

    # ── find ... -delete ─────────────────────────────────────────────
    if cmd == "find":
        if "-delete" in args:
            return DestructiveAction(
                command=cmd, targets=_find_search_paths(args), flags=flags,
                source="find -delete — deletes matched files",
            )
        # -exec / -execdir <cmd> — a deletion command run per match.
        for exec_flag in ("-exec", "-execdir"):
            if exec_flag in args:
                exec_idx = args.index(exec_flag)
                exec_cmd = args[exec_idx + 1] if exec_idx + 1 < len(args) else ""
                exec_cmd_base = _strip_path(exec_cmd)
                if exec_cmd_base in ("rm", "rmdir", "shred", "srm"):
                    return DestructiveAction(
                        command=cmd, targets=_find_search_paths(args), flags=flags,
                        source=f"find {exec_flag} {exec_cmd_base} — deletes matched files",
                    )

    # ── git clean -f / git reset --hard (honouring global options) ──
    # ``git`` accepts global options BEFORE the subcommand
    # (``git -C /path reset --hard``, ``git --work-tree=/ reset --hard``),
    # which hid the destructive subcommand from an args[0] check.
    if cmd == "git":
        subcommand, sub_args, git_dirs = _git_split(args)
        sub_flags, sub_non_flags = _parse_flags_targets(sub_args)

        if subcommand == "clean" and (
            "-f" in " ".join(sub_flags) or "--force" in " ".join(sub_flags)
        ):
            targets = _git_targets(git_dirs, sub_non_flags)
            return DestructiveAction(
                command=cmd, targets=targets, flags=sub_flags,
                source="git clean -f — removes untracked files (including .env, secrets)",
            )

        if subcommand == "reset" and "--hard" in sub_args:
            targets = _git_targets(git_dirs, sub_non_flags)
            return DestructiveAction(
                command=cmd, targets=targets, flags=sub_flags,
                source="git reset --hard — discards working tree changes",
            )

    return None


# Global git options (before the subcommand) that take a path we care
# about — the directory git will actually operate on.
_GIT_DIR_OPTS: set[str] = {"-C", "--work-tree", "--git-dir"}
# Global git options that consume a following argument.
_GIT_GLOBAL_OPTS_WITH_ARG: set[str] = {
    "-C", "-c", "--work-tree", "--git-dir", "--namespace",
    "--super-prefix", "--exec-path",
}


def _git_split(args: list[str]) -> tuple[str | None, list[str], list[str]]:
    """Split git args into (subcommand, sub_args, operative_dirs).

    Parses the global options that may appear before the subcommand,
    collecting any directory git is pointed at (``-C``, ``--work-tree``,
    ``--git-dir``) so a subcommand aimed outside the repo is still checked.
    """
    git_dirs: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            i += 1
            break
        if not a.startswith("-"):
            return a, args[i + 1:], git_dirs
        if "=" in a:
            key, val = a.split("=", 1)
            if key in _GIT_DIR_OPTS:
                git_dirs.append(val)
            i += 1
            continue
        if a in _GIT_GLOBAL_OPTS_WITH_ARG:
            val = args[i + 1] if i + 1 < len(args) else ""
            if a in _GIT_DIR_OPTS:
                git_dirs.append(val)
            i += 2
            continue
        i += 1
    return None, [], git_dirs


def _git_targets(git_dirs: list[str], sub_non_flags: list[str]) -> list[str]:
    """Resolve the paths a git clean/reset will hit.

    If git is pointed at an explicit directory (``-C``/``--work-tree``/
    ``--git-dir``), that directory is the operative target; otherwise the
    current repo (``.``) plus any explicit pathspecs.
    """
    if git_dirs:
        return git_dirs + sub_non_flags
    return sub_non_flags if sub_non_flags else ["."]


# ─────────────────────────────────────────────────────────────────────
# Tier 2: Risk warnings
# ─────────────────────────────────────────────────────────────────────


def identify_risks(tokens: list[str]) -> list[RiskWarning]:
    """Identify non-filesystem risks in a command.

    Returns a list of RiskWarning objects. These are NOT blocks —
    they are warnings that surface consequential actions the developer
    should be aware of.
    """
    if not tokens:
        return []

    tokens = _unwrap_wrappers(tokens)
    if not tokens:
        return []

    cmd = _strip_path(tokens[0])
    args = tokens[1:]
    flags, non_flags = _parse_flags_targets(args)
    full_cmd = " ".join(tokens)
    warnings: list[RiskWarning] = []

    # ── Package installation (arbitrary code execution) ────────────
    # Severity: medium for known PyPI packages (the common case),
    # high for git URLs or local paths (less trusted sources).
    if cmd in ("pip", "pip3", "python3", "python") and "install" in args:
        # python -m pip install, pip install, etc.
        if cmd in ("python", "python3") and "-m" in args:
            try:
                m_idx = args.index("-m")
                if m_idx + 1 < len(args) and args[m_idx + 1] in ("pip", "pip3"):
                    if "install" in args[m_idx + 2:]:
                        # Check if installing from a non-PyPI source
                        is_non_pypi = any(
                            a.startswith("git+") or a.startswith("/") or
                            a.startswith("./") or a.startswith("../") or
                            ".git" in a
                            for a in args
                        )
                        warnings.append(RiskWarning(
                            category="package",
                            command=full_cmd,
                            reason="pip install executes setup.py — "
                                   "arbitrary code runs on your machine",
                            severity="high" if is_non_pypi else "medium",
                        ))
            except (ValueError, IndexError):
                pass
        elif cmd in ("pip", "pip3"):
            is_non_pypi = any(
                a.startswith("git+") or a.startswith("/") or
                a.startswith("./") or a.startswith("../") or
                ".git" in a
                for a in args
            )
            warnings.append(RiskWarning(
                category="package",
                command=full_cmd,
                reason="pip install executes setup.py — "
                       "arbitrary code runs on your machine",
                severity="high" if is_non_pypi else "medium",
            ))

    if cmd in ("npm", "yarn", "pnpm") and "install" in args:
        warnings.append(RiskWarning(
            category="package",
            command=full_cmd,
            reason=f"{cmd} install runs postinstall scripts — "
                   "arbitrary code executes on your machine",
            severity="medium",
        ))

    if cmd == "cargo" and "install" in args:
        warnings.append(RiskWarning(
            category="package",
            command=full_cmd,
            reason="cargo install runs build scripts — arbitrary code execution",
            severity="medium",
        ))

    # ── Network requests (potential credential exfiltration) ───────
    if cmd in ("curl", "wget"):
        # Check for credential/header flags
        has_cred = any(
            a.startswith("-H") or a.startswith("--header")
            or "Authorization" in a or "Bearer" in a or "token" in a.lower()
            for a in args
        )
        # Check for $VAR patterns that might be secrets
        has_var = any("$" in a for a in args)
        if has_cred or has_var:
            warnings.append(RiskWarning(
                category="network",
                command=full_cmd,
                reason="network request with potential credentials — "
                       "data exfiltration risk. blastradius cannot inspect "
                       "what data is sent or where it goes",
                severity="high",
            ))
        else:
            warnings.append(RiskWarning(
                category="network",
                command=full_cmd,
                reason="network request — blastradius cannot inspect "
                       "what data is sent or where it goes",
                severity="medium",
            ))

    # ── Irreversible git operations ────────────────────────────────
    if cmd == "git":
        if "filter-branch" in args:
            warnings.append(RiskWarning(
                category="git",
                command=full_cmd,
                reason="git filter-branch rewrites history irreversibly — "
                       "all collaborators must re-clone",
                severity="high",
            ))
        if "push" in args and ("--force" in args or "-f" in flags):
            warnings.append(RiskWarning(
                category="git",
                command=full_cmd,
                reason="git push --force overwrites remote history — "
                       "collaborators' branches may be destroyed",
                severity="high",
            ))
        if "push" in args and not ("--force" in args or "-f" in flags):
            warnings.append(RiskWarning(
                category="git",
                command=full_cmd,
                reason="git push publishes commits to a remote — "
                       "difficult to undo if sensitive data is included",
                severity="medium",
            ))
        # git clean -x: ignores .gitignore, deletes .env and secrets
        if "clean" in args and ("-x" in args or "-fdx" in args or "-fx" in " ".join(args)):
            warnings.append(RiskWarning(
                category="git",
                command=full_cmd,
                reason="git clean -x ignores .gitignore — .env, secrets, "
                       "and local config WILL be deleted",
                severity="high",
            ))

    # ── Recursive permission changes ───────────────────────────────
    if cmd in ("chmod", "chown") and "-R" in args:
        target = non_flags[-1] if non_flags else "."
        warnings.append(RiskWarning(
            category="permission",
            command=full_cmd,
            reason=f"recursive {cmd} on {target} — changes permissions "
                   f"on entire directory tree, potential security impact",
            severity="high",
        ))

    # ── Irreversible publish ───────────────────────────────────────
    if cmd == "twine" and "upload" in args:
        warnings.append(RiskWarning(
            category="publish",
            command=full_cmd,
            reason="twine upload publishes to PyPI — irreversible. "
                   "Once published, the version name cannot be reused",
            severity="high",
        ))
    if cmd in ("npm", "yarn") and "publish" in args:
        warnings.append(RiskWarning(
            category="publish",
            command=full_cmd,
            reason=f"{cmd} publish is irreversible — the version name "
                   f"cannot be reused once published",
            severity="high",
        ))

    # ── Config / secret file access ────────────────────────────────
    # Only warn when the command WRITES to a config/secret file.
    # Reading (cat, less, head) is less dangerous — the secret stays
    # on the machine. Writing (echo >, sed -i, mv, cp) creates or
    # modifies a file that might be committed or deployed.
    config_indicators = [".env", "secrets", "credentials", "id_rsa",
                         ".pem", ".key"]
    write_cmds = {"echo", "sed", "cp", "mv", "tee", "dd", "cat"}
    # Detect if this is a write operation: redirect (>), sed -i,
    # cp/mv to a config file, tee, etc.
    is_write = (
        cmd in ("sed", "cp", "mv", "tee", "dd") or
        # echo > .env (redirect detected by > in full_cmd)
        (cmd == "echo" and ">" in full_cmd) or
        # cat > .env (redirect)
        (cmd == "cat" and ">" in full_cmd)
    )
    for indicator in config_indicators:
        if indicator in full_cmd and is_write:
            warnings.append(RiskWarning(
                category="config",
                command=full_cmd,
                reason=f"command writes to {indicator} — potential "
                       f"credential or secret file creation/modification",
                severity="high",
            ))
            break

    # ── Deployment target indicators ───────────────────────────────
    if "production" in full_cmd or "prod" in non_flags:
        if any(kw in full_cmd for kw in ["deploy", "kubectl", "terraform",
                                          "ansible", "helm", "docker"]):
            warnings.append(RiskWarning(
                category="deployment",
                command=full_cmd,
                reason="command targets production infrastructure — "
                       "changes are live and may affect users",
                severity="high",
            ))
    if "staging" in full_cmd and "production" in full_cmd:
        warnings.append(RiskWarning(
            category="deployment",
            command=full_cmd,
            reason="command changes staging to production — "
                   "verify this is intentional",
            severity="high",
        ))

    # ── Remote system access ───────────────────────────────────────
    if cmd in ("ssh", "scp", "rsync"):
        warnings.append(RiskWarning(
            category="network",
            command=full_cmd,
            reason=f"{cmd} accesses a remote system — blastradius "
                   f"cannot inspect what happens on the remote host",
            severity="medium",
        ))

    # ── Docker with host mounts ────────────────────────────────────
    if cmd == "docker" and "run" in args:
        if "-v" in args or "--volume" in args:
            warnings.append(RiskWarning(
                category="deployment",
                command=full_cmd,
                reason="docker run with -v mounts host paths into the "
                       "container — the container can modify host files",
                severity="medium",
            ))

    return warnings


__all__ = [
    "DestructiveAction",
    "RiskWarning",
    "identify_destructive",
    "identify_risks",
]
