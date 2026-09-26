# blastradius

> A deterministic guard between AI agents and the shell. It runs at the moment of execution, after all reasoning has finished, and it is the last thing between an agent and `rm -rf $HOME`.

## The incident

August 2026. A developer asked Claude Fable to write a script sandboxing agents under `/tmp` with automatic cleanup. Because the script involved hard deletion, the model ran an adversarial self-review. Anthropic's harness then downgraded the model twice, to Opus 5 and then Opus 4.8, on safety grounds.

**Opus 4.8 correctly identified the home directory as dangerous.** It then deleted it anyway, because the safety test and the cleanup step reused the same variable name. 700GB and a week of work, gone.

Every safety layer worked. The reasoning was correct. The harm happened anyway — a variable collision at execution time. No amount of better judgement prevents that.

This is not isolated. Six public incidents in ten months, one failure class:

| Date | Incident | What happened |
|------|----------|---------------|
| Aug 2026 | Guillemot | Variable collision: safety test and cleanup reused the same variable. `rm -rf "$CLEANUP_DIR"` with CLEANUP_DIR unset → deleted 700GB home directory. |
| Apr 2026 | [Claude Code #49464](https://github.com/anthropics/claude-code/issues/49464) | `rm -f ~/` — cleaning a file literally named `~`. Shell expanded `~` to `$HOME`. |
| Nov 2025 | [Claude Code #12637](https://github.com/anthropics/claude-code/issues/12637) | Glob expansion caught a directory named `~`. |
| Oct 2025 | [Claude Code #10077](https://github.com/anthropics/claude-code/issues/10077) | `rm -rf $HOME` — direct home directory deletion. |
| Dec 2025 | Mac wipe | `rm -rf ~/Library` — wiped Mac including Keychain. |
| Aug 2026 | Backup typo | `rm -rf $HOME/ .profile` — extra space made rm target `$HOME/` instead of `$HOME/.profile`. Model replied "Sorry, typo." |

Every one of these is a variable resolution or tilde expansion failure. Every one is preventable by checking the resolved target before execution — not by better reasoning, but by deterministic code.

## What this does

```
$ blastradius -- rm -rf "$AGENT_TMP/session-$SID"

blastradius  BLOCKED

  command   rm -rf "$AGENT_TMP/session-$SID"
  resolved  /

  reason    AGENT_TMP is unset — expansion produced an empty string
            SID is unset
            target resolved to filesystem root

  rule      empty-variable-expansion (cannot be overridden)

  If this is intentional, run it yourself outside the agent.
```

That is the Guillemot pattern, refused. The variable was unset. The expansion produced an empty string. The target resolved to root. The guard refused.

## Three principles

**1. Never consult a model.** This is deterministic code. No LLM call, no network, no heuristics that "usually" work. The premise of the product is that model judgement already failed — adding more of it is the one thing that cannot help. Zero latency, no API dependency.

**2. Fail closed.** If the target cannot be resolved with certainty — unparseable syntax, command substitution, an unset variable, a glob that can't be evaluated — **refuse**. A guard that permits when confused is worse than no guard, because it manufactures confidence.

**3. Refusals are legible.** Always print the resolved absolute path and the specific rule that fired. A block the user doesn't understand becomes an uninstall.

## How it works

```
blastradius -- rm -rf "$TMPDIR/session-123"
```

The pipeline:

1. **Tokenise** — one quote-aware lexer splits the command into simple commands on `;`, `&&`, `||`, `|`, `|&` and `&`, removes output/input redirections from each command's arguments, and performs brace expansion (`{a,b}`, `{1..3}`). It refuses `$(...)` and backticks (also inside double quotes), `<(...)`/`>(...)`, `eval`, unquoted `(`/`)`, newlines, unterminated quotes and `${...}` containing quotes. If we can't fully model it, we refuse.

2. **Identify** — is this a destructive command? `rm`, `rmdir`, `unlink`, `shred`, `truncate`, `dd`, `tee` (without `-a`), `find -delete`, `find -exec/-execdir rm`, `find -fprint/-fprintf/-fls`, `git clean -f`, `git reset --hard`. If not destructive, allow (blastradius only guards filesystem destruction). Before identifying:
   - Leading `NAME=value` assignments and shell reserved words (`!`, `{`, `then`, `do`, …) are skipped, and a `$VAR` command name is expanded (refused if it cannot be).
   - Command-runner wrappers (`sudo`, `doas`, `env`, `nice`, `nohup`, `timeout`, `chrt`, `taskset`, `flock`, `watch`, `chroot`, `systemd-run`, `nsenter`, `unshare`, `firejail`, `strace`, `fakeroot`, `busybox`, …) are unwrapped. If a wrapper's options do not lead to a known command, the remaining words are scanned for the first destructive command. This can refuse a harmless wrapped command that merely mentions one (`sudo grep -r rm /etc`); that false positive is accepted. Directories a wrapper switches to (`sudo -D`, `env -C`, `chroot`, `systemd-run`) are judged too.
   - Inner command strings — `sh/bash/zsh/dash/ksh/mksh/ash -c STR`, `env -S STR`, `su/runuser/script/flock -c STR`, `sg GROUP STR`, `watch STR`, `eval ARGS`, a here-string fed to a shell, `find -exec sh -c STR`, `xargs sh -c STR` — are checked recursively with the same cwd, environment and scope. A block inside becomes a block outside, carrying the inner rule. Nesting is capped (`recursion-depth`).
   - A destructive command run by `xargs`/`parallel` also receives targets from stdin, so it is refused (`stdin-targets`).
   - `git` global options (`-C`, `--work-tree`, `--git-dir`) before the subcommand are honoured.
   - Across `;`/`&&`/`||`, assignments (`X=/etc; …`, `export`, `unset`, `read`) and `cd`/`pushd` carry into later commands; after `source`, `popd` or an unresolvable `cd`, the directory is unknown and destructive commands are refused (`ambiguous-cwd`).

3. **Resolve** — for each target argument:
   - Expand `$VAR` and `${VAR}` against the real environment.
   - If any variable is unset or empty → **refuse** (`empty-variable-expansion`). This is the Guillemot rule.
   - Only `$VAR` and `${VAR}` are modelled. Any other expansion left in the target — `${VAR:-default}`, `${VAR:=x}`, `${#VAR}`, `${VAR%pattern}`, `$1`, `$$`, `$@` — cannot be resolved with certainty, so → **refuse** (`unresolvable-expansion`). Fail closed.
   - If the target starts with `~` → **refuse** (`tilde-ambiguous`). Tilde means both "home directory" and "a file literally called tilde." Require an explicit absolute path.
   - Expand globs against the real filesystem from the correct CWD.
   - Canonicalise: resolve `..`, resolve symlinks, produce an absolute real path.

4. **Judge** — check each resolved path against:
   - **Floor rules** (unoverridable): `/`, `$HOME`, `/home`, `/Users`, `/etc`, `/usr`, `/bin`, `/sbin`, `/var`, `/System`, `/Library`, and any path at depth ≤ 1 from root. No configuration can override these.
   - **Scope**: from `.blastradius` in the repo root, or defaults (repo root, `/tmp/**`, `$TMPDIR/**`, build dirs).
   - **Glob breadth**: a glob that expands to more than 100 entries, or matches anything at repo root level, is refused even inside scope.

5. **Redirections** — an output redirection that truncates (`>`, `>|`, `&>`, `N>`, `>&file`) is judged exactly like a `truncate` target, with the same floor, scope, tilde and expansion rules, so `: > /etc/passwd` is refused. Appends (`>>`), fd duplications (`2>&1`, `>&2`) and `/dev/null`, `/dev/stdout`, `/dev/stderr`, `/dev/tty`, `/dev/fd/N` are exempt. Redirections are never treated as `rm` targets.

6. **Report** — if any target is refused, print the refusal and exit non-zero. If all targets pass, exec the command.

## Installation

### Claude Code hook (recommended)

```bash
pip install actenon-blastradius
blastradius install --claude-code
```

This writes a `PreToolUse` hook to `.claude/settings.json` that fires before every Bash command. Destructive commands whose resolved target falls outside scope are blocked before execution.

For a global install (all projects):

```bash
blastradius install --claude-code --global
```

### Wrapper mode (any agent, any harness)

```bash
pip install actenon-blastradius
blastradius -- rm -rf /tmp/foo
```

Works with any agent, any CI, any harness. Checks the command; if allowed, execs it; if refused, prints the block and exits non-zero.

### Zero-install

```bash
uvx actenon-blastradius -- rm -rf /tmp/foo
```

No install needed. `uvx` runs the latest published version. The PyPI package name is `actenon-blastradius` (the `blastradius` name was taken by an unrelated Terraform tool); the command is still `blastradius`.

## Configuration

Create a `.blastradius` file in your repo root:

```
# blastradius scope config
allow /tmp/**
allow ./build/**
allow ./node_modules
allow <repo>/dist
deny ./secrets/**
```

- `allow <pattern>` — paths matching this pattern are allowed (if they pass the floor rules).
- `deny <pattern>` — paths matching this pattern are always refused, even if also matched by an allow entry.
- `<repo>` expands to the git repo root.
- `**` matches any number of path components.
- Lines starting with `#` are comments.

If no `.blastradius` file exists, the defaults are:

- `<git repo root>/**`
- `/tmp/**`
- `$TMPDIR/**`
- `<repo>/build`, `dist`, `target`, `.venv`, `node_modules`, `__pycache__`, `.pytest_cache`, `.mypy_cache`, `.ruff_cache`, `.tox`, `.eggs`, `htmlcov`

Most people never need to write a config.

## The floor rules cannot be overridden

The following paths are **always refused**, regardless of scope, config, flags, or environment variables:

- `/` (root)
- `$HOME` (your home directory)
- `/home`, `/Users`
- `/etc`, `/usr`, `/bin`, `/sbin`, `/lib`, `/lib64`
- `/var`, `/var/lib`, `/var/log`
- `/System`, `/Library` (macOS)
- `/opt`, `/root`, `/boot`, `/dev`, `/proc`, `/sys`
- Any path at depth ≤ 1 from root (e.g. `/tmp`, `/foo`)

There is no flag, no config entry, and no environment variable that can make these deletable. This is intentional. A config option to delete your home directory will be found and used by an agent.

## What it refuses to model

`;`, `&&`, `||`, `|`, `|&` and `&` are split, and every simple command is checked (a compound command is blocked if any part is). blastradius refuses to parse commands containing:

- `$(...)` or backticks (command substitution), including inside double quotes
- `<(...)` or `>(...)` (process substitution)
- `eval` as the whole command (elsewhere its arguments are checked as a command string)
- Unquoted `(` or `)` anywhere (subshells, function definitions, `case` patterns, arithmetic)
- Newlines, unterminated quotes, `${...}` containing quotes or nested expansions, and brace expansions producing more than 1024 words

This is a feature, not a limitation. If we can't fully model what the command will do, we refuse it. The user can run it themselves outside the agent — the guard is for the agent path, not the human path.

## Rule reference

Every refusal names a rule ID:

| Rule | When it fires | Overridable? |
|------|---------------|--------------|
| `floor-path` | Target is root, home, system dir, or depth ≤ 1 from root | No |
| `empty-variable-expansion` | A `$VAR` in the target is unset or empty | No |
| `tilde-ambiguous` | Target starts with `~` | No |
| `empty-target` | Target is an empty string after expansion | No |
| `unresolvable-expansion` | Target uses an expansion beyond `$VAR`/`${VAR}` (e.g. `${VAR:-/}`, `$1`, `$$`) | No |
| `out-of-scope` | Target is outside the allowed scope | Yes (via `.blastradius`) |
| `glob-no-match` | Glob pattern matched no files | No |
| `glob-breadth` | Glob expanded to >100 entries or matched repo-root-level files | Yes (via config) |
| `stdin-targets` | Destructive command run by `xargs`/`parallel` (targets arrive on stdin) | No |
| `ambiguous-cwd` | Destructive command or truncating redirection after a directory change that cannot be resolved | No |
| `recursion-depth` | Inner command strings nested beyond the modelling depth | No |
| `no-targets` | Destructive command with no targets | No |
| `unparseable-command-*` | Command contains `$()`, backticks, `<()`, `eval`, unquoted `(`, a newline, an unterminated quote, etc. | No |

## Limitations

- **Not a sandbox.** blastradius refuses destructive commands; it does not prevent an agent from writing files, executing code, or making network calls. It guards one failure class: destructive filesystem deletion.
- **Interpreters and scripts are not modelled.** `python -c`, `perl -e`, `node -e`, `ruby -e`, `bash script.sh`, a shell reading commands from a pipe or a file (`curl … | sh`, `sh < file`), `git -c alias.x='!…'`, and aliases or functions already defined in the user's shell run code blastradius cannot see. They are allowed, not refused.
- **Only the listed commands are destructive.** Tools that overwrite files by other means (`cp`, `mv`, `install`, `rsync --delete`, `sed -i`, `sort -o`, `curl -o`, `strace -o`, `chmod -R`, `chown -R`, `mkfs`) are not judged.
- **Time of check vs time of use.** Paths are resolved when the command is checked; a symlink or directory swapped between the check and the exec is not re-checked.
- **Wrapper false positives.** After a wrapper, the fallback scan can refuse a harmless command that mentions a destructive one as an argument (`sudo grep -r rm /etc`).
- **Positional parameters are not modelled.** `sh -c 'rm -rf "$1"' _ build` is refused, because `$1` inside the string is not resolved.
- **No Windows path support beyond basic detection.** The floor list includes `C:\Windows` and `C:\Users`, but glob expansion and canonicalisation are POSIX-oriented.
- **No daemon, no GUI, no telemetry.** It is a single command that checks and execs (or refuses). Nothing else.

## Tech

- Python 3.10+
- Zero runtime dependencies
- Sub-millisecond decision time (well under the 10ms target)
- 342 tests, including all six reconstructed incidents, wrapper/expansion and shell-semantics bypass suites, and a full must-allow suite

## License

Apache-2.0
