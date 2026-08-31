"""blastradius CLI.

Three modes:

  1. Wrapper mode:  blastradius -- rm -rf /tmp/foo
     Checks the command. If allowed, execs it. If refused, prints
     the refusal and exits non-zero.

  2. Hook mode:     blastradius hook
     Reads a Claude Code PreToolUse JSON payload from stdin, checks
     the Bash command, outputs a decision JSON on stdout.

  3. Install mode:  blastradius install --claude-code
     Writes the hook config to .claude/settings.json (or ~/.claude/
     with --global).
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from .check import check_command
from .report import format_allowed, format_multi_refusal, format_refusal, format_warnings


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    if not argv:
        _print_help()
        return 0

    # Parse global flags that can appear before the command.
    strict = False
    quiet = False
    rest: list[str] = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--strict":
            strict = True
        elif a == "--quiet":
            quiet = True
        elif a == "--help" or a == "-h":
            _print_help()
            return 0
        elif a == "--version":
            _print_version()
            return 0
        else:
            rest.append(a)
        i += 1

    # Subcommands.
    if rest and rest[0] == "hook":
        return _cmd_hook(rest[1:], strict=strict)
    if rest and rest[0] == "install":
        return _cmd_install(rest[1:])

    # Wrapper mode: blastradius [--strict] [--quiet] -- <command...>
    if rest and rest[0] == "--":
        return _cmd_wrapper(rest[1:], strict=strict, quiet=quiet)

    # If the first remaining arg looks like a command (not a flag),
    # treat the whole thing as wrapper mode without the --.
    if rest and not rest[0].startswith("-"):
        return _cmd_wrapper(rest, strict=strict, quiet=quiet)

    _print_help()
    return 2


# ─────────────────────────────────────────────────────────────────────
# Wrapper mode
# ─────────────────────────────────────────────────────────────────────


def _cmd_wrapper(command_args: list[str], *, strict: bool = False, quiet: bool = False) -> int:
    if not command_args:
        print("blastradius: no command given after --", file=sys.stderr)
        return 2

    # Reconstruct the command string.
    command = " ".join(command_args)

    result = check_command(command)

    # ── In strict mode, warnings become blocks ─────────────────────
    if strict and result.has_warnings and result.allowed:
        # Print the warnings, then block
        print(format_warnings(result.warnings, command=command), file=sys.stderr)
        print("  --strict is set: warnings are treated as blocks.", file=sys.stderr)
        print("  Remove --strict to allow this command, or fix the warnings.", file=sys.stderr)
        return 1

    # ── Print output ────────────────────────────────────────────────
    if result.allowed:
        if result.has_warnings:
            # Warnings are always shown, even in --quiet mode.
            print(format_warnings(result.warnings, command=command), file=sys.stderr)
        else:
            # The ALLOWED summary is suppressed in --quiet mode.
            if not quiet:
                print(format_allowed(command=command, warnings=result.warnings),
                      file=sys.stderr)

        # Exec the command.
        try:
            os.execvp(command_args[0], command_args)
        except FileNotFoundError:
            print(f"blastradius: command not found: {command_args[0]}", file=sys.stderr)
            return 127
        except PermissionError:
            print(f"blastradius: permission denied: {command_args[0]}", file=sys.stderr)
            return 126
        return 0  # unreachable

    # Refused.
    if len(result.refusals) == 1:
        refusal, _ = result.refusals[0]
        print(format_refusal(refusal, command=command), file=sys.stderr)
    else:
        print(format_multi_refusal(result.refusals, command=command), file=sys.stderr)
    return 1


# ─────────────────────────────────────────────────────────────────────
# Hook mode (Claude Code / Cursor PreToolUse)
# ─────────────────────────────────────────────────────────────────────


def _cmd_hook(_args: list[str], *, strict: bool = False) -> int:
    """Read a PreToolUse payload from stdin, output a decision.

    In strict mode, warnings are treated as blocks — the hook returns
    {"decision": "block"} for any command that has warnings.
    """
    try:
        raw_input = sys.stdin.read()
        payload = json.loads(raw_input)
    except (json.JSONDecodeError, OSError):
        # Can't parse — fail closed.
        print(json.dumps({
            "decision": "block",
            "reason": "blastradius: could not parse hook input",
        }))
        return 0

    tool_name = payload.get("tool_name", "")
    if tool_name != "Bash":
        # Not a Bash command — allow (blastradius only guards shell).
        return 0

    tool_input = payload.get("tool_input", {})
    command = tool_input.get("command", "")

    if not command:
        return 0

    result = check_command(command)

    if result.allowed:
        # In strict mode, warnings become blocks.
        if strict and result.has_warnings:
            warning_text = format_warnings(result.warnings, command=command)
            print(json.dumps({
                "decision": "block",
                "reason": warning_text + "\n  --strict is set: warnings are treated as blocks.",
            }))
            return 0

        # Allow — but if there are warnings, surface them.
        if result.has_warnings:
            warning_text = format_warnings(result.warnings, command=command)
            print(json.dumps({
                "decision": "allow",
                "reason": warning_text,
            }))
        return 0

    # Block — output the decision JSON.
    if len(result.refusals) == 1:
        refusal, _ = result.refusals[0]
        reason_text = format_refusal(refusal, command=command)
    else:
        reason_text = format_multi_refusal(result.refusals, command=command)

    print(json.dumps({
        "decision": "block",
        "reason": reason_text,
    }))
    return 0


# ─────────────────────────────────────────────────────────────────────
# Install mode
# ─────────────────────────────────────────────────────────────────────


def _cmd_install(args: list[str]) -> int:
    """Install the hook config for Claude Code or Cursor."""
    from .hooks import install_claude_code_hook, install_cursor_hook

    target = args[0] if args else ""

    if target in ("--claude-code", "claude-code"):
        global_install = "--global" in args
        return install_claude_code_hook(global_install=global_install)
    elif target in ("--cursor", "cursor"):
        global_install = "--global" in args
        return install_cursor_hook(global_install=global_install)
    else:
        print("Usage: blastradius install --claude-code [--global]", file=sys.stderr)
        print("       blastradius install --cursor [--global]", file=sys.stderr)
        return 2


# ─────────────────────────────────────────────────────────────────────
# Help
# ─────────────────────────────────────────────────────────────────────


def _print_help() -> None:
    print(
        """blastradius — a deterministic guard between AI agents and the shell.

Usage:
  blastradius [flags] -- <command>   Wrapper mode: check then exec
  blastradius hook [flags]            Hook mode: read PreToolUse JSON from stdin
  blastradius install --claude-code   Install the Claude Code hook
  blastradius install --cursor        Install the Cursor hook
  blastradius --version               Print version
  blastradius --help                   Show this help

Flags:
  --strict    Treat warnings as blocks. A command with any warning
              (pip install, curl, git push, etc.) is refused.
              Useful for high-security environments or CI gates.
  --quiet     Suppress the ALLOWED summary on safe commands.
              Warnings and blocks are still printed.

Wrapper mode:
  blastradius -- rm -rf /tmp/foo
  blastradius --strict -- pip install stripe
  blastradius --quiet -- ls -la

  Checks the command. If allowed, execs it. If refused, prints the
  refusal and exits non-zero. Warnings are printed to stderr but
  do not block unless --strict is set.

Hook mode:
  Reads a JSON payload from stdin (Claude Code PreToolUse format),
  checks the Bash command, and outputs a decision JSON on stdout.

The floor rules (/, $HOME, /etc, /usr, etc.) cannot be overridden
by any configuration. Scope comes from .blastradius in the repo root.
"""
    )


def _print_version() -> None:
    from . import __version__
    print(f"blastradius {__version__}")


if __name__ == "__main__":
    sys.exit(main())
