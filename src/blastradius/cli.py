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
from .report import format_multi_refusal, format_refusal


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    if not argv:
        _print_help()
        return 0

    # Subcommands.
    if argv[0] == "hook":
        return _cmd_hook(argv[1:])
    if argv[0] == "install":
        return _cmd_install(argv[1:])
    if argv[0] == "--help" or argv[0] == "-h":
        _print_help()
        return 0
    if argv[0] == "--version":
        _print_version()
        return 0

    # Wrapper mode: blastradius -- <command...>
    if argv[0] == "--":
        return _cmd_wrapper(argv[1:])

    # If the first arg looks like a command (not a flag), treat the
    # whole thing as wrapper mode without the --.
    if not argv[0].startswith("-"):
        return _cmd_wrapper(argv)

    _print_help()
    return 2


# ─────────────────────────────────────────────────────────────────────
# Wrapper mode
# ─────────────────────────────────────────────────────────────────────


def _cmd_wrapper(command_args: list[str]) -> int:
    if not command_args:
        print("blastradius: no command given after --", file=sys.stderr)
        return 2

    # Reconstruct the command string. We join with spaces, but this
    # is only for display — the tokeniser re-parses it.
    command = " ".join(command_args)

    result = check_command(command)

    if result.allowed:
        # Exec the command. blastradius is replaced by the target process.
        # We use os.execvp so the command's stdout/stderr go directly
        # to the terminal, and its exit code becomes the process exit code.
        os.execvp(command_args[0], command_args)
        # execvp doesn't return on success.
        return 0  # unreachable

    # Refused — print the refusal and exit non-zero.
    if len(result.refusals) == 1:
        refusal, _ = result.refusals[0]
        print(format_refusal(refusal, command=command), file=sys.stderr)
    else:
        print(
            format_multi_refusal(result.refusals, command=command),
            file=sys.stderr,
        )
    return 1


# ─────────────────────────────────────────────────────────────────────
# Hook mode (Claude Code / Cursor PreToolUse)
# ─────────────────────────────────────────────────────────────────────


def _cmd_hook(_args: list[str]) -> int:
    """Read a PreToolUse payload from stdin, output a decision.

    Claude Code sends JSON on stdin:
      {"tool_name": "Bash", "tool_input": {"command": "rm -rf /tmp"}}

    We output JSON on stdout:
      {"decision": "block", "reason": "..."}  — block
      {} or nothing                           — allow

    Exit code 0 in both cases (the decision is in the JSON).
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
        # Allow — output nothing (or an empty allow decision).
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
  blastradius -- <command>          Wrapper mode: check then exec
  blastradius hook                  Hook mode: read PreToolUse JSON from stdin
  blastradius install --claude-code Install the Claude Code hook
  blastradius install --cursor      Install the Cursor hook
  blastradius --version             Print version
  blastradius --help                 Show this help

Wrapper mode:
  blastradius -- rm -rf /tmp/foo
  Checks the command. If allowed, execs it. If refused, prints the
  refusal and exits non-zero.

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
