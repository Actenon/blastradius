"""Hook installers for Claude Code and Cursor.

Claude Code hooks are configured in .claude/settings.json (project)
or ~/.claude/settings.json (global). The PreToolUse hook fires before
a tool is used and can block.

Cursor hooks are configured in .cursor/hooks.json (project) or
~/.cursor/hooks.json (global).

The installer is idempotent — it doesn't duplicate the hook if already
present. It writes a backup of the existing config before modifying.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path


# The hook command that Claude Code will run.
# It reads the PreToolUse JSON from stdin and outputs a decision.
_CLAUDE_CODE_HOOK_COMMAND = "blastradius hook"

# The matcher for Bash tool uses.
_CLAUDE_CODE_MATCHER = "Bash"


def _read_json(path: Path) -> dict:
    """Read a JSON file, returning {} if it doesn't exist or is invalid."""
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def _write_json(path: Path, data: dict) -> None:
    """Write JSON to a file, creating parent dirs."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def _backup(path: Path) -> None:
    """Create a .bak copy of a file if it exists."""
    if path.exists():
        backup_path = path.with_suffix(path.suffix + ".bak")
        backup_path.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")


def install_claude_code_hook(*, global_install: bool = False) -> int:
    """Install the PreToolUse hook for Claude Code.

    Writes to .claude/settings.json (project) or ~/.claude/settings.json
    (global). Idempotent — doesn't duplicate the hook if already present.
    """
    if global_install:
        config_path = Path.home() / ".claude" / "settings.json"
    else:
        config_path = Path.cwd() / ".claude" / "settings.json"

    config = _read_json(config_path)

    # Back up the existing config.
    if config_path.exists():
        _backup(config_path)

    # Ensure hooks structure exists.
    hooks = config.setdefault("hooks", {})
    pre_tool_use = hooks.setdefault("PreToolUse", [])

    # Check if our hook is already present.
    already_installed = False
    for entry in pre_tool_use:
        if not isinstance(entry, dict):
            continue
        if entry.get("matcher") == _CLAUDE_CODE_MATCHER:
            hook_list = entry.get("hooks", [])
            for h in hook_list:
                if isinstance(h, dict) and h.get("command", "").startswith("blastradius"):
                    already_installed = True
                    break

    if already_installed:
        print(f"blastradius hook already installed in {config_path}")
        return 0

    # Add our hook entry.
    pre_tool_use.append({
        "matcher": _CLAUDE_CODE_MATCHER,
        "hooks": [
            {
                "type": "command",
                "command": _CLAUDE_CODE_HOOK_COMMAND,
            }
        ],
    })

    _write_json(config_path, config)
    print(f"blastradius hook installed in {config_path}")
    print(f"  matcher: {_CLAUDE_CODE_MATCHER}")
    print(f"  command: {_CLAUDE_CODE_HOOK_COMMAND}")
    return 0


def install_cursor_hook(*, global_install: bool = False) -> int:
    """Install the pre-execution hook for Cursor.

    Cursor's hook format is different from Claude Code's. This is a
    placeholder — Cursor's hook API is less documented and may require
    a different approach. For now, we write a .cursor/hooks.json that
    Cursor can read if it supports this format.
    """
    if global_install:
        config_path = Path.home() / ".cursor" / "hooks.json"
    else:
        config_path = Path.cwd() / ".cursor" / "hooks.json"

    config = _read_json(config_path)

    if config_path.exists():
        _backup(config_path)

    # Cursor hook format (best-effort — may need adjustment).
    hooks = config.setdefault("hooks", [])
    already_installed = any(
        isinstance(h, dict) and h.get("command", "").startswith("blastradius")
        for h in hooks
    )

    if already_installed:
        print(f"blastradius hook already installed in {config_path}")
        return 0

    hooks.append({
        "event": "preCommand",
        "command": _CLAUDE_CODE_HOOK_COMMAND,
    })

    _write_json(config_path, config)
    print(f"blastradius hook installed in {config_path}")
    print("  Note: Cursor hook support is experimental. Verify the hook")
    print("  fires correctly in your Cursor version.")
    return 0


__all__ = ["install_claude_code_hook", "install_cursor_hook"]
