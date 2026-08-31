#!/usr/bin/env python3
"""Codex PreToolUse bridge into the Docker-backed command executor."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path


EVAL_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = EVAL_DIR.parent
sys.path.insert(0, str(EVAL_DIR))
sys.path.insert(0, str(REPO_ROOT / "src"))

from runner.blast_intercept import intercept_command, to_dict
from runner.isolation import IsolatedExecutor, IsolationConfig


def _append_jsonl(path: str, value: dict) -> None:
    payload = (json.dumps(value, sort_keys=True) + "\n").encode()
    fd = os.open(path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
    try:
        os.write(fd, payload)
    finally:
        os.close(fd)


def _deny(reason: str) -> None:
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }))


def pre_tool_use(args: argparse.Namespace) -> int:
    event = json.load(sys.stdin)
    tool_name = event.get("tool_name", "")
    tool_input = event.get("tool_input") or {}
    cwd = event.get("cwd") or args.workspace

    if tool_name == "apply_patch":
        _append_jsonl(args.capture, {
            "captured_at_ns": time.time_ns(),
            "captured_before_execution": True,
            "tool_name": tool_name,
            "command": tool_input.get("command", ""),
            "cwd": cwd,
            "decision": "REFUSE",
            "reason": "This experiment routes writes through the isolated Bash pipeline.",
        })
        _deny("Use a Bash command so the write runs through the isolated command pipeline.")
        return 0

    if tool_name != "Bash":
        return 0

    command = tool_input.get("command")
    if not isinstance(command, str):
        _deny("Bash tool input did not contain a string command.")
        return 0

    blast_event = intercept_command(
        command,
        cwd,
        event.get("tool_use_id", "codex"),
    )
    capture = to_dict(blast_event)
    capture["captured_at_ns"] = time.time_ns()
    capture["captured_before_execution"] = True
    capture["tool_name"] = tool_name
    _append_jsonl(args.capture, capture)

    executor = IsolatedExecutor(IsolationConfig(workspace=args.workspace))
    result = executor.execute(command, cwd=cwd)
    _append_jsonl(args.ledger, executor.get_ledger()[-1])

    if blast_event.decision == "REFUSE":
        _deny(blast_event.reason)
        return 0

    if not result.executed:
        _deny(result.error or "The isolated executor could not start the command.")
        return 0

    context = (
        f"BlastRadius {blast_event.decision}; the command ran in the isolated "
        f"container with exit code {result.exit_code}."
    )
    if result.stdout:
        context += f" stdout: {result.stdout[:2000]}"
    if result.stderr:
        context += f" stderr: {result.stderr[:2000]}"
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
            "updatedInput": {"command": "/usr/bin/true"},
            "additionalContext": context,
        }
    }))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="operation", required=True)

    pre = subparsers.add_parser("pre-tool-use")
    pre.add_argument("--workspace", required=True)
    pre.add_argument("--capture", required=True)
    pre.add_argument("--ledger", required=True)
    pre.set_defaults(func=pre_tool_use)

    return parser


def main() -> int:
    args = build_parser().parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
