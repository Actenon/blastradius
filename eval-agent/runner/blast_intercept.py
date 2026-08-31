"""BlastRadius interception layer.

Intercepts every shell command the agent attempts and runs it through
BlastRadius. Records the decision, resolved targets, and tier.

This module NEVER judges BlastRadius using BlastRadius itself —
the independent instrumentation module records actual effects separately.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Ensure blastradius is importable
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))


@dataclass
class BlastRadiusEvent:
    """A single BlastRadius interception event."""
    timestamp: str
    command: str
    cwd: str
    agent_task_id: str
    decision: str  # ALLOW, WARN, REFUSE, UNKNOWN
    resolved_targets: list[str] = field(default_factory=list)
    reason: str = ""
    tier: str = ""  # "deterministic" or "heuristic"
    warnings: list[dict[str, str]] = field(default_factory=list)
    raw_output: str = ""


def intercept_command(
    command: str,
    cwd: str,
    agent_task_id: str,
) -> BlastRadiusEvent:
    """Run a command through BlastRadius and return the interception event.

    This does NOT execute the command. It only checks it.
    """
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    # Run blastradius in check-only mode (don't exec)
    # We use the Python API directly for speed.
    try:
        from blastradius.check import check_command
        result = check_command(command, cwd=cwd)

        if result.blocked:
            decision = "REFUSE"
            tier = "deterministic"
            reason = result.first_refusal.reason if result.first_refusal else "blocked"
            resolved = [r.resolved or "" for r, _ in result.refusals]
            raw = f"BLOCKED: {reason}"
        elif result.has_warnings:
            decision = "WARN"
            tier = "heuristic"
            reason = "; ".join(w.reason for w in result.warnings)
            resolved = []
            raw = f"WARNED: {reason}"
        else:
            decision = "ALLOW"
            tier = "deterministic"
            reason = ""
            resolved = []
            raw = "ALLOWED"

        warnings = [
            {"category": w.category, "reason": w.reason, "severity": w.severity}
            for w in result.warnings
        ]

    except Exception as e:
        decision = "UNKNOWN"
        tier = ""
        reason = f"blastradius error: {e}"
        resolved = []
        raw = f"ERROR: {e}"
        warnings = []

    return BlastRadiusEvent(
        timestamp=timestamp,
        command=command,
        cwd=cwd,
        agent_task_id=agent_task_id,
        decision=decision,
        resolved_targets=resolved,
        reason=reason,
        tier=tier,
        warnings=warnings,
        raw_output=raw,
    )


def create_hook(agent_task_id: str) -> callable:
    """Create a hook function that intercepts commands through BlastRadius.

    The hook returns None to block the command, or the command string
    to allow it. Blocked commands are recorded but not executed.
    """
    events: list[BlastRadiusEvent] = []

    def hook(command: str, cwd: str) -> str | None:
        event = intercept_command(command, cwd, agent_task_id)
        events.append(event)

        # In REFUSE mode, return None to block.
        # In WARN mode, return the command to allow.
        # In ALLOW mode, return the command to allow.
        if event.decision == "REFUSE":
            return None  # block
        return command  # allow

    hook.events = events  # type: ignore[attr-defined]
    return hook


def to_dict(event: BlastRadiusEvent) -> dict:
    return {
        "timestamp": event.timestamp,
        "command": event.command,
        "cwd": event.cwd,
        "agent_task_id": event.agent_task_id,
        "blastradius_result": {
            "decision": event.decision,
            "resolved_targets": event.resolved_targets,
            "reason": event.reason,
            "tier": event.tier,
            "warnings": event.warnings,
        },
    }
