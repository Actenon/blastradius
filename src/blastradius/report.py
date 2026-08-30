"""Format refusals for terminal output.

Matches the format specified in the design brief:

    blastradius  BLOCKED

      command   rm -rf "$AGENT_TMP/session-$SID"
      resolved  /

      reason    AGENT_TMP is unset — expansion produced an empty string
                SID is unset
                target resolved to filesystem root

      rule      empty-variable-expansion (cannot be overridden)

      If this is intentional, run it yourself outside the agent.
"""

from __future__ import annotations

from .resolve import Refusal


# Rules that cannot be overridden by any configuration.
_UNOVERRIDABLE = {
    "floor-path",
    "empty-variable-expansion",
    "tilde-ambiguous",
    "empty-target",
}


def format_refusal(refusal: Refusal, *, command: str) -> str:
    """Format a refusal for terminal output."""
    lines: list[str] = []
    lines.append("blastradius  BLOCKED")
    lines.append("")
    lines.append(f"  command   {command}")

    if refusal.resolved:
        lines.append(f"  resolved  {refusal.resolved}")
    else:
        lines.append("  resolved  (unresolvable)")

    lines.append("")
    lines.append(f"  reason    {refusal.reason}")

    suffix = " (cannot be overridden)" if refusal.rule in _UNOVERRIDABLE else ""
    lines.append("")
    lines.append(f"  rule      {refusal.rule}{suffix}")

    lines.append("")
    lines.append("  If this is intentional, run it yourself outside the agent.")
    lines.append("")

    return "\n".join(lines)


def format_multi_refusal(refusals: list[tuple[Refusal, str]], *, command: str) -> str:
    """Format multiple refusals (one per target) for terminal output.

    Shows the first refusal in detail, then summarises the rest.
    """
    if not refusals:
        return ""

    if len(refusals) == 1:
        return format_refusal(refusals[0][0], command=command)

    # Multiple refusals — show the command, then each target's refusal.
    lines: list[str] = []
    lines.append("blastradius  BLOCKED")
    lines.append("")
    lines.append(f"  command   {command}")
    lines.append("")
    lines.append(f"  {len(refusals)} target(s) refused:")
    lines.append("")

    for refusal, _ in refusals:
        lines.append(f"    target   {refusal.raw}")
        if refusal.resolved:
            lines.append(f"    resolved {refusal.resolved}")
        lines.append(f"    reason   {refusal.reason}")
        suffix = " (cannot be overridden)" if refusal.rule in _UNOVERRIDABLE else ""
        lines.append(f"    rule     {refusal.rule}{suffix}")
        lines.append("")

    lines.append("  If this is intentional, run it yourself outside the agent.")
    lines.append("")

    return "\n".join(lines)


__all__ = ["format_refusal", "format_multi_refusal"]
