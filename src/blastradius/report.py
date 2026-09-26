"""Format refusals and warnings for terminal output.

v0.3.0: Three output modes:

  1. BLOCK — a filesystem-destruction target was refused. Prints the
     full refusal block (same format as before).

  2. WARN — the command was allowed but contains consequential
     non-filesystem actions. Prints a yellow warning block listing
     each risk category.

  3. ALLOWED — the command was allowed with no warnings. Prints a
     one-line summary so the developer knows the check ran and what
     scope it covered. Silence is never the output.
"""

from __future__ import annotations

from .commands import RiskWarning
from .resolve import Refusal


# Rules that cannot be overridden by any configuration.
_UNOVERRIDABLE = {
    "floor-path",
    "empty-variable-expansion",
    "tilde-ambiguous",
    "empty-target",
    "unresolvable-expansion",
}


def format_refusal(refusal: Refusal, *, command: str) -> str:
    """Format a single refusal for terminal output."""
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
    """Format multiple refusals for terminal output."""
    if not refusals:
        return ""

    if len(refusals) == 1:
        return format_refusal(refusals[0][0], command=command)

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


def format_warnings(warnings: list[RiskWarning], *, command: str) -> str:
    """Format risk warnings for terminal output.

    Warnings are printed when the command is allowed but contains
    consequential non-filesystem actions.
    """
    if not warnings:
        return ""

    lines: list[str] = []
    lines.append("blastradius  WARNING")
    lines.append("")
    lines.append(f"  command   {command}")
    lines.append("")

    # Deduplicate by category+reason.
    seen = set()
    unique: list[RiskWarning] = []
    for w in warnings:
        key = (w.category, w.reason)
        if key not in seen:
            seen.add(key)
            unique.append(w)

    for w in unique:
        sev_marker = "⚠" if w.severity == "high" else "·"
        lines.append(f"  {sev_marker} [{w.category}] {w.reason}")
    lines.append("")
    lines.append(f"  blastradius  ALLOWED — {len(unique)} warning(s), not blocked.")
    lines.append("  Filesystem-destruction targets were checked; the warnings")
    lines.append("  above are informational. Review before proceeding.")
    lines.append("")

    return "\n".join(lines)


def format_allowed(*, command: str, warnings: list[RiskWarning]) -> str:
    """Format the ALLOWED summary.

    If there are warnings, formats a WARNING block.
    If there are no warnings, formats a one-line ALLOWED summary
    with the warning count (always 0 in this case).
    """
    if warnings:
        return format_warnings(warnings, command=command)

    # No warnings — one-line summary with count.
    return f"blastradius  ALLOWED — 0 warnings, filesystem-destruction check only\n  command   {command}\n"


__all__ = [
    "format_refusal",
    "format_multi_refusal",
    "format_warnings",
    "format_allowed",
]
