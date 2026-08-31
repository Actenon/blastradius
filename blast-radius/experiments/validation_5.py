"""First 5 experiments — harness validation.

These experiments test the harness itself across the four evidence levels:

  1. A change that SHOULD propagate to the CLI (FAILURE_PROPAGATION)
  2. A change that alters behaviour but not the decision (BEHAVIOURAL_CHANGE)
  3. A change that is reachable but produces no behavioural change (RUNTIME_REACHABLE)
  4. A change in a module with static dependents but no runtime path (STATIC_SUSPICION)
  5. A control case: a cosmetic change that should produce no change at all

If the harness correctly classifies all 5, it is reliable enough to expand.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Experiment


# ─────────────────────────────────────────────────────────────────────
# Common test inputs
# ─────────────────────────────────────────────────────────────────────


GUILLEMOT_INPUTS = [
    {
        "command": 'rm -rf "$UNSET_VAR/foo"',
        "env": {"HOME": "/home/test", "PATH": "/usr/bin"},
        "allow": [],
        "cwd": "/tmp",
    },
    {
        "command": "rm -rf /tmp/build",
        "env": {"HOME": "/home/test", "PATH": "/usr/bin"},
        "allow": ["/tmp/**"],
        "cwd": "/tmp",
    },
    {
        "command": "rm -rf /",
        "env": {"HOME": "/home/test", "PATH": "/usr/bin"},
        "allow": [],
        "cwd": "/tmp",
    },
    {
        "command": "rm -rf ~/foo",
        "env": {"HOME": "/home/test", "PATH": "/usr/bin"},
        "allow": [],
        "cwd": "/tmp",
    },
]


# ─────────────────────────────────────────────────────────────────────
# Experiment 1: Disable floor-path check → should propagate to CLI
# ─────────────────────────────────────────────────────────────────────


def _disable_floor_check(source: str) -> str:
    """Remove the floor check from check.py — rm -rf / would be allowed."""
    # Replace the is_floor check with a no-op
    return source.replace(
        "if is_floor(path, home=env.get(\"HOME\", \"\")):",
        "if False:  # MUTATION: floor check disabled",
    )


EXP1 = Experiment(
    name="exp01-disable-floor-check",
    description="Disable the floor-path check in check.py. rm -rf / should "
                "become allowed instead of blocked. This is a FAILURE_PROPAGATION "
                "case — the decision changes from block to allow, which changes "
                "the CLI exit code and the hook block decision.",
    module="check",
    mutation=_disable_floor_check,
    inputs=GUILLEMOT_INPUTS,
    category="regression",
    expected_behaviour="rm -rf / changes from blocked (floor-path) to allowed",
)


# ─────────────────────────────────────────────────────────────────────
# Experiment 2: Change refusal message text (behavioural change, no propagation)
# ─────────────────────────────────────────────────────────────────────


def _change_refusal_text(source: str) -> str:
    """Change the floor-path refusal message text.

    This changes the Refusal.reason field but not the Refusal.rule or
    the allowed/refused decision. The CLI exit code and hook decision
    are unchanged. This is a BEHAVIOURAL_CHANGE without propagation.
    """
    return source.replace(
        "this rule cannot be overridden by any configuration",
        "this rule cannot be overridden by any config file or flag",
    )


EXP2 = Experiment(
    name="exp02-change-refusal-text",
    description="Change the floor-path refusal message wording in rules.py. "
                "The refusal reason text changes, but the rule ID and the "
                "block/allow decision are unchanged. This is a "
                "BEHAVIOURAL_CHANGE that does NOT propagate to the CLI exit "
                "code or hook decision.",
    module="rules",
    mutation=_change_refusal_text,
    inputs=GUILLEMOT_INPUTS,
    category="regression",
    expected_behaviour="Refusal reason text differs, but allowed/refused "
                       "decision and rule ID are unchanged",
)


# ─────────────────────────────────────────────────────────────────────
# Experiment 3: Add a comment (reachable, no behavioural change)
# ─────────────────────────────────────────────────────────────────────


def _add_comment(source: str) -> str:
    """Add a comment to resolve.py. No behavioural change."""
    return source.replace(
        '"""Resolve a shell target argument to its actual absolute path.',
        '"""Resolve a shell target argument to its actual absolute path.\n\n# MUTATION: added comment for testing — no behavioural change.\n',
        1,
    )


EXP3 = Experiment(
    name="exp03-add-comment",
    description="Add a comment to resolve.py. The module is imported by "
                "check.py (static dependency), and the test inputs exercise "
                "resolve_target at runtime. But the comment produces no "
                "behavioural change. This is RUNTIME_REACHABLE with no "
                "behavioural difference.",
    module="resolve",
    mutation=_add_comment,
    inputs=GUILLEMOT_INPUTS,
    category="control",
    expected_behaviour="No change in any output",
)


# ─────────────────────────────────────────────────────────────────────
# Experiment 4: Change a function that is statically depended on but
# never reached by the test inputs
# ─────────────────────────────────────────────────────────────────────


def _change_unused_function(source: str) -> str:
    """Change the _find_variables helper in resolve.py.

    This function exists in resolve.py and is imported by tokenise.py
    (static dependency), but it is never called by any of the test
    inputs (which don't exercise variable-finding in isolation). The
    change should be STATIC_SUSPICION — the module is depended on, but
    the specific function is never reached at runtime.
    """
    return source.replace(
        "def _find_variables(s: str) -> list[str]:",
        "def _find_variables_MUTATED(s: str) -> list[str]:",
    )


EXP4 = Experiment(
    name="exp04-change-unreached-function",
    description="Rename _find_variables in resolve.py. This function is "
                "defined in a module with static dependents, but it is "
                "not called by any test input path. The harness should "
                "classify this as RUNTIME_REACHABLE (the module runs) "
                "with no behavioural change (the function is never called).",
    module="resolve",
    mutation=_change_unused_function,
    inputs=GUILLEMOT_INPUTS,
    category="control",
    expected_behaviour="No change in any output — the renamed function "
                       "is never called by the test inputs",
)


# ─────────────────────────────────────────────────────────────────────
# Experiment 5: Control — change a docstring in hooks.py
# ─────────────────────────────────────────────────────────────────────


def _change_hooks_docstring(source: str) -> str:
    """Change a docstring in hooks.py. hooks.py is never imported by
    check.py or the test inputs. This is a pure control case."""
    return source.replace(
        "Hook installers for Claude Code and Cursor.",
        "Hook installers for Claude Code and Cursor (modified for test).",
    )


EXP5 = Experiment(
    name="exp05-change-hooks-docstring",
    description="Change a docstring in hooks.py. This module is not in "
                "the runtime path of any test input. This is a pure "
                "control case — no static dependency, no runtime "
                "reachability, no behavioural change.",
    module="hooks",
    mutation=_change_hooks_docstring,
    inputs=GUILLEMOT_INPUTS,
    category="control",
    expected_behaviour="No change in any output",
)


VALIDATION_EXPERIMENTS = [EXP1, EXP2, EXP3, EXP4, EXP5]
