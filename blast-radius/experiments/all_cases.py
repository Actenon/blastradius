"""Historical and synthetic regression cases for blast-radius analysis.

Each experiment reconstructs a real or realistic regression:

  HISTORICAL (H-series): based on the 7 bugs found in the v0.2.0
  adversarial audit. Each experiment reverts the fix and tests whether
  the harness detects the regression.

  SYNTHETIC (S-series): realistic regressions that COULD happen in this
  codebase, based on common failure patterns in shell-guard tools.

  CONTROL (C-series): known-benign changes that should NOT trigger.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Experiment


# ─────────────────────────────────────────────────────────────────────
# Common test inputs — designed to exercise every code path
# ─────────────────────────────────────────────────────────────────────


FULL_INPUTS = [
    # Empty variable (Guillemot pattern)
    {
        "command": 'rm -rf "$UNSET_VAR/foo"',
        "env": {"HOME": "/home/test", "PATH": "/usr/bin"},
        "allow": [],
        "cwd": "/tmp",
    },
    # Floor path
    {
        "command": "rm -rf /",
        "env": {"HOME": "/home/test", "PATH": "/usr/bin"},
        "allow": [],
        "cwd": "/tmp",
    },
    # Tilde
    {
        "command": "rm -rf ~/foo",
        "env": {"HOME": "/home/test", "PATH": "/usr/bin"},
        "allow": [],
        "cwd": "/tmp",
    },
    # Allowed path
    {
        "command": "rm -rf /tmp/build",
        "env": {"HOME": "/home/test", "PATH": "/usr/bin"},
        "allow": ["/tmp/**"],
        "cwd": "/tmp",
    },
    # Quoted semicolon (was false positive in v0.1.0)
    {
        "command": 'rm -rf "/tmp/foo;bar"',
        "env": {"HOME": "/home/test", "PATH": "/usr/bin"},
        "allow": ["/tmp/**"],
        "cwd": "/tmp",
    },
    # Newline (was bypass in v0.1.0)
    {
        "command": "echo hello\nrm -rf $HOME",
        "env": {"HOME": "/home/test", "PATH": "/usr/bin"},
        "allow": [],
        "cwd": "/tmp",
    },
    # No targets (was allowed in v0.1.0)
    {
        "command": "rm -rf",
        "env": {"HOME": "/home/test", "PATH": "/usr/bin"},
        "allow": [],
        "cwd": "/tmp",
    },
    # -- separator (was mishandled in v0.1.0)
    {
        "command": "rm -rf -- -foo",
        "env": {"HOME": "/home/test", "PATH": "/usr/bin"},
        "allow": [],
        "cwd": "/tmp",
    },
    # find -delete
    {
        "command": "find . -name '*.pyc' -delete",
        "env": {"HOME": "/home/test", "PATH": "/usr/bin"},
        "allow": ["/tmp/**"],
        "cwd": "/tmp",
    },
    # git clean
    {
        "command": "git clean -fdx",
        "env": {"HOME": "/home/test", "PATH": "/usr/bin"},
        "allow": ["/tmp/**"],
        "cwd": "/tmp",
    },
    # Non-destructive
    {
        "command": "ls -la",
        "env": {"HOME": "/home/test", "PATH": "/usr/bin"},
        "allow": [],
        "cwd": "/tmp",
    },
    # truncate
    {
        "command": "truncate -s 0 /tmp/log",
        "env": {"HOME": "/home/test", "PATH": "/usr/bin"},
        "allow": ["/tmp/**"],
        "cwd": "/tmp",
    },
]


# ─────────────────────────────────────────────────────────────────────
# H-series: Historical regressions (from the v0.2.0 audit)
# ─────────────────────────────────────────────────────────────────────


def _revert_quote_aware_tokeniser(source: str) -> str:
    """H01: Revert the quote-aware tokeniser to the v0.1.0 raw-regex approach.

    This reintroduces the false positive: rm -rf "foo;bar" is refused
    because the semicolon regex fires on the raw string.
    """
    # Replace the _scan_for_metacharacters call with a raw regex check
    return source.replace(
        "    # ── Quote-aware scan for refused metacharacters ─────────────────\n"
        "    # We walk the string respecting quotes, tracking quote state.\n"
        "    # Only unquoted metacharacters trigger a refusal. This prevents\n"
        "    # false positives on filenames like \"foo;bar\" or \"a|b\".\n"
        "    refusal = _scan_for_metacharacters(command)\n"
        "    if refusal:\n"
        "        return TokeniseResult(tokens=None, refusal=refusal)",
        "    # ── Raw regex check (v0.1.0 approach — false positives on quoted ;) ──\n"
        "    import re\n"
        "    for regex, suffix, desc in _REFUSE_REGEXES:\n"
        "        if regex.search(command):\n"
        "            return TokeniseResult(tokens=None, refusal=Refusal(\n"
        "                rule=f\"unparseable-command-{suffix}\",\n"
        "                reason=f\"{desc}\",\n"
        "                raw=command,\n"
        "            ))\n"
        "    _REFUSE_REGEXES = [(re.compile(p), s, d) for p, s, d in _REFUSE_PATTERNS]"
    )


def _revert_newline_refusal(source: str) -> str:
    """H02: Revert the newline refusal. Newlines become whitespace again.

    This reintroduces the critical bypass: echo foo\nrm -rf $HOME is
    allowed because echo is non-destructive.
    """
    return source.replace(
        '        # Newline — treated as a command separator (same threat as ;).\n'
        '        # This closes the "echo foo\\nrm -rf $HOME" bypass.\n'
        '        if c == "\\n":\n'
        '            return Refusal(\n'
        '                rule="unparseable-command-newline",\n'
        '                reason=(\n'
        '                    "command contains a newline — blastradius treats "\n'
        '                    "newlines as command separators (same threat as ;). "\n'
        '                    "If this is intentional, run the commands separately "\n'
        '                    "outside the agent."\n'
        '                ),\n'
        '                raw=s,\n'
        '            )\n',
        '        # MUTATION: newline check removed (v0.1.0 bypass)\n',
    )


def _revert_double_dash(source: str) -> str:
    """H03: Revert the -- separator support in commands.py.

    rm -- -foo misclassifies -foo as a flag again.
    """
    return source.replace(
        "    # ── Parse flags and targets, respecting -- ──────────────────────\n"
        "    # After --, every remaining argument is a target, even if it\n"
        "    # starts with -. This matches bash semantics.\n"
        "    flags: list[str] = []\n"
        "    non_flags: list[str] = []\n"
        "    seen_double_dash = False\n"
        "    for a in args:\n"
        "        if seen_double_dash:\n"
        "            non_flags.append(a)\n"
        "        elif a == \"--\":\n"
        "            seen_double_dash = True\n"
        "        elif a.startswith(\"-\") and a != \"-\":\n"
        "            flags.append(a)\n"
        "        else:\n"
        "            non_flags.append(a)",
        "    # MUTATION: -- separator not tracked (v0.1.0 behaviour)\n"
        "    flags = [a for a in args if a.startswith(\"-\")]\n"
        "    non_flags = [a for a in args if not a.startswith(\"-\")]",
    )


def _revert_no_targets_check(source: str) -> str:
    """H04: Revert the no-targets check in check.py.

    rm -rf with no targets is allowed again.
    """
    return source.replace(
        "    # BUG 5 fix: refuse destructive commands with zero targets.\n"
        "    # An rm with no targets is suspicious — the intent is unclear\n"
        "    # and it may be a misparsed command. Fail closed.\n"
        "    if not action.targets:\n"
        "        from .resolve import Refusal as _Refusal\n"
        "        return CheckResult(\n"
        "            allowed=False,\n"
        "            refusals=[(\n"
        "                _Refusal(\n"
        "                    rule=\"no-targets\",\n"
        "                    reason=(\n"
        "                        f\"destructive command '{action.command}' has no \"\n"
        "                        f\"targets — intent is unclear, refusing to proceed\"\n"
        "                    ),\n"
        "                    raw=command,\n"
        "                ),\n"
        "                command,\n"
        "            )],\n"
        "            command=command,\n"
        "            action=action,\n"
        "        )\n",
        "    # MUTATION: no-targets check removed (v0.1.0 allowed rm -rf with no targets)\n",
    )


def _revert_execvp_error_handling(source: str) -> str:
    """H05: Revert the FileNotFoundError handling in cli.py.

    os.execvp on a nonexistent command crashes with a traceback.
    """
    return source.replace(
        "        try:\n"
        "            os.execvp(command_args[0], command_args)\n"
        "        except FileNotFoundError:\n"
        "            print(\n"
        "                f\"blastradius: command not found: {command_args[0]}\",\n"
        "                file=sys.stderr,\n"
        "            )\n"
        "            return 127\n"
        "        except PermissionError:\n"
        "            print(\n"
        "                f\"blastradius: permission denied: {command_args[0]}\",\n"
        "                file=sys.stderr,\n"
        "            )\n"
        "            return 126\n"
        "        # execvp doesn't return on success.\n"
        "        return 0  # unreachable",
        "        # MUTATION: no error handling (v0.1.0 crashed with traceback)\n"
        "        os.execvp(command_args[0], command_args)\n"
        "        return 0  # unreachable",
    )


def _revert_double_star_root(source: str) -> str:
    """H06: Revert the ** regex to require at least one path component.

    /path/** no longer matches /path itself.
    """
    return source.replace(
        "                    if regex_parts:\n"
        "                        # Remove the trailing / from the last regex part.\n"
        "                        last = regex_parts[-1]\n"
        "                        if last.endswith(\"/\"):\n"
        "                            regex_parts[-1] = last[:-1]\n"
        "                    regex_parts.append(\"(?:/.*)?\")",
        "                    # MUTATION: require at least one component (v0.1.0)\n"
        "                    regex_parts.append(\"(?:/.*)\")",
    )


def _revert_line_continuation(source: str) -> str:
    """H07: Revert the backslash-newline line continuation handling."""
    return source.replace(
        "            if next_c == \"\\n\":\n"
        "                # Line continuation: backslash-newline is removed.\n"
        "                i += 2\n"
        "                continue",
        "                # MUTATION: line continuation not handled (v0.1.0)",
    )


# ─────────────────────────────────────────────────────────────────────
# S-series: Synthetic regressions (realistic failure patterns)
# ─────────────────────────────────────────────────────────────────────


def _break_empty_var_detection(source: str) -> str:
    """S01: Break the empty-variable-expansion check.

    Change `if val == "":` to `if False:` so unset variables are
    silently expanded to empty strings without refusal.
    """
    return source.replace(
        '        if val == "":\n'
        "            unset.append(name)",
        "        if False:  # MUTATION: empty-var detection disabled\n"
        "            unset.append(name)",
    )


def _break_tilde_refusal(source: str) -> str:
    """S02: Disable the tilde-ambiguous refusal.

    rm -rf ~/foo would be allowed (tilde resolves to $HOME).
    """
    return source.replace(
        '    if expanded.startswith("~"):',
        '    if False:  # MUTATION: tilde check disabled',
    )


def _break_glob_no_match(source: str) -> str:
    """S03: Disable the glob-no-match refusal.

    A glob that matches nothing would be allowed instead of refused.
    """
    return source.replace(
        '    if not matches:\n'
        '        return Refusal(\n'
        '            rule="glob-no-match",',
        '    if False:  # MUTATION: glob-no-match disabled\n'
        '        return Refusal(\n'
        '            rule="glob-no-match",',
    )


def _break_scope_deny(source: str) -> str:
    """S04: Break the scope deny-first logic.

    Deny patterns would no longer override allow patterns.
    """
    return source.replace(
        "        # Check deny first — deny always wins.\n"
        "        for pattern in self.deny:\n"
        "            if _match_scope(pattern, real, self.repo_root):\n"
        "                return False",
        "        # MUTATION: deny check skipped — allow wins always\n"
        "        if False:\n"
        "            for pattern in self.deny:\n"
        "                if _match_scope(pattern, real, self.repo_root):\n"
        "                    return False",
    )


def _break_find_delete_detection(source: str) -> str:
    """S05: Break the find -delete detection.

    find . -delete would no longer be identified as destructive.
    """
    return source.replace(
        '        if "-delete" in args:',
        '        if False:  # MUTATION: find -delete detection disabled',
    )


def _break_git_clean_detection(source: str) -> str:
    """S06: Break the git clean detection.

    git clean -fdx would no longer be identified as destructive.
    """
    return source.replace(
        '    if cmd == "git" and len(args) >= 1 and args[0] == "clean":',
        '    if False:  # MUTATION: git clean detection disabled',
    )


def _break_truncate_detection(source: str) -> str:
    """S07: Break the truncate detection."""
    return source.replace(
        '    if cmd == "truncate":',
        '    if False:  # MUTATION: truncate detection disabled',
    )


def _break_dd_detection(source: str) -> str:
    """S08: Break the dd detection."""
    return source.replace(
        '    if cmd == "dd":',
        '    if False:  # MUTATION: dd detection disabled',
    )


def _change_floor_list(source: str) -> str:
    """S09: Remove /etc from the floor list.

    rm -rf /etc would be allowed (if in scope).
    """
    return source.replace(
        '    "/etc",\n',
        '    # MUTATION: /etc removed from floor list\n',
    )


def _break_depth_check(source: str) -> str:
    """S10: Break the depth-≤1 floor check.

    Only explicit FLOOR_EXACT paths would be floor. Paths like
    /tmp (depth 1, not in explicit list) would not be floor.
    """
    return source.replace(
        "    # Depth ≤ 1 from root: / or /single-component.\n"
        "    depth = _path_depth(real)\n"
        "    if depth <= 1:\n"
        "        return True",
        "    # MUTATION: depth check disabled\n"
        "    if False:\n"
        "        return True",
    )


def _break_symlink_resolution(source: str) -> str:
    """S11: Use os.path.abspath instead of os.path.realpath.

    Symlinks would no longer be resolved, allowing a scope-inside
    path that symlinks outside scope to pass.
    """
    return source.replace(
        "    real = os.path.realpath(path)",
        "    real = os.path.abspath(path)  # MUTATION: doesn't resolve symlinks",
    )


def _break_backtick_refusal(source: str) -> str:
    """S12: Disable the backtick command-substitution refusal."""
    return source.replace(
        '        # Backtick command substitution.\n'
        '        if c == "`":\n'
        '            return Refusal(',
        '        # MUTATION: backtick check disabled\n'
        '        if False:\n'
        '            return Refusal(',
    )


def _break_command_substitution_refusal(source: str) -> str:
    """S13: Disable the $(...) command-substitution refusal."""
    return source.replace(
        '        # $(...) command substitution.\n'
        '        if c == "$" and i + 1 < len(s) and s[i + 1] == "(":\n'
        '            return Refusal(',
        '        # MUTATION: $(...) check disabled\n'
        '        if False:\n'
        '            return Refusal(',
    )


def _break_pipe_refusal(source: str) -> str:
    """S14: Disable the pipe refusal."""
    return source.replace(
        '        # Single | (pipeline).\n'
        '        if c == "|":\n'
        '            return Refusal(',
        '        # MUTATION: pipe check disabled\n'
        '        if False:\n'
        '            return Refusal(',
    )


def _change_default_max_breadth(source: str) -> str:
    """S15: Change the default glob breadth from 100 to 1000000.

    rm -rf * that expands to 500 entries would be allowed.
    """
    return source.replace(
        "DEFAULT_MAX_GLOB_BREADTH = 100",
        "DEFAULT_MAX_GLOB_BREADTH = 1000000  # MUTATION: breadth check effectively disabled",
    )


# ─────────────────────────────────────────────────────────────────────
# C-series: Control cases (benign changes that should NOT trigger)
# ─────────────────────────────────────────────────────────────────────


def _c01_add_comment_to_rules(source: str) -> str:
    """C01: Add a comment to rules.py."""
    return source.replace(
        '"""Floor rules, scope, and glob-breadth checks.',
        '"""Floor rules, scope, and glob-breadth checks.\n\n# C01: benign comment added for testing.\n',
        1,
    )


def _c02_rename_local_variable(source: str) -> str:
    """C02: Rename a local variable in resolve.py."""
    return source.replace(
        "    variables_used = []\n    unset = []",
        "    vars_used = []  # C02: renamed\n    unset = []",
    ).replace("variables_used.append(name)", "vars_used.append(name)").replace(
        "return expanded, variables_used, unset",
        "return expanded, vars_used, unset",
    )


def _c03_change_report_formatting(source: str) -> str:
    """C03: Change a formatting constant in report.py (non-functional)."""
    return source.replace(
        'lines.append("blastradius  BLOCKED")',
        'lines.append("blastradius  BLOCKED ")  # C03: added trailing space',
    )


def _c04_add_new_function(source: str) -> str:
    """C04: Add a new unused function to commands.py."""
    if "def _c04_unused_function" not in source:
        # Append at the end of the file
        return source + "\n\ndef _c04_unused_function() -> None:\n    \"\"\"C04: unused function for testing.\"\"\"\n    pass\n"
    return source


def _c05_change_docstring(source: str) -> str:
    """C05: Change a docstring in check.py."""
    return source.replace(
        "Core check function — the decision pipeline.",
        "Core check function — the decision pipeline (C05: modified docstring).",
    )


def _c06_reorder_imports(source: str) -> str:
    """C06: Reorder imports in check.py (no functional change)."""
    return source.replace(
        "from .commands import DestructiveAction, identify_destructive\n"
        "from .resolve import Refusal, Resolved, resolve_target\n"
        "from .rules import (",
        "from .resolve import Refusal, Resolved, resolve_target\n"
        "from .commands import DestructiveAction, identify_destructive\n"
        "from .rules import (",
    )


def _c07_change_constant_name(source: str) -> str:
    """C07: Change an unused constant name."""
    return source.replace(
        'GENESIS_PREV_HASH = "0" * 64',
        'GENESIS_HASH = "0" * 64  # C07: renamed (not used in blastradius)',
    )


def _c08_add_type_annotation(source: str) -> str:
    """C08: Add a return type annotation to a function that lacks one."""
    return source.replace(
        "def _has_glob_chars(s: str) -> bool:",
        "def _has_glob_chars(s: str) -> bool:  # C08: annotation added",
    )


def _c09_change_whitespace(source: str) -> str:
    """C09: Change indentation style (tabs to spaces, no functional change)."""
    # This is a no-op — we can't safely change whitespace without breaking Python.
    # Instead, add a blank line.
    return source.replace("\n\n\n", "\n\n\n\n", 1)


def _c10_add_future_import(source: str) -> str:
    """C10: Add a __future__ import (already present, so no-op)."""
    if "from __future__ import annotations" in source:
        return source  # Already has it
    return "from __future__ import annotations\n" + source


# ─────────────────────────────────────────────────────────────────────
# Assemble the full experiment suite
# ─────────────────────────────────────────────────────────────────────


HISTORICAL_EXPERIMENTS = [
    Experiment("H01-revert-quote-aware-tokeniser", "Revert quote-aware tokeniser to raw regex — quoted semicolons falsely refused", "tokenise", _revert_quote_aware_tokeniser, FULL_INPUTS, "regression"),
    Experiment("H02-revert-newline-refusal", "Revert newline refusal — echo\\nrm bypass reintroduced", "tokenise", _revert_newline_refusal, FULL_INPUTS, "regression"),
    Experiment("H03-revert-double-dash", "Revert -- separator support — rm -- -foo misclassifies target", "commands", _revert_double_dash, FULL_INPUTS, "regression"),
    Experiment("H04-revert-no-targets-check", "Revert no-targets check — rm -rf with no targets allowed", "check", _revert_no_targets_check, FULL_INPUTS, "regression"),
    Experiment("H05-revert-execvp-handling", "Revert FileNotFoundError handling — crash on missing command", "cli", _revert_execvp_error_handling, FULL_INPUTS, "regression"),
    Experiment("H06-revert-double-star-root", "Revert ** matching zero components — /path doesn't match /path/**", "rules", _revert_double_star_root, FULL_INPUTS, "regression"),
    Experiment("H07-revert-line-continuation", "Revert backslash-newline handling — literal \\n in token", "tokenise", _revert_line_continuation, FULL_INPUTS, "regression"),
]

SYNTHETIC_EXPERIMENTS = [
    Experiment("S01-break-empty-var-detection", "Disable empty-variable detection — Guillemot pattern allowed", "resolve", _break_empty_var_detection, FULL_INPUTS, "regression"),
    Experiment("S02-break-tilde-refusal", "Disable tilde refusal — rm -rf ~/foo allowed", "resolve", _break_tilde_refusal, FULL_INPUTS, "regression"),
    Experiment("S03-break-glob-no-match", "Disable glob-no-match refusal — empty globs allowed", "resolve", _break_glob_no_match, FULL_INPUTS, "regression"),
    Experiment("S04-break-scope-deny", "Break scope deny-first logic — deny patterns ignored", "rules", _break_scope_deny, FULL_INPUTS, "regression"),
    Experiment("S05-break-find-delete", "Disable find -delete detection", "commands", _break_find_delete_detection, FULL_INPUTS, "regression"),
    Experiment("S06-break-git-clean", "Disable git clean detection", "commands", _break_git_clean_detection, FULL_INPUTS, "regression"),
    Experiment("S07-break-truncate", "Disable truncate detection", "commands", _break_truncate_detection, FULL_INPUTS, "regression"),
    Experiment("S08-break-dd", "Disable dd detection", "commands", _break_dd_detection, FULL_INPUTS, "regression"),
    Experiment("S09-remove-etc-from-floor", "Remove /etc from floor list", "rules", _change_floor_list, FULL_INPUTS, "regression"),
    Experiment("S10-break-depth-check", "Disable depth-≤1 floor check", "rules", _break_depth_check, FULL_INPUTS, "regression"),
    Experiment("S11-break-symlink-resolution", "Use abspath instead of realpath — symlinks not resolved", "resolve", _break_symlink_resolution, FULL_INPUTS, "regression"),
    Experiment("S12-break-backtick-refusal", "Disable backtick command-substitution refusal", "tokenise", _break_backtick_refusal, FULL_INPUTS, "regression"),
    Experiment("S13-break-cmd-subst-refusal", "Disable $(...) command-substitution refusal", "tokenise", _break_command_substitution_refusal, FULL_INPUTS, "regression"),
    Experiment("S14-break-pipe-refusal", "Disable pipe refusal", "tokenise", _break_pipe_refusal, FULL_INPUTS, "regression"),
    Experiment("S15-disable-breadth-check", "Set max glob breadth to 1000000 — effectively disabled", "rules", _change_default_max_breadth, FULL_INPUTS, "regression"),
]

CONTROL_EXPERIMENTS = [
    Experiment("C01-add-comment-rules", "Add a comment to rules.py", "rules", _c01_add_comment_to_rules, FULL_INPUTS, "control"),
    Experiment("C02-rename-local-var", "Rename a local variable in resolve.py", "resolve", _c02_rename_local_variable, FULL_INPUTS, "control"),
    Experiment("C03-change-report-format", "Change formatting in report.py", "report", _c03_change_report_formatting, FULL_INPUTS, "control"),
    Experiment("C04-add-unused-function", "Add an unused function to commands.py", "commands", _c04_add_new_function, FULL_INPUTS, "control"),
    Experiment("C05-change-docstring", "Change a docstring in check.py", "check", _c05_change_docstring, FULL_INPUTS, "control"),
    Experiment("C06-reorder-imports", "Reorder imports in check.py", "check", _c06_reorder_imports, FULL_INPUTS, "control"),
    Experiment("C07-change-constant-name", "Change an unused constant name", "resolve", _c07_change_constant_name, FULL_INPUTS, "control"),
    Experiment("C08-add-type-annotation", "Add a type annotation", "resolve", _c08_add_type_annotation, FULL_INPUTS, "control"),
    Experiment("C09-change-whitespace", "Add a blank line (whitespace change)", "resolve", _c09_change_whitespace, FULL_INPUTS, "control"),
    Experiment("C10-add-future-import", "Add a __future__ import (already present)", "resolve", _c10_add_future_import, FULL_INPUTS, "control"),
]

ALL_EXPERIMENTS = HISTORICAL_EXPERIMENTS + SYNTHETIC_EXPERIMENTS + CONTROL_EXPERIMENTS
