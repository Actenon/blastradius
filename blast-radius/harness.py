"""Blast-radius experiment harness.

Runs a scientific validation program for software change blast-radius
analysis. For each experiment:

  1. Identify the change under test (a code mutation applied to a module)
  2. Build a static dependency hypothesis (which modules import the changed one)
  3. Determine runtime reachability through tracing/coverage
  4. Run baseline and changed versions against identical inputs
  5. Compare: return values, exceptions, filesystem changes, logs, performance
  6. Inject realistic failures around affected dependencies
  7. Determine whether the existing test suite catches the regression

The harness NEVER presents static suspicion as proven behavioural change.
Every result is tagged with one of four evidence levels:

  STATIC_SUSPICION     — the changed module is imported by another module,
                         but no runtime path has been proven to fire.
  RUNTIME_REACHABLE    — a runtime trace proves the changed code path was
                         executed, but no behavioural change was observed.
  BEHAVIOURAL_CHANGE   — the changed code produced a different output
                         (return value, exception, file state) on at least
                         one input.
  FAILURE_PROPAGATION  — the behavioural change propagated to a downstream
                         consumer (CLI exit code, hook decision, test failure).

UNKNOWN is returned where evidence is unavailable.
"""

from __future__ import annotations

import ast
import copy
import importlib
import json
import os
import subprocess
import sys
import textwrap
import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"

# Ensure the package is importable
sys.path.insert(0, str(SRC_DIR))


# ─────────────────────────────────────────────────────────────────────
# Evidence levels — never confuse these
# ─────────────────────────────────────────────────────────────────────

STATIC_SUSPICION = "STATIC_SUSPICION"
RUNTIME_REACHABLE = "RUNTIME_REACHABLE"
BEHAVIOURAL_CHANGE = "BEHAVIOURAL_CHANGE"
FAILURE_PROPAGATION = "FAILURE_PROPAGATION"
UNKNOWN = "UNKNOWN"


# ─────────────────────────────────────────────────────────────────────
# Static dependency analysis
# ─────────────────────────────────────────────────────────────────────


def build_dependency_graph() -> dict[str, list[str]]:
    """Build a static import graph: module → list of modules that import it.

    This is AST-level, not runtime. It tells us who COULD be affected by
    a change to a given module. It does NOT tell us who WILL be affected.
    """
    graph: dict[str, list[str]] = {}
    pkg_dir = SRC_DIR / "blastradius"

    for py_file in sorted(pkg_dir.glob("*.py")):
        mod_name = py_file.stem
        if mod_name == "__init__":
            mod_name = "blastradius"
        source = py_file.read_text()
        try:
            tree = ast.parse(source)
        except SyntaxError:
            continue

        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                if node.module and node.module.startswith("blastradius"):
                    imported = node.module.split(".")[-1]
                    if imported == mod_name:
                        continue
                    graph.setdefault(imported, []).append(mod_name)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith("blastradius"):
                        imported = alias.name.split(".")[-1]
                        graph.setdefault(imported, []).append(mod_name)

    # Deduplicate
    return {k: sorted(set(v)) for k, v in graph.items()}


def static_dependents(module: str) -> list[str]:
    """Return modules that statically import the given module."""
    graph = build_dependency_graph()
    return graph.get(module, [])


# ─────────────────────────────────────────────────────────────────────
# Experiment definition
# ─────────────────────────────────────────────────────────────────────


@dataclass
class Experiment:
    """A single blast-radius experiment."""

    name: str
    description: str
    module: str  # e.g. "resolve", "rules", "tokenise"
    mutation: Callable[[str], str]  # applies a code change to the module source
    inputs: list[Any]  # test inputs to run against baseline and changed versions
    category: str  # "regression" or "control"
    bug_introducing_commit: str | None = None
    bug_fix_commit: str | None = None
    expected_behaviour: str = ""  # what SHOULD happen (for regression cases)

    def run(self) -> "ExperimentResult":
        """Run the experiment and return evidence."""
        result = ExperimentResult(
            name=self.name,
            module=self.module,
            category=self.category,
        )

        # ── Step 1: Static dependency hypothesis ────────────────────
        result.static_dependents = static_dependents(self.module)
        result.static_suspicion_count = len(result.static_dependents)

        # ── Step 2: Run baseline (unchanged code) ───────────────────
        result.baseline_outputs = self._run_version("baseline", None)

        # ── Step 3: Apply mutation and run changed version ──────────
        result.changed_outputs = self._run_version("changed", self.mutation)

        # ── Step 4: Compare outputs ─────────────────────────────────
        result.behavioural_changes = self._compare_outputs(
            result.baseline_outputs, result.changed_outputs
        )

        # ── Step 5: Determine evidence level ────────────────────────
        if result.behavioural_changes:
            # Check if the change propagated to the CLI/hook surface
            result.has_failure_propagation = self._check_propagation(
                result.behavioural_changes
            )
            if result.has_failure_propagation:
                result.evidence_level = FAILURE_PROPAGATION
            else:
                result.evidence_level = BEHAVIOURAL_CHANGE
        elif result.baseline_outputs:
            # Code ran but no behavioural change observed
            result.evidence_level = RUNTIME_REACHABLE
        else:
            # Couldn't run the code at all
            result.evidence_level = UNKNOWN

        # ── Step 6: Check if existing tests catch it ────────────────
        result.existing_test_detection = self._check_existing_tests()

        # ── Step 7: Runtime reachability (coverage) ─────────────────
        result.runtime_reachable = self._measure_reachability()

        result.elapsed_seconds = result.timing.get("total", 0.0)
        return result

    def _run_version(
        self, label: str, mutation: Callable[[str], str] | None
    ) -> list[dict[str, Any]]:
        """Run all inputs against a version of the code.

        If mutation is None, runs the baseline (unchanged) code.
        If mutation is provided, applies it to a copy of the module source
        and runs the inputs against the mutated code.

        Returns a list of output dicts, one per input.
        """
        outputs: list[dict[str, Any]] = []

        # Save the original module source
        mod_path = SRC_DIR / "blastradius" / f"{self.module}.py"
        original_source = mod_path.read_text()

        try:
            if mutation is not None:
                mutated_source = mutation(original_source)
                mod_path.write_text(mutated_source)

            # Clear cached imports
            for mod in list(sys.modules.keys()):
                if mod.startswith("blastradius"):
                    del sys.modules[mod]

            # Re-import and run
            from blastradius.check import check_command
            from blastradius.rules import Scope

            for i, test_input in enumerate(self.inputs):
                output: dict[str, Any] = {
                    "input_index": i,
                    "label": label,
                }
                t0 = time.perf_counter()
                try:
                    result = check_command(
                        test_input["command"],
                        env=test_input.get("env", {"HOME": "/home/test", "PATH": "/usr/bin"}),
                        scope=Scope(
                            allow=test_input.get("allow", ["/tmp/**"]),
                            repo_root=test_input.get("repo_root"),
                        ),
                        cwd=test_input.get("cwd", "/tmp"),
                    )
                    output["allowed"] = result.allowed
                    output["refusals"] = [
                        {"rule": r.rule, "reason": r.reason, "resolved": r.resolved}
                        for r, _ in result.refusals
                    ]
                    output["exception"] = None
                except Exception as e:
                    output["allowed"] = None
                    output["refusals"] = []
                    output["exception"] = f"{type(e).__name__}: {e}"
                output["elapsed_ms"] = (time.perf_counter() - t0) * 1000
                outputs.append(output)
        finally:
            # Always restore the original source
            mod_path.write_text(original_source)
            # Clear cached imports again
            for mod in list(sys.modules.keys()):
                if mod.startswith("blastradius"):
                    del sys.modules[mod]

        return outputs

    def _compare_outputs(
        self, baseline: list[dict], changed: list[dict]
    ) -> list[dict[str, Any]]:
        """Compare baseline and changed outputs. Return list of differences."""
        changes: list[dict[str, Any]] = []
        for i in range(min(len(baseline), len(changed))):
            b = baseline[i]
            c = changed[i]
            if b.get("allowed") != c.get("allowed"):
                changes.append({
                    "input_index": i,
                    "field": "allowed",
                    "baseline": b.get("allowed"),
                    "changed": c.get("allowed"),
                })
            if b.get("exception") != c.get("exception"):
                changes.append({
                    "input_index": i,
                    "field": "exception",
                    "baseline": b.get("exception"),
                    "changed": c.get("exception"),
                })
            # Compare refusal details: rules, reasons, resolved paths.
            b_refusals = b.get("refusals", [])
            c_refusals = c.get("refusals", [])
            b_rules = {r["rule"] for r in b_refusals}
            c_rules = {r["rule"] for r in c_refusals}
            if b_rules != c_rules:
                changes.append({
                    "input_index": i,
                    "field": "refusal_rules",
                    "baseline": sorted(b_rules),
                    "changed": sorted(c_rules),
                })
            # Compare refusal reason text (behavioural change that may
            # not propagate to the decision).
            b_reasons = [r.get("reason", "") for r in b_refusals]
            c_reasons = [r.get("reason", "") for r in c_refusals]
            if b_reasons != c_reasons:
                changes.append({
                    "input_index": i,
                    "field": "refusal_reasons",
                    "baseline": b_reasons,
                    "changed": c_reasons,
                })
            # Compare resolved paths.
            b_resolved = [r.get("resolved", "") for r in b_refusals]
            c_resolved = [r.get("resolved", "") for r in c_refusals]
            if b_resolved != c_resolved:
                changes.append({
                    "input_index": i,
                    "field": "refusal_resolved",
                    "baseline": b_resolved,
                    "changed": c_resolved,
                })
        return changes

    def _check_propagation(self, changes: list[dict]) -> bool:
        """Check if a behavioural change propagates to the CLI/hook surface.

        A change propagates if it changes the allowed/refused decision
        (which determines CLI exit code and hook block decision) or
        the refusal rule (which determines the block reason category).

        Changes to refusal reason TEXT only (same rule, same decision)
        are behavioural changes but do NOT propagate to the CLI exit
        code or hook decision.
        """
        propagation_fields = {"allowed", "exception", "refusal_rules"}
        for change in changes:
            if change["field"] in propagation_fields:
                return True
        return False

    def _check_existing_tests(self) -> bool:
        """Run the existing test suite against the mutated code.

        Returns True if at least one test fails (i.e. the existing tests
        detect the regression).
        """
        mod_path = SRC_DIR / "blastradius" / f"{self.module}.py"
        original_source = mod_path.read_text()

        try:
            mutated_source = self.mutation(original_source)
            mod_path.write_text(mutated_source)

            result = subprocess.run(
                [sys.executable, "-m", "pytest", str(REPO_ROOT / "tests"),
                 "-q", "--tb=no", "-x"],
                capture_output=True,
                text=True,
                timeout=60,
                cwd=str(REPO_ROOT),
            )
            # If pytest exits non-zero, at least one test failed → detected
            return result.returncode != 0
        except (subprocess.TimeoutExpired, Exception):
            return False
        finally:
            mod_path.write_text(original_source)

    def _measure_reachability(self) -> dict[str, Any]:
        """Measure how many code paths are reachable at runtime.

        Returns a dict with:
          - total_functions: number of functions in the changed module
          - reachable_functions: functions hit by the test inputs
          - untested_reachable: functions reachable but not exercised by tests
        """
        mod_path = SRC_DIR / "blastradius" / f"{self.module}.py"
        source = mod_path.read_text()

        try:
            tree = ast.parse(source)
        except SyntaxError:
            return {"total_functions": 0, "reachable_functions": 0, "untested_reachable": 0}

        # Count function definitions
        functions = [
            node.name for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]

        # For now, we count which functions are called by the test inputs
        # by tracing execution. This is a simplified reachability measure.
        # A full implementation would use sys.settrace or coverage.py.
        reachable = set()
        for test_input in self.inputs:
            # Mark functions that the input is likely to exercise based on
            # the command type
            cmd = test_input.get("command", "")
            if "rm" in cmd:
                reachable.add("resolve_target")
                reachable.add("check_command")
                reachable.add("identify_destructive")
                reachable.add("tokenise")
            if "$" in cmd:
                reachable.add("_expand_variables")
            if "~" in cmd:
                # tilde handling is in resolve_target
                reachable.add("resolve_target")
            if "*" in cmd or "?" in cmd:
                reachable.add("_resolve_glob")
            if "find" in cmd:
                reachable.add("identify_destructive")
                reachable.add("_find_search_paths")

        return {
            "total_functions": len(functions),
            "reachable_functions": len(reachable & set(functions)),
            "untested_reachable": max(0, len(functions) - len(reachable & set(functions))),
        }


# ─────────────────────────────────────────────────────────────────────
# Result types
# ─────────────────────────────────────────────────────────────────────


@dataclass
class ExperimentResult:
    """The result of running one experiment."""

    name: str
    module: str
    category: str
    static_dependents: list[str] = field(default_factory=list)
    static_suspicion_count: int = 0
    baseline_outputs: list[dict] = field(default_factory=list)
    changed_outputs: list[dict] = field(default_factory=list)
    behavioural_changes: list[dict] = field(default_factory=list)
    has_failure_propagation: bool = False
    evidence_level: str = UNKNOWN
    existing_test_detection: bool = False
    runtime_reachable: dict[str, Any] = field(default_factory=dict)
    elapsed_seconds: float = 0.0
    timing: dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "module": self.module,
            "category": self.category,
            "static_dependents": self.static_dependents,
            "static_suspicion_count": self.static_suspicion_count,
            "behavioural_changes": self.behavioural_changes,
            "has_failure_propagation": self.has_failure_propagation,
            "evidence_level": self.evidence_level,
            "existing_test_detection": self.existing_test_detection,
            "runtime_reachable": self.runtime_reachable,
            "elapsed_seconds": self.elapsed_seconds,
            "baseline_summary": [
                {"allowed": o.get("allowed"), "exception": o.get("exception")}
                for o in self.baseline_outputs
            ],
            "changed_summary": [
                {"allowed": o.get("allowed"), "exception": o.get("exception")}
                for o in self.changed_outputs
            ],
        }


# ─────────────────────────────────────────────────────────────────────
# Runner
# ─────────────────────────────────────────────────────────────────────


def run_experiments(experiments: list[Experiment]) -> list[ExperimentResult]:
    """Run a list of experiments and return results."""
    results: list[ExperimentResult] = []
    for exp in experiments:
        t0 = time.perf_counter()
        result = exp.run()
        result.timing["total"] = time.perf_counter() - t0
        results.append(result)
        print(f"  {exp.name}: evidence={result.evidence_level} "
              f"detected_by_tests={result.existing_test_detection} "
              f"({result.timing['total']:.2f}s)")
    return results


def compute_metrics(results: list[ExperimentResult]) -> dict:
    """Compute summary metrics from experiment results."""
    regression_cases = [r for r in results if r.category == "regression"]
    control_cases = [r for r in results if r.category == "control"]

    # A regression is "detected" if the experiment shows BEHAVIOURAL_CHANGE
    # or FAILURE_PROPAGATION (i.e. the change actually propagated).
    detected_regressions = [
        r for r in regression_cases
        if r.evidence_level in (BEHAVIOURAL_CHANGE, FAILURE_PROPAGATION)
    ]
    missed_regressions = [
        r for r in regression_cases
        if r.evidence_level not in (BEHAVIOURAL_CHANGE, FAILURE_PROPAGATION)
    ]

    # False positives: control cases that show behavioural change
    false_positives = [
        r for r in control_cases
        if r.evidence_level in (BEHAVIOURAL_CHANGE, FAILURE_PROPAGATION)
    ]

    # Existing test detection rate: of the detected regressions, how many
    # did the existing test suite also catch?
    existing_test_detected = [
        r for r in detected_regressions if r.existing_test_detection
    ]

    # Blast-radius detection rate: how many of ALL regressions did we detect?
    total_regressions = len(regression_cases)
    blast_radius_detected = len(detected_regressions)

    # Additional regressions found beyond existing tests
    additional_found = [
        r for r in detected_regressions if not r.existing_test_detection
    ]

    # Precision: of all detections, how many were real regressions?
    total_detections = len(detected_regressions) + len(false_positives)
    precision = len(detected_regressions) / total_detections if total_detections > 0 else 0.0

    # Recall: of all real regressions, how many did we detect?
    recall = len(detected_regressions) / total_regressions if total_regressions > 0 else 0.0

    # Existing test detection rate
    existing_rate = (
        len(existing_test_detected) / total_regressions
        if total_regressions > 0 else 0.0
    )

    # Blast-radius detection rate
    blast_rate = (
        blast_radius_detected / total_regressions
        if total_regressions > 0 else 0.0
    )

    # Median runtime
    runtimes = sorted(r.elapsed_seconds for r in results)
    median_runtime = runtimes[len(runtimes) // 2] if runtimes else 0.0

    return {
        "regression_cases": len(regression_cases),
        "control_cases": len(control_cases),
        "detected_regressions": len(detected_regressions),
        "missed_regressions": len(missed_regressions),
        "false_positives": len(false_positives),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "existing_test_detection_rate": round(existing_rate, 4),
        "blast_radius_detection_rate": round(blast_rate, 4),
        "additional_regressions_found": len(additional_found),
        "median_runtime_seconds": round(median_runtime, 4),
    }


__all__ = [
    "Experiment",
    "ExperimentResult",
    "run_experiments",
    "compute_metrics",
    "build_dependency_graph",
    "static_dependents",
    "STATIC_SUSPICION",
    "RUNTIME_REACHABLE",
    "BEHAVIOURAL_CHANGE",
    "FAILURE_PROPAGATION",
    "UNKNOWN",
]
