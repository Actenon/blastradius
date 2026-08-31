#!/usr/bin/env python3
"""Main runner for the blast-radius validation program.

Runs all experiments, produces summary.json, report.html, and per-experiment
result files.

Usage:
  python blast-radius/run.py              # run all experiments
  python blast-radius/run.py --validate   # run only the 5 validation experiments
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

BLAST_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BLAST_DIR))

from harness import (
    run_experiments,
    compute_metrics,
    build_dependency_graph,
    BEHAVIOURAL_CHANGE,
    FAILURE_PROPAGATION,
    RUNTIME_REACHABLE,
    STATIC_SUSPICION,
    UNKNOWN,
)


def main() -> int:
    validate_only = "--validate" in sys.argv

    if validate_only:
        from experiments.validation_5 import VALIDATION_EXPERIMENTS
        experiments = VALIDATION_EXPERIMENTS
        print("=== Running 5 validation experiments ===")
    else:
        from experiments.all_cases import ALL_EXPERIMENTS
        experiments = ALL_EXPERIMENTS
        print(f"=== Running {len(experiments)} experiments ===")

    print()
    t0 = time.perf_counter()
    results = run_experiments(experiments)
    total_elapsed = time.perf_counter() - t0
    print(f"\nTotal elapsed: {total_elapsed:.1f}s")
    print(f"Median per-experiment: {sorted(r.elapsed_seconds for r in results)[len(results)//2]:.2f}s")

    # ── Compute metrics ────────────────────────────────────────────
    metrics = compute_metrics(results)
    print("\n=== Metrics ===")
    print(json.dumps(metrics, indent=2))

    # ── Write summary.json ─────────────────────────────────────────
    summary_path = BLAST_DIR / "summary.json"
    summary_path.write_text(json.dumps(metrics, indent=2) + "\n")
    print(f"\nWrote {summary_path}")

    # ── Write per-experiment results ───────────────────────────────
    results_dir = BLAST_DIR / "results"
    results_dir.mkdir(exist_ok=True)
    for r in results:
        result_file = results_dir / f"{r.name}.json"
        result_file.write_text(json.dumps(r.to_dict(), indent=2, default=str) + "\n")
    print(f"Wrote {len(results)} result files to {results_dir}/")

    # ── Write report.html ──────────────────────────────────────────
    report_html = _generate_report_html(results, metrics)
    report_path = BLAST_DIR / "report.html"
    report_path.write_text(report_html)
    print(f"Wrote {report_path}")

    # ── Latent blast radius ────────────────────────────────────────
    latent = _compute_latent_blast_radius(results)
    latent_path = BLAST_DIR / "results" / "latent_blast_radius.json"
    latent_path.write_text(json.dumps(latent, indent=2) + "\n")
    print(f"Wrote {latent_path}")
    print(f"\nLatent blast radius: {latent['total_reachable']} reachable paths, "
          f"{latent['total_tested']} tested, "
          f"{latent['total_untested']} untested")

    # ── Final summary ──────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("BLAST-RADIUS VALIDATION COMPLETE")
    print("=" * 60)
    print(f"  Regression cases:     {metrics['regression_cases']}")
    print(f"  Control cases:        {metrics['control_cases']}")
    print(f"  Detected regressions: {metrics['detected_regressions']}")
    print(f"  Missed regressions:   {metrics['missed_regressions']}")
    print(f"  False positives:      {metrics['false_positives']}")
    print(f"  Precision:            {metrics['precision']:.1%}")
    print(f"  Recall:               {metrics['recall']:.1%}")
    print(f"  Existing test rate:   {metrics['existing_test_detection_rate']:.1%}")
    print(f"  Blast-radius rate:    {metrics['blast_radius_detection_rate']:.1%}")
    print(f"  Additional found:     {metrics['additional_regressions_found']}")
    print(f"  Median runtime:       {metrics['median_runtime_seconds']:.2f}s")
    print("=" * 60)

    return 0


def _compute_latent_blast_radius(results: list) -> dict:
    """Compute the latent blast radius: reachable-but-untested paths."""
    total_reachable = 0
    total_tested = 0
    total_untested = 0
    per_module: dict[str, dict] = {}

    for r in results:
        rr = r.runtime_reachable or {}
        reachable = rr.get("reachable_functions", 0)
        untested = rr.get("untested_reachable", 0)
        tested = reachable  # reachable functions that are also tested
        total_reachable += reachable + untested
        total_tested += tested
        total_untested += untested

        mod = r.module
        if mod not in per_module:
            per_module[mod] = {"reachable": 0, "tested": 0, "untested": 0}
        per_module[mod]["reachable"] += reachable + untested
        per_module[mod]["tested"] += tested
        per_module[mod]["untested"] += untested

    return {
        "total_reachable": total_reachable,
        "total_tested": total_tested,
        "total_untested": total_untested,
        "per_module": per_module,
        "description": (
            f"{total_untested} production-reachable code paths are not "
            f"exercised by any test input. These are latent blast-radius "
            f"paths — a change to them would propagate at runtime but "
            f"CI would not detect it."
        ),
    }


def _generate_report_html(results: list, metrics: dict) -> str:
    """Generate a self-contained HTML report."""
    rows = []
    for r in results:
        evidence_color = {
            FAILURE_PROPAGATION: "#E0514B",
            BEHAVIOURAL_CHANGE: "#E0A82E",
            RUNTIME_REACHABLE: "#3FA98A",
            STATIC_SUSPICION: "#78849A",
            UNKNOWN: "#4A5364",
        }.get(r.evidence_level, "#4A5364")

        changes = ", ".join(c["field"] for c in r.behavioural_changes) or "—"
        detected = "✓" if r.existing_test_detection else "✗"
        detected_color = "#3FA98A" if r.existing_test_detection else "#E0514B"

        rows.append(f"""
        <tr>
          <td><code>{r.name}</code></td>
          <td>{r.module}</td>
          <td style="color:{evidence_color};font-weight:600">{r.evidence_level}</td>
          <td>{r.static_suspicion_count}</td>
          <td>{changes}</td>
          <td style="color:{detected_color};font-weight:700;text-align:center">{detected}</td>
          <td style="text-align:right">{r.elapsed_seconds:.2f}s</td>
        </tr>""")

    rows_html = "\n".join(rows)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>blastradius — Blast-Radius Validation Report</title>
<style>
:root {{
  --bg:#08090C; --panel:#11141B; --line:#242A36;
  --ink:#E9EDF3; --dim:#78849A; --dimmer:#4A5364;
  --seal:#E0A82E; --refuse:#E0514B; --bound:#3FA98A;
}}
* {{ box-sizing: border-box; }}
body {{ margin:0; background:var(--bg); color:var(--ink);
  font-family:system-ui,sans-serif; font-size:14px; line-height:1.5;
  -webkit-font-smoothing:antialiased; }}
code {{ font-family:'JetBrains Mono',ui-monospace,monospace; font-size:12px; }}
.wrap {{ max-width:1100px; margin:0 auto; padding:30px 22px 80px; }}
h1 {{ font-size:28px; font-weight:800; letter-spacing:-.02em; margin:0 0 8px; }}
h1 em {{ font-style:normal; color:var(--seal); }}
.lede {{ color:var(--dim); max-width:70ch; margin-bottom:24px; }}
.metrics {{ display:grid; grid-template-columns:repeat(auto-fill,minmax(180px,1fr));
  gap:12px; margin-bottom:30px; }}
.metric {{ background:var(--panel); border:1px solid var(--line); border-radius:8px;
  padding:14px; }}
.metric .label {{ font-size:11px; color:var(--dim); text-transform:uppercase;
  letter-spacing:.1em; margin-bottom:4px; }}
.metric .value {{ font-size:22px; font-weight:700; }}
.metric .value.good {{ color:var(--bound); }}
.metric .value.bad {{ color:var(--refuse); }}
.metric .value.warn {{ color:var(--seal); }}
table {{ width:100%; border-collapse:collapse; font-size:12px; }}
th {{ text-align:left; padding:8px 10px; border-bottom:1px solid var(--line);
  color:var(--dim); font-weight:600; text-transform:uppercase;
  font-size:10px; letter-spacing:.1em; }}
td {{ padding:8px 10px; border-bottom:1px solid rgba(36,42,54,.5); }}
tr:hover {{ background:var(--panel); }}
.section {{ margin-top:30px; }}
.section h2 {{ font-size:18px; font-weight:700; margin-bottom:12px; }}
</style>
</head>
<body>
<div class="wrap">
  <h1>Blast-Radius <em>Validation Report</em></h1>
  <p class="lede">Scientific validation of software change blast-radius analysis.
  {metrics['regression_cases']} regression cases and {metrics['control_cases']}
  control cases were run through the harness. Each experiment applies a code
  mutation, runs baseline and changed versions against identical inputs, and
  classifies the evidence into four levels: static suspicion, runtime reachable,
  behavioural change, or failure propagation.</p>

  <div class="metrics">
    <div class="metric"><div class="label">Regression Cases</div><div class="value">{metrics['regression_cases']}</div></div>
    <div class="metric"><div class="label">Control Cases</div><div class="value">{metrics['control_cases']}</div></div>
    <div class="metric"><div class="label">Detected</div><div class="value good">{metrics['detected_regressions']}</div></div>
    <div class="metric"><div class="label">Missed</div><div class="value bad">{metrics['missed_regressions']}</div></div>
    <div class="metric"><div class="label">False Positives</div><div class="value {'bad' if metrics['false_positives'] else 'good'}">{metrics['false_positives']}</div></div>
    <div class="metric"><div class="label">Precision</div><div class="value {'good' if metrics['precision'] >= 0.9 else 'warn'}">{metrics['precision']:.1%}</div></div>
    <div class="metric"><div class="label">Recall</div><div class="value {'good' if metrics['recall'] >= 0.9 else 'warn'}">{metrics['recall']:.1%}</div></div>
    <div class="metric"><div class="label">Existing Test Rate</div><div class="value warn">{metrics['existing_test_detection_rate']:.1%}</div></div>
    <div class="metric"><div class="label">Blast-Radius Rate</div><div class="value good">{metrics['blast_radius_detection_rate']:.1%}</div></div>
    <div class="metric"><div class="label">Additional Found</div><div class="value warn">{metrics['additional_regressions_found']}</div></div>
    <div class="metric"><div class="label">Median Runtime</div><div class="value">{metrics['median_runtime_seconds']:.2f}s</div></div>
  </div>

  <div class="section">
    <h2>Experiment Results</h2>
    <table>
      <thead>
        <tr>
          <th>Experiment</th>
          <th>Module</th>
          <th>Evidence Level</th>
          <th>Static Deps</th>
          <th>Behavioural Changes</th>
          <th>Tests Detect</th>
          <th>Runtime</th>
        </tr>
      </thead>
      <tbody>
        {rows_html}
      </tbody>
    </table>
  </div>

  <div class="section">
    <h2>Methodology</h2>
    <p style="color:var(--dim);max-width:80ch">
      Each experiment applies a targeted code mutation to one module, then runs
      identical inputs against the baseline and changed versions. The harness
      compares return values, exceptions, refusal rules, refusal reasons, and
      resolved paths. Evidence is classified into four levels:
      <strong style="color:var(--dimmer)">STATIC_SUSPICION</strong> (module is
      imported but no runtime path proven),
      <strong style="color:var(--bound)">RUNTIME_REACHABLE</strong> (code ran,
      no behavioural change),
      <strong style="color:var(--seal)">BEHAVIOURAL_CHANGE</strong> (output
      differs but decision unchanged), and
      <strong style="color:var(--refuse)">FAILURE_PROPAGATION</strong> (decision
      changed, CLI exit code or hook block affected). The existing test suite is
      run against each mutation to determine whether it would have caught the
      regression. Where evidence is unavailable, UNKNOWN is returned.
    </p>
  </div>
</div>
</body>
</html>"""


if __name__ == "__main__":
    sys.exit(main())
