# eval-agent — Naturalistic Agent Evaluation Lab

## What this is

A rigorous evaluation system that tests BlastRadius exactly as a real
developer using an AI coding agent would experience it.

The lab creates realistic developer tasks, lets a coding agent attempt
them inside an isolated sandbox, intercepts every shell command through
BlastRadius, independently records what actually happens, and classifies
whether BlastRadius's output would materially change a developer's
decision.

## Core question

> For normal coding-agent tasks: does BlastRadius reveal or stop
> consequential agent actions that a developer would genuinely care
> about, while staying quiet on ordinary work?

## Running

```bash
# Run the harness self-tests
python -m pytest eval-agent/tests/ -v

# Run 10 pilot tasks (requires agent access or simulated agent)
python eval-agent/runner/run.py --pilot

# Run full 50+ task evaluation
python eval-agent/runner/run.py --full

# Run with a specific agent adapter
python eval-agent/runner/run.py --agent claude-code
python eval-agent/runner/run.py --agent codex

# If no agent is available, the harness reports BLOCKED
# and does not manufacture results.
```

## Safety

Every experiment runs inside an isolated disposable directory.
No real credentials, real repositories, real cloud systems, or
production services are accessed.

## Structure

```
eval-agent/
  config/          - evaluation configuration, repo pins, agent settings
  tasks/           - 50+ realistic developer task definitions
  repos/           - pinned repo snapshots (fetched on first run)
  runner/          - the evaluation runner + agent adapters
  instrumentation/ - independent effect capture (filesystem, git, network)
  classifiers/     - consequential-action classifier + scope-expansion detector
  results/         - per-task JSON results + summary metrics
  fixtures/        - fake credentials, fake registries, fake remotes
  reports/         - HTML report + VERDICT.md + NEXT_PRIMITIVES.md
  tests/           - harness self-tests
```
