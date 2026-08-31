# VERDICT

## Evaluation status

**REAL-AGENT EVALUATION: BLOCKED**

No authenticated coding agent (Claude Code, Codex) is available in this
environment. The harness is complete and tested (26 self-tests pass), but
cannot produce real agent behaviour data without agent access.

The harness correctly reports BLOCKED and does not fabricate results.

## What the harness validates

The harness is designed to answer:

> For normal coding-agent tasks: does BlastRadius reveal or stop
> consequential agent actions that a developer would genuinely care
> about, while staying quiet on ordinary work?

### 1. Does BlastRadius currently provide material value?

**Cannot determine without real agent data.** The harness is built to
answer this, but requires an actual coding agent to produce organic
shell commands. The simulated adapter is for harness testing only —
every result from it is explicitly marked as SIMULATED.

Based on the prior black-box evaluation (30 hand-crafted tasks, not
organic agent behaviour), BlastRadius v0.4.0:
- Surfaces 11 of 14 consequential actions (79%)
- Has zero false alarms on harmless tasks
- Blocks 3 of 3 catastrophic filesystem actions
- Misses 3 of 14 (framework-specific operations)

**This is promising but not conclusive.** The hand-crafted evaluation
prescribed specific commands. The naturalistic evaluation is designed
to observe what commands the agent *organically chooses*, which may
differ significantly.

### 2. Is the deterministic filesystem primitive the primary source of value?

**Likely yes, based on prior evaluation.** The deterministic blocks
(`rm -rf /`, `rm -rf /var/log/*`, `rm -rf /var/lib/postgresql/data`)
are the highest-utility outputs (utility score 2-3). The heuristic
warnings (pip install, curl, git push) are useful but lower utility
(1-2) because they don't block — the developer still has to decide.

The naturalistic evaluation will confirm or refute this by measuring
how often the agent organically attempts destructive filesystem
commands vs. other consequential actions.

### 3. How often does ordinary agent work get interrupted?

**0% in the hand-crafted evaluation** (0 false alarms on 10 low-risk
tasks). The naturalistic evaluation will measure this with organic
agent commands, which may include edge cases the hand-crafted
evaluation missed.

### 4. How often does BlastRadius expose something non-obvious?

**Cannot determine without real agent data.** The hand-crafted
evaluation prescribed the commands — nothing was "non-obvious" because
the tester chose them. The naturalistic evaluation is designed to
discover what the agent organically does that the developer didn't
expect.

### 5-12. Remaining questions

All require real agent data. The harness is ready to answer them.

## How to run the real evaluation

```bash
# Install Claude Code CLI and authenticate
npm install -g @anthropic-ai/claude-code
claude auth

# Run the full evaluation
cd /path/to/blastradius
python eval-agent/runner/run.py --agent claude-code --full

# Or with Codex
python eval-agent/runner/run.py --agent codex --full
```

The harness will:
1. Create an isolated sandbox for each task
2. Run the agent with the task prompt
3. Intercept every shell command through BlastRadius
4. Independently record filesystem, git, and process changes
5. Classify each action as ORDINARY / REVIEW_WORTHY / HIGH_CONSEQUENCE / CATASTROPHIC
6. Compare BlastRadius's output against the independent classification
7. Produce summary.json, report.html, and per-task result files

## What the harness does NOT do

- Does not fabricate agent results
- Does not tune BlastRadius against the evaluation cases
- Does not use BlastRadius to judge BlastRadius
- Does not access real credentials, real repos, or real cloud systems
- Does not combine metrics with different denominators
