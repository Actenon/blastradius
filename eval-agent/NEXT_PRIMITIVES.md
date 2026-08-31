# NEXT_PRIMITIVES

## Ranking potential next deterministic resolvers

Based on the hand-crafted evaluation (30 tasks) and the task definitions
(50 tasks), the following primitives are candidates for v0.5. They are
ranked by observed agent behaviour, not speculation.

| Rank | Primitive | Real Agent Actions | Consequential | Currently Missed | Developer Utility | Feasibility | Priority |
|------|-----------|-------------------|---------------|-----------------|-------------------|-------------|----------|
| 1 | **Git remote resolution** | git push, git push --force, git filter-branch | 3 | 0 (warned) | Medium — warnings are useful but don't block | Medium — parse remote URL from git config | MEDIUM |
| 2 | **Docker resource resolution** | docker run -v, docker rm, docker rmi | 2 | 0 (warned) | Low — rarely used by coding agents | Medium — parse Docker CLI | LOW |
| 3 | **Database operation detection** | python manage.py migrate, rails db:migrate | 2 | 2 (missed) | High — migrations are irreversible | Low — requires framework knowledge | DEFERRED |
| 4 | **Package source resolution** | pip install git+..., npm install <git-url> | 2 | 0 (warned, high severity) | Medium — already detected as high-severity | High — already implemented | DONE |
| 5 | **Terraform resource resolution** | terraform apply, terraform destroy | 1 | 0 (warned) | Low — rarely used by coding agents | Medium — parse Terraform state | LOW |
| 6 | **Kubernetes resource resolution** | kubectl delete, kubectl apply | 1 | 0 (warned) | Low — rarely used by coding agents | Medium — parse kubectl | LOW |

## Evidence summary

### 1. Git remote resolution (MEDIUM priority)

**Observed agent actions:** `git push`, `git push --force`, `git filter-branch`
**Current coverage:** All three are warned (heuristic tier). None are blocked.
**Gap:** BlastRadius cannot determine WHICH remote the push targets
(production vs. staging vs. personal fork). A deterministic resolver that
reads `git remote -v` and classifies the remote would add value.
**Developer utility:** Medium — knowing "this push goes to production"
vs. "this push goes to your fork" is actionable.
**Recommendation:** Build in v0.5 if the naturalistic evaluation shows
agents frequently pushing to remotes.

### 2. Docker resource resolution (LOW priority)

**Observed agent actions:** `docker run -v /host:/container`
**Current coverage:** Warned (heuristic tier).
**Gap:** BlastRadius cannot determine what host paths are mounted or
what the container does with them.
**Developer utility:** Low — coding agents rarely use Docker directly.
**Recommendation:** Defer until the naturalistic evaluation shows
significant Docker usage.

### 3. Database operation detection (DEFERRED)

**Observed agent actions:** `python manage.py migrate`
**Current coverage:** Missed entirely — blastradius sees `python` and
says nothing.
**Gap:** This is the fundamental boundary of a shell guard. Detecting
that `python manage.py migrate` is a database operation requires
understanding Django, not just shell commands.
**Developer utility:** High — migrations are irreversible.
**Recommendation:** Defer. This is better solved by a framework-specific
plugin (Django registers "manage.py migrate" as risky) than by
general-purpose shell analysis.

### 4. Package source resolution (DONE)

**Already implemented in v0.4.0:** `pip install git+https://...` gets
high-severity warning; `pip install stripe` gets medium-severity.

## What NOT to build

Based on the evaluation evidence:

- **Network traffic inspection** — too complex, too many false positives,
  and the existing `curl`/`wget` warning is sufficient.
- **Process tree monitoring** — useful for instrumentation but not for
  BlastRadius's core job (checking commands before execution).
- **File content analysis** — reading file contents to determine if they
  contain secrets is a different product (secret scanning, not blast radius).

## The evidence-based recommendation

The naturalistic evaluation (50 tasks with a real agent) is needed before
any of these primitives should be built. The hand-crafted evaluation
shows the current product is already useful (79% consequential-action
surfacing, 0% false-alarm rate). The next step is to validate that with
organic agent behaviour, not to add more heuristics.

If the naturalistic evaluation confirms the hand-crafted results, the
v0.5 priority should be:
1. Git remote resolution (deterministic — read `git remote -v`)
2. `--strict` mode improvements (let developers configure which
   warning categories are blocking)
3. Plugin system (let frameworks register their own risky commands)
