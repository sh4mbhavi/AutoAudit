# Phase 11 remediation — what was done, and what is left

Companion to [release-decision.md](release-decision.md) and
[remediation-plan.md](remediation-plan.md). The decision was **DO NOT RELEASE**
with ten conditions. Seven needed no permission we do not have; this records
what happened to them.

**Branch:** `fix/soc2-phase-11-conditions`, ten commits over the Phase 1–11
baseline (`f1d90867`), 327 files changed. `AutoAudit-phase-11` is untouched: its
value is that it changed nothing.

## Headline

Every engineering condition that could be closed without a decision or a
permission is closed. What remains is **two decisions and two permissions**, and
one merge that is blocked on the decisions.

Of the six section-19.3 criteria that were NOT MET, three are now met — including
all three that were blocking *and* within engineering's gift. The three still
outstanding need a repository administrator (branch protection) and a named GRC
authority (crosswalk approval, risk ownership).

## The four blockers

| # | blocker | state |
|---|---|---|
| 1 | Production topology cannot run a scan | **closed** — all six services healthy, worker answers a Celery ping over the TLS broker, verified twice |
| 2 | Ready controls emit contract-rejected results | **closed** — 30 controls fixed (18 were counted by reading; executing found 30), gated over all 76 |
| 3 | Unknown evidence reads as a pass | **closed** — same 30 controls, plus a direct-test gate over every ready control |
| 4 | `pre-commit --all-files` cannot pass | **closed** — exits 0 twice in a row, no file modified |

### 1. The production topology

`engine/powershell/service/main.py` carried a module-level `ThreadPoolExecutor |
None` annotation. Mariner's `python3` is 3.9, so PEP 604 raised `TypeError` at
import, the container crash-looped, and the worker — which waits on it being
healthy — never started. Reproduced against a real 3.9 interpreter, fixed with
`typing.Optional`, and gated by
`tools/tests/test_powershell_service_python_floor.py`, which parses the service
against the 3.9 grammar, rejects PEP 604 in any annotation evaluated at import,
and asserts the floor it enforces still matches `pyproject.toml` and the
Dockerfile.

`tools/ci/production_overlay_smoke.py` now starts all six services rather than
two, and asserts the two things that were missing: the worker answers
`celery inspect ping`, and `/readiness` answers. The wider scope immediately
found that the harness's own Redis ACL needed `&*` — Redis 7 starts every user
with `resetchannels`, so `~* +@all` grants every key and command and still denies
the pub/sub channel Celery's `mingle` step opens. `docs/compliance/phase-5/
deployment.md` told the deployment owner to restrict the ACL and never mentioned
channels; it does now.

### 2 and 3. The policy corpus

Phase 11 counted 18 controls that could emit a document `OPAResult` rejects, by
reading the source. Executing every ready policy against seven hostile input
shapes found **30**: nine that never emitted `affected_resources`, nine that
omitted it only from `default result`, two that had it only in the default, four
that lost it on some paths, and six in the older CIS versions and Essential
Eight that no phase had looked at, because "ready" had only ever been audited for
v6.0.0.

The worst of the indeterminacy defects:

- **1.2.2** reported `{"shared_mailboxes": "oops"}` as "Sign-in is blocked for
  all 4 shared mailbox(es)" — 4 being the length of the word.
- **1.3.5** put `input.collector_error` in its details, a key absent from healthy
  evidence, so the computed rule never fired: the control returned its default
  for every input it has ever seen, including a compliant tenant.
- **v4.0.0/1.3.1** answered "All 0 managed domain(s) have password expiration
  disabled" when the domains key was absent — a pass built from no evidence.
- **3.1.1** stored missing audit-log evidence as a tenant failure of the audit
  control.
- **E8-PRIV-1.1** answered `compliant: false` with the message "No admin accounts
  detected - check collector permissions".
- **2.1.15** compared `NotifyOutboundSpamRecipients` for equality against a
  hard-coded example address, so every tenant with its own address failed.

All 30 now follow the shape Phase 2 established in 2.1.5. Three existing tests
asserted the defect rather than the behaviour — 5.1.4.4, 1.2.2 and E8-PRIV-1.1
each had a case named for unable-to-determine that asserted `compliant == false`.

Two gates exist because their absence is why this survived ten phases:
`test_result_contract_over_policies.py` evaluates every ready control across all
four selectable benchmarks against `OPAResult`, and asserts every one is
exercised by at least one direct Rego test.

`opa test` went from 582 to 972.

## Criteria, re-evaluated

| # | criterion | before | after |
|---|---|---|---|
| 1 | Worktree and artifacts controlled and reproducible | met with qualifications | **met** |
| 2 | All required checks enforced and green | NOT MET (blocking) | **green; enforcement still unverifiable** — needs condition 8 |
| 3 | Exactly one Alembic head | met here, fails on integration | unchanged — needs the upstream merge |
| 4 | Strict OPA check and every policy test pass | met | **met** (972, was 582) |
| 5 | Appendix B semantic and collector coverage | met as written | **met, and extended to all 76 ready controls** |
| 6 | No known credential or broken class | NOT MET on one of five | **met** |
| 7 | Unknown/error cannot appear as pass or ordinary noncompliance | NOT MET (blocking) | **met** |
| 8 | Compliance and coverage both displayed | met | **met, and now reachable** |
| 9 | Scan lifecycle failure and redelivery | met | met |
| 10 | Cross-tenant SharePoint impossible | met at test level | unchanged |
| 11 | Evidence owner-authorized, immutable, retained | NOT MET (blocking) | **met** |
| 12 | GRC approves crosswalk, limitations, wording | NOT MET, externally blocked | unchanged — needs condition 9 |
| 13 | Remaining risks have named owners | NOT MET (blocking) | unchanged — needs condition 9 |

## Phase 11's four decisive checks, re-run

1. **All six production services started, six healthy.** PASS, twice — once with
   the PowerShell fix, once again after every base image was digest-pinned and
   the piped `curl | sh` uv installer was replaced.
2. **Every ready policy evaluated against `OPAResult`.** 76 of 76 accepted, from
   a gate that is now part of the engine suite.
3. **`pre-commit run --all-files` the way CI runs it.** Exit 0, twice in a row,
   no file modified.
4. **Suites from a checkout with no `.git`, `ENGINE_GIT_SHA` supplied.** 2092
   engine and 908 backend/tools passed. This check found two tests that depended
   on the checkout being a repository; both fixed.

Under `TZ=Australia/Melbourne`: identical.

## What is left

**Two decisions, which gate the upstream merge (W2):**

1. **Which `/readiness` survives.** `upstream/main` shipped its own in PR #302;
   this stack has a different one with per-check timeouts and a broker check.
   Keeping both silently shadows one.
2. **Who integrates `metadata.json` and `registry.py`.** Nine open PRs touch the
   first and seven touch the second.

Until those are answered, the duplicate Alembic revision `2899a0e678b6` and the
second head remain, and criterion 3 stays conditional. Nothing else on this
branch depends on them.

**Two permissions, which are conditions 8 and 9:**

- **Condition 8** needs a repository administrator to export and apply branch
  protection. Criterion 2 cannot be verified from here at all —
  the account this work was done from cannot read the protection settings.
- **Condition 9** needs a named GRC authority to approve the crosswalk, settle
  D01–D10 and take ownership of the open risks. Criteria 12 and 13 are that
  approval.

**One decision that would improve a policy answer, not block one:** **D03**,
zero-resource results. Where a collector fabricates an empty population from a
null response, the unambiguous half is closed — `default_policy` and the totals
distinguish "no policy exists" from "a policy exists and is empty". A genuinely
zero population still needs D03.

## Findings this work added to the record

Things not in the Phase 11 register, found by doing the work:

- **The contract defect is 30 controls, not 18.** Reading found 18; executing
  found 30. Six were in benchmarks no phase had audited.
- **1.3.5 could never produce a result at all**, for any input, because of an
  undefined key in its details object.
- **Deleting a scan returned a 500**, not the silent severing the register
  recorded: `ON DELETE SET NULL` and the Phase 7 identity trigger contradict each
  other. Now an explicit, audited 409.
- **The alert-metrics gate had a second key-order bypass** — a rule with `expr:`
  before `alert:` had its expression dropped entirely.
- **`engine/docker/powershell/Dockerfile`** was a stale duplicate of the
  PowerShell image with an unpinned base and unpinned gallery modules, built by
  nothing, present since before Phase 7.
- **The product-claims gate found two more claim sites** than the register
  listed — "Real-time compliance monitoring" on both auth brand panels, and a
  "Start Free Trial" button on the landing CTA.
- **Nothing enforces `.nvmrc` locally.** Node ≥24.5 defines a global
  `localStorage` that is undefined without `--localstorage-file`; vitest's jsdom
  environment skips any key already on the Node global, so on Node 26 twelve
  frontend tests fail for a reason that has nothing to do with the code.
- **`detect-secrets-hook` requires a git working tree**, so the secret gate could
  not run against a released tarball or an unpacked image layer.
