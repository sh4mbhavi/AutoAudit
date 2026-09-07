# Phase 11 — release decision

- **Date:** 2026-09-07 (Australia/Melbourne)
- **Scope:** the integrated Phase 1–10 stack in `AutoAudit-phase-11`, branch
  `fix/soc2-phase-11-final-verification`, base `8736fcb9`
- **Decision:** **DO NOT RELEASE**
- **Decided by:** this verification phase, on the evidence in
  [verification.json](verification.json), [risk-register.json](risk-register.json)
  and [acceptance-criteria.json](acceptance-criteria.json)
- **Not decided:** whether to accept any of these risks. That is an owner
  decision, and this programme still has no named owners.

## The decision in one paragraph

The engineering is strong and the gates are green — 1,938 engine tests, 803
backend and tools tests, 582 OPA policy tests, a strict OPA check, seventeen
alert rules with unit tests, a tested backup restore, database-enforced
immutability, and identical results under UTC and Australia/Melbourne. None of
that is in question. The release is refused because **the reviewed production
topology cannot run a scan**, because **eighteen of the sixty-nine controls the
product advertises as ready can emit a result its own contract rejects**, because
**unknown evidence reads as a pass and unknown status reads as a failure**, because **a CI gate the programme
added cannot pass**, and because the three acceptance criteria that depend on
people — enforced checks, GRC approval of the crosswalk, and owned risks — have
no owner to satisfy them. **Six of the thirteen acceptance criteria in section
19.3 are not met**, five of them blocking, and the risk register carries **85
open risks — 7 blocking and 27 high — none with an owner.**

Every one of the technical blockers was invisible to ten prior phases for the
same reason: each was hidden behind exactly the kind of check this phase exists
to run — starting *all* the containers, evaluating the *ready* policies against
the engine's own contract, and running the gate the way CI runs it.

## What blocks the release

### 1. The production Compose topology cannot run a scan

`engine/powershell/service/main.py:63` is
`_EXECUTION_POOL: ThreadPoolExecutor | None = None` at module scope with no
`from __future__ import annotations`. The image's Python is **3.9.19**, where a
module-level annotated assignment is evaluated at runtime and PEP 604 `X | None`
raises `TypeError`. The container crash-loops. The `worker` declares
`depends_on: powershell-service: {condition: service_healthy}`, so it never
starts either.

Brought up as written, `docker-compose.production.yml` gives four healthy
services and two that never start. With no worker there is no Celery consumer,
and every scan a user creates sits in the outbox for ever.

Introduced by **Phase 9**; absent from phases 1–8, from the base commit and from
upstream. It survived because nothing starts or imports that module: the shipped
overlay smoke deliberately starts `db` and `redis` only, the PowerShell runtime
smoke exercises the *local Docker transport* rather than the HTTP service, and no
test imports `engine/powershell/service/main.py`.

One line fixes it, and that was verified: with the future-import added the module
imports cleanly under the image's own 3.9.19.

### 2. Eighteen of sixty-nine ready controls can emit a result the contract rejects

`OPAResult` requires `affected_resources` with `strict=True`, `extra="forbid"`
and no default.

- **Nine** ready v6.0.0 policies never emit it at all, so **every** evaluation is
  rejected: 4.1, 5.1.2.3, 5.1.3.1, 5.1.3.2, 5.1.4.1, 5.1.4.3, 5.1.4.4, 5.1.4.5,
  5.1.4.6.
- **Nine more** emit it in their computed result and omit it from their
  `default result`, so they are rejected **exactly when the default fires** —
  when evidence is missing or malformed: 1.2.2, 1.3.5, 2.1.9, 2.1.12, 2.1.13,
  2.1.14, 2.1.15, 6.5.2, 7.2.5.

Demonstrated with the pinned OPA 1.20.2 against 5.1.4.5 with valid *compliant*
evidence: the policy returns `compliant: true`, and `OPAResult.model_validate`
raises `affected_resources Field required`. `opa_client.py:159` turns that into
`ValueError("OPA returned an invalid result contract")` and `tasks.py:941`
records `EvaluationFailure("evaluation_error")`. The engine's handling is
correct — the error is never flattened into a pass or a fail. The controls are
simply unassessable whenever evaluation is reached.

The second group is harder to reason about, not easier: those controls work on
the happy path and become contract-invalid precisely on the unknown-evidence
path, so the defect only appears once something else has already gone wrong.

It shipped because the semantic suite covers the **44 crosswalked** controls, and
these are among the **25 ready controls the crosswalk does not reference**.

### 3. Unknown evidence reads as a pass, and unknown status reads as a failure

CIS 1.2.2 does `object.get(input, "shared_mailboxes", [])` with no type check,
and its unknown-status branch resolves to `compliant: false`. Every case below
was evaluated with the pinned OPA and then validated against the engine's own
contract:

| input | compliant | contract | recorded as |
|---|---|---|---|
| valid list, all disabled | true | accepted | passed ✓ |
| `{"shared_mailboxes": "oops"}` | true | accepted | **passed** |
| `{}` — key absent | true | accepted | **passed** |
| `{"shared_mailboxes": null}` | false | rejected | evaluation_error |
| `[{"account_disabled": null}]` | false | accepted | **failed** |

Two violations of acceptance criterion 7. A string produces **no bindings at
all** for `some mailbox in shared_mailboxes` — Rego does not iterate a string's
characters — so both comprehensions are empty and the control passes;
`count(shared_mailboxes)` then counts the string's **length**, writing *"Sign-in
is blocked for all 4 shared mailbox(es)"* into the audit record for four
mailboxes that do not exist. And a mailbox whose `account_disabled` the collector
could not determine is recorded as an ordinary tenant **failure**, not as
indeterminate.

The explicit-`null` case is the only one that behaves correctly, and only by
accident: its `default result` omits `affected_resources`, so the contract
rejects it (§2) and it becomes an error rather than the tenant failure its own
message describes.

The crosswalk's `residual_limitation` for CC6.3-P11 already reads *"Empty-evidence
behavior must be corrected"*. It is still uncorrected, and 1.2.2 is one of the 25
controls the crosswalk suite does not reach.

### 4. A CI gate this programme added cannot pass

`ci.supply-chain.yml`'s `hooks` job runs
`pre-commit run --all-files --show-diff-on-failure`. On a pristine committed copy
of this stack the first pass **modifies 221 files** (+2,812 / −1,547) through
`ruff-format`, `trailing-whitespace` and `end-of-file-fixer`. A second pass
modifies nothing and **still fails**: `ruff` reports **19 errors with no *safe*
auto-fix** — E402 ×9, E741 ×4, F841 ×4, E731, E712 — in `security/` (11),
`engine/` (7) and `backend-api/app/api/v1/platforms.py` (1). Six carry unsafe
fixes ruff will not apply on its own.

Most of it is inherited repository debt rather than Phase 10's code. That does
not change the outcome: the gate is red on the first pull request and stays red.
Phase 10 verified it by running `pre-commit` against only the 63 files it
changed, not `--all-files`.

### 5. Integration is a prerequisite, and it is now blocking

`upstream/main` has moved three times across phases 9, 10 and 11 and is **96
commits** ahead of the stack base.

- **PR #302 is merged** and `upstream/main` now has its own `/readiness` in the
  same `main.py`. The collision Phase 10 predicted arrived through a different
  pull request; **#361 is now `CONFLICTING`**. The two implementations differ in
  ways that matter — this stack checks the database *and* the broker with a
  per-check timeout and leaks no DSN; upstream's checks the database with no
  timeout.
- **The Alembic collision is real.** Revision `2899a0e678b6` exists under two
  filenames. Alembic warns and loads, then cannot resolve `head` on the combined
  graph — so `alembic upgrade head` fails, and with it
  `backend-api/entrypoint.sh:5`, which runs exactly that on every container
  start. Remove the duplicate file and the graph has two heads
  (`b9d4e17c6a52`, `8a7b91ea95d9`) and needs a new merge revision.
- **28 of 38 open pull requests** touch files this stack changes.
  `metadata.json` is contended by 9 and `registry.py` by 7 — the two files the
  delivery plan says must not be edited concurrently without a nominated
  integrator, and no integrator has been nominated in eleven phases.

### 6. The SOC 2 report has no caller

`GET /v1/scans/{scan_id}/soc2-report` is Phase 7's audit-facing surface: it
renders from the mapping snapshot pinned into the scan, transcribes every rating
verbatim, and carries the unapproved-approval block and the disclaimer. Thirty-
four backend tests cover it. `frontend/src/types/soc2.ts` types the entire
response contract.

**Nothing calls it.** `frontend/src/api/client.ts` has no `soc2` function and no
reference to the route; a search of the whole frontend finds the endpoint only in
that type file. The one download path in the client fetches
`/v1/evidence/reports/{filename}` — the Essential-Eight evidence scanner's
artifact, not a compliance report.

Plan item 19.1.12 asks for a SOC 2 evidence pack and a GRC reviewer tracing a
sample through it. The pack is an authenticated JSON response with no caller, no
export and no UI: the reviewer needs an engineer with a token. The types were
written and the wiring was never done.

### 7. The public site claims two standards and an export the product does not have

Plan item 19.1.14 asks for public documentation and claims to be reviewed against
actual status, and section 19.4 forbids describing technical readiness as a
completed examination. Two claims are live on the public site today:

- **`AboutUs.tsx:68`**, under the heading *"Industry Standards We Support"*,
  lists **NIST Framework** and **ISO 27001** beside CIS and the Essential Eight
  as if the four were equivalent. There is no NIST or ISO 27001 policy,
  collector, metadata record or benchmark, and `GET /v1/benchmarks` cannot return
  one. What exists is `security/strategies/custom_benchmarks.py:83` and `:91` —
  keyword checkers over an uploaded document carrying **one rule each**, in the
  unmaintained TPRM module. Two of the four entries are a 140-control automated
  benchmark; the other two are a keyword search of a customer-supplied file.
- **`FAQSection.tsx:43`**: *"Yes! Generate and export comprehensive compliance
  reports in PDF, Excel, or CSV formats. Reports are audit-ready…"* No PDF,
  spreadsheet or CSV generation exists in `backend-api/app`. The only report
  surfaces are a JSON endpoint and a stored evidence object; the one "Download
  PDF" control belongs to the Essential-Eight evidence scanner. Four further
  pages carry audit-readiness wording, including a hero that promises
  *"Export audit-ready documentation instantly"*.

Worth stating alongside those: **no SOC 2 certification or attestation claim
exists anywhere outside the phase documents.** A search of `README.md`,
`SECURITY.md`, `docs/` and the whole frontend finds SOC 2 only as a report
contract and its types. On the specific anti-pattern the plan names — describing
technical readiness as a completed examination — this programme has been
disciplined. The two false claims above are about other standards and a
capability, not about SOC 2 status.

D08 — the decision that would govern public wording — is an unapproved draft
with no owner, and is not in this branch.

### 8. What the adversarial pass added

Fourteen independent verifiers produced 93 candidate findings; each faced three
refuters defaulting to REFUTED, and **71 survived**. The full set is in
[risk-register.json](risk-register.json). The ones that bear on the decision:

- **Six more policies mishandle unknown evidence.** CIS 3.1.1 stores missing
  audit-log evidence as a tenant **fail**; 2.1.12, 2.1.13 and 2.1.14 map their
  own explicit *unknown* branch onto `compliant: false`; 1.3.5, 7.2.5 and 7.3.1
  store a null setting as an ordinary fail; 6.3.1, 6.5.3, 2.1.8 and 2.1.10 **pass**
  on an empty population their collectors fabricate from a null response. And
  v4.0.0's 1.3.1 records a **pass** when the evidence key is absent entirely.
  §3 is not one bad policy; it is a pattern across the 25 controls the crosswalk
  does not cover.
- **The preview-deploy workflow has been dead since Phase 5**, and still carries
  the known default credential. It sets `APP_ENV=preview`, and
  `config.py:125` returns early only for `dev` — so the validator runs,
  `autoaudit_dev_password` fails the strength check, `redis://` fails the TLS
  requirement, `Settings()` raises at import, and the container exits before
  uvicorn. It is byte-identical across every phase snapshot since Phase 7.
- **Phase 10's alert-metric gate has a hole in it.**
  `tools/ci/check_alert_metrics.py` silently drops the expression of any rule
  whose `expr:` key comes before its `alert:` key, so those metric names are
  never checked — a second bypass of the same gate Phase 10 already found one
  bypass in.
- **Evidence is destructible in more ways than Phase 10 recorded.** Deleting an
  artifact leaves an encrypted excerpt of the same evidence behind in
  `evidence_validation`; an approved manual-evidence bundle's attachments can be
  destroyed unilaterally by the submitter; `delete_scan` severs evidence from the
  control it proves, unaudited; the hold endpoint's stated "the owner cannot lift
  their own" is not implemented; and Phase 10's own recorded bypass list is
  inaccurate about two of the three paths it names. Neither of Phase 10's two new
  evidence-lifecycle endpoints has a test anywhere.
- **`POST /v1/auth/login` has no rate limiting, throttling or lockout** anywhere
  in the tree.
- **More public copy that is not true:** a 99.9% uptime commitment, "real-time"
  and "continuous" monitoring on six surfaces for a product with no scheduler, a
  14-day free trial and Premium/Enterprise support plans with no billing system,
  and claimed customer counts for a product with no production deployment.

The refuters also did the opposite job, and it is worth recording: they rejected
the claims that GRC approval and risk ownership are *defects* — correctly, since
both are externally blocked and repeatedly recorded as such — and rejected "no
evidence-pack generator exists" and "no scan is re-derivable from provenance" as
overstated. Those are carried as unmet criteria and as a documented break in the
traceability chain, not as defects.

### 9. The criteria that need people

| Criterion | State |
|---|---|
| 2 — required checks enforced and green | Enforcement unverifiable (the account is not an administrator; `branches/main/protection` returns 404 and rulesets are empty). Green is disproved by §4 above. |
| 12 — GRC approves the crosswalk, limitations, public wording | `mapping.json` is `proposed_pending_grc_approval`, `approval.approved: false`, every reviewer field null. |
| 13 — remaining risks have named owners, due dates, documented acceptance | Every row of this register carries `owner: null`. So does every row of the CC1–CC9 register, by design. |
| — | Phase 0 decisions **D01–D10 are cited 62 times across fourteen files in the Phase 1–10 handoffs and exist in no branch that would be merged.** They live only as untracked files in a different worktree, along with the execution plan itself. |

Section 19.4 states: *"Do not mark the program complete with an unowned accepted
risk."* This phase does not mark it complete.

## What is genuinely ready

Recording this plainly, because "do not release" should not be read as "the work
is not good".

- **Gates.** Engine 1,938 passed / 1 skipped / 11 xfailed. Backend and tools 803
  passed. `opa test` 582/582. `opa check --strict` clean. promtool: 17 rules,
  unit tests SUCCESS. Alert-metric, organizational-register, control-status,
  promotion and API-type gates all clean. Frontend typecheck, 262 tests, build
  and lint clean. Every one of these also passes **from a clean checkout** — a
  1,006-file export with no `.git`, no virtualenv and no `node_modules`, with a
  fresh `uv sync --frozen` and `npm ci` — with one precondition that nothing in
  the repository declares: 21 tests need the checkout to be a git repository, or
  `ENGINE_GIT_SHA` to be set. Supplied, the clean-checkout engine result is
  identical to the worktree's; CI's `actions/checkout` satisfies it, so no CI job
  is affected today.
- **Timezone.** Both suites re-run in full against a second PostgreSQL cluster
  at `Australia/Melbourne`: byte-identical to the UTC results.
- **Containers.** `container_smoke.py` PASS. `production_overlay_smoke.py` PASS.
  Under the full production overlay, `db`, `redis`, `backend-api` and
  `dispatcher` all reach healthy with zero restarts, only the API publishes a
  host port, and `/readiness` answers `200 {"status":"ready","checks":{"database":{"ok":true},"broker":{"ok":true}}}`
  against a production-configured database and a TLS-authenticated Redis.
- **Migrations.** Exactly one head. Clean-database upgrade applies the full chain
  and is idempotent. Prior-head upgrades are tested. Downgrades deliberately
  refuse, consistently, pointing at the tested restore.
- **Immutability is enforced by the database, not by application code** — Phase 3
  terminal-result and scan-input triggers, Phase 7 append-only audit and manual
  revision triggers, Phase 8 append-only drift triggers.
- **Traceability holds for five of its six links.** Report → mapping → result →
  policy → collector → provenance all resolve unaided, and `policy_source` stores
  the evaluated Rego verbatim. The sixth link is the break: only the input
  *digest* is stored, so what the judgement was made on cannot be recovered.
- **The crosswalk is clean.** An independent check of `mapping.json` against
  Appendix A and Appendix B raised no finding across 24 verified assertions.

## Conditions for reconsidering

The execution plan for conditions 1–7 is
[remediation-plan.md](remediation-plan.md), which also adds the evidence-lifecycle
and residual-security work this list originally omitted (criteria 6 and 11).
It has since been executed: [remediation-report.md](remediation-report.md)
records the outcome, including that condition 2 turned out to be thirty policies
rather than eighteen.

1. Fix §1 (one line) and add an overlay smoke that starts every service.
2. Fix §2 (eighteen policies) and add a gate that validates every **ready** control's
   output against `OPAResult`, not only the 44 crosswalked ones.
3. Fix §3 — which is a pattern, not one policy: eleven controls across CIS 3.1.1,
   2.1.12–2.1.14, 1.3.5, 7.2.5, 7.3.1, 6.3.1, 6.5.3, 2.1.8, 2.1.10 and v4.0.0's
   1.3.1 mishandle unknown or empty evidence — and settle D03 so the
   zero-resource case has an approved answer.
4. Make `pre-commit run --all-files` pass, or scope the hook and say so. Close
   the `check_alert_metrics.py` key-order hole while you are in that file.
5. Wire the SOC 2 report to something a reviewer can reach (§6), and correct the
   public claims (§7 and §8). Delete or repair `pr.preview-deploy.yml`, which has
   been dead since Phase 5 and still carries the known default credential.
6. Integrate with `upstream/main` in the order set out in
   [coordination-review.md](coordination-review.md), with a nominated integrator
   for `metadata.json` and `registry.py`.
7. Bring `docs/compliance/phase-0/` and the execution plan into the branch, or
   state in every handoff that they are not part of the deliverable.
8. A repository administrator exports the branch-protection settings and applies
   the required-check set.
9. GRC approves the crosswalk, the limitations and the public wording; D01–D10
   get owners and decisions; every row of this register gets an owner, a due date
   and an explicit acceptance or rejection.
10. Then re-run Phase 11. Items 1–7 are engineering or documentation and can
    start now; 8 and 9 cannot.

## What this decision is not

It is not a SOC 2 examination, an attestation, or a statement that the product is
or is not compliant. No independent auditor has examined anything here, no
control has an execution record, and the crosswalk that would frame such a
statement is unapproved. This is an engineering release decision about a branch.
