# Phase 10 — Production operations and organizational SOC 2 evidence

Date: 2026-09-07 (Australia/Melbourne).

Local engineering implemented. The platform decision, every organizational
control owner, and all operating evidence remain externally blocked. No public
PR, production service, external tenant, credential or repository setting was
changed.

## Baseline and workspace

- Worktree: `/Users/clupa/Documents/projects/autoaudit/AutoAudit-phase-10`.
- Branch: `fix/soc2-phase-10-production-operations`; uncommitted and unpushed.
- Git base: Phase 1 `8736fcb9`, overlaid with the complete Phase 9 working
  source. [phase-9-snapshot.json](phase-9-snapshot.json) records SHA-256 for all
  972 prerequisite files; the overlay was verified byte-identical, and
  `git status` compared entry-for-entry against the Phase 9 worktree, before any
  Phase 10 change. Every earlier worktree is preserved and untouched.
- **Upstream moved again.** Phase 9 recorded `bfb8edd4`; it is now `0a074cc9`
  (PRs #294, #330, #352). [Coordination review](coordination-review.md) records
  that, the 43 open PRs, and the two that collide with Phase 10 in substance.
  One of them, **PR #361, creates the same file and the same endpoint Phase 10
  created independently.**
- Phase 9's recorded results were reproduced here before any change:
  engine 1,914 passed / 1 skipped / 11 xfailed; backend and tools 639 passed;
  `opa check --strict` clean; `opa test` 582/582; frontend 262 tests.
- Phase 10 changes only: [phase-10-changes.json](phase-10-changes.json).

## What this phase is, and what it refuses to be

Plan section 18 has two halves. The engineering half (18.1, ten items) is
repository work. The governance half (18.2, CC1–CC9) is organizational evidence
that a repository cannot produce: it needs named owners, executed activities and
management review, and Phase 0 decisions D01–D10 remain unapproved drafts with
no named owners — recorded identically in the Phase 7, 8 and 9 handoffs.

So Phase 10 built the mechanisms and **refused to manufacture the approvals**.
Three refusals in particular are deliberate and are the phase's most important
decisions:

- **It did not select a deployment platform.** It removed three false claims
  that a reader would have taken for a decision already made, and recorded the
  option space in [deployment-platform-decision.md](deployment-platform-decision.md).
- **It did not set a retention period, and its retention tool deletes nothing.**
  D04 governs retention and says outright that no automatic cleanup is
  authorized by it.
- **It did not appoint a single control owner.** Every row of the CC1–CC9
  register carries `owner: null` and the decision that would assign one.

## Every alert in this repository was unfireable

Six rule files referenced seventeen metric names. **Eleven of them appeared
nowhere else in the repository**, and no Prometheus, Alertmanager or exporter is
deployed by anything here. Two rules used `absent_over_time` on a metric nothing
emitted, so from the moment Prometheus was first stood up they would have fired
permanently — eight pages a day, for ever, on day one.

That is the plan's first anti-pattern guard: *do not treat conceptual monitoring
YAML as proof that monitoring operates.*

### What is emitted now

`GET /metrics` on the API (`backend-api/app/core/metrics.py`) reports the
request-level series only it can see. Everything about scans is derived from the
**database** by the dispatcher (`engine/worker/metrics.py`).

That second choice is the substantive one. The obvious design is a counter in
the Celery worker, and it is wrong here for three reasons: the worker runs
`--pool=prefork --concurrency=4`, so a counter in a forked child is invisible to
a scrape of the parent; a counter resets on restart, so an operator comparing
"errors this hour" against the scan record would find two numbers and no way to
tell which is right; and **the database is the audit record** — a metric read
from the scan and result rows cannot disagree with the evidence an auditor
reads, while a parallel counter can.

The cost is stated rather than hidden: a gauge sampled on a poll cannot measure
something that starts and finishes between two samples. Per-collection latency is
exactly that, and Phase 9's outbox deletes its row at settlement, so it cannot be
recovered afterwards either. **This phase ships no collection-duration series at
all rather than a misleading one.**

Nine metrics are emitted; nine are declared external in
`tools/ci/external_metrics.json` with the exporter that must provide them. Six of
those nine exist only on Kubernetes, which the repository does not deploy — so
they are labelled `platform: kubernetes` and a non-Kubernetes deployment drops
them by selector rather than by editing.

### What was retired, and why

Seven rules are gone, each with its reason recorded in
[`RETIRED-ALERTS.md`](../../../infrastructure/monitoring/alerts/RETIRED-ALERTS.md):

- **`FailedAuditChecks`** paged the infrastructure team when a *tenant* was
  non-compliant. A failed control is the product working correctly and reporting
  a true finding; D01 and D02 are explicit that a control failure and a
  collection failure are different things. Its operational half —
  controls that could not be assessed — is now `ControlErrorRateHigh`.
- **`SuspiciousPrivilegeEscalation`** had no honest signal: **no API route in
  AutoAudit writes `user.role`.** Roles are set by the production-prohibited
  development seed or out of band against the database, so the application
  cannot observe a change it never performs. A counter that is structurally
  always zero would read as coverage.
- **`UnauthorisedAccessAttempt`** measured *host* failed logins via an auditd
  exporter that is not deployed, while its description described application
  authentication. Failed authentication against the API is already fully
  described by the error counter, filtered to the auth routes.
- **`ScanEngineFailure`** was defined **twice**, in two files, with the same
  expression and conflicting severity and team. Alertmanager groups by
  `['alertname','team']`, so one condition produced two notifications whose two
  runbook anchors gave contradictory advice.
- The two CI/CD rules could only be fed by a Pushgateway that is not deployed,
  and were the only two alerts in the repository with no runbook at all.

`MissingComplianceScans` was rewritten rather than dropped: scans are
user-initiated, so "no scan in the last hour" is the normal state of any real
deployment. A last-completion timestamp is a question that can be answered.

### The gate that keeps it honest

`tools/ci/check_alert_metrics.py` fails the build when an alert reads a metric
that is neither emitted by the application nor declared external. It binds in
both directions: deleting an emitter breaks the alert that reads it, and an
unused external declaration is rejected as the way a retired name creeps back.

`ci.validate-alerts.yml` was rebuilt around it. It is **no longer path-filtered**
— deleting a metric emitter in the application is what actually breaks an alert,
and the old filter meant that ran no alert validation at all. promtool is now
pinned and checksum-verified (`tools/ci/install_promtool.py`), matching the
convention `install_opa.py` established in Phase 4 rather than
`apt-get install -y prometheus`.

`promtool test rules` replaced `alert_simulation_test.py`, which required a live
Prometheus and Pushgateway at hardcoded localhost URLs, was run by nothing, and
**could not have passed**: it pushed a constant gauge value and asserted `rate()`
of it exceeded 10. The rate of a constant is zero. Its second test passed by
accident, for the same reason.

The unit tests pin what a threshold *means*: that server errors fire and a burst
of expired sessions does not; that a tenant with many failed controls pages
nobody; that `ScanExporterDown` fires on an absent series and not only a zero
one; and that the network threshold means gigabits, which it did not — the
expression said 1,000,000,000 **bytes** per second while its description and
runbook both said 1 Gbps, an error of 8×.

## Key rotation

Before Phase 10 there was one Fernet key and no fallback. Changing
`ENCRYPTION_KEY` made every stored M365 client secret permanently unreadable at
the next restart — a fact Phase 5's deployment note warned about and nothing in
the code could soften.

`ENCRYPTION_KEY` still encrypts; `ENCRYPTION_KEY_DECRYPT_ONLY` lists retired keys
that may still decrypt. That makes a rotation a window rather than a cutover.
`tools/ops/rotate_encryption_key.py` rewrites each row not already under the
primary key, one at a time under `FOR UPDATE` — the lock matters, because the
connection update route can rewrite the same secret between the read and the
write.

The pass is resumable because `needs_rewrite()` answers "is this row current" by
trial decryption under the primary key alone, so an interrupted run picks up
where it stopped without a key-id column on five tables.

The API and the worker hold the same ring and share no code, which is the
situation the PowerShell executor already documents about its duplicated
validator. Both sides are asserted, because a rotation implemented in only one
fails silently, at scan time, deep inside a collection.

`evidence_validation.extracted_text_encrypted` is **deliberately not rotated and
deliberately not discarded**: nothing in the product reads that column, so
rewriting it would risk the audit record for no gain and NULLing it would destroy
retained evidence. `--check` counts those rows so a key retirement is decided
with the number in view.

An `InvalidToken` was previously an unhandled 500 whose traceback could reach a
log. It is now a 409 with a code and no detail, and it increments
`autoaudit_decryption_failures_total`, which is the signal that a retired key was
dropped before the rewrite finished.

## Backups, and a restore that actually ran

There was nothing: no `pg_dump`, no restore script, no stated RPO or RTO, no
backup service in any compose file. The only strings matching "backup" belonged
to `security/strategies/regular_backups.py` — a **scanner** that grades a
*customer's* backup evidence against the Essential Eight. AutoAudit shipped a
tool that would have failed AutoAudit on every one of those controls.

`tools/ops/backup.py` dumps the database and the evidence object store, and
writes a manifest recording each artifact's SHA-256, the Alembic revision, the
server version and the retention policy version. `restore` verifies every digest
before writing anything and refuses a cross-major-version restore.

`tools/tests/test_phase10_backup_restore.py` takes a real dump of a real migrated
database with real rows and evidence bytes, **destroys the source**, restores into
a fresh database, and asserts the rows and the bytes came back. That is the plan's
anti-pattern guard answered: *do not conflate backup existence with a tested
restore.*

Proposed RPO/RTO/retention numbers are in
[backup-and-recovery.md](backup-and-recovery.md) and are **proposals**. An RPO is
a promise to a customer; engineering can propose one and cannot make one. The
archive is **not encrypted**, and the manifest says so rather than leaving a
reader to assume.

## The worker image did not build from its lockfile

`engine/Dockerfile` did `COPY pyproject.toml` then `pip install .`, and never
copied `uv.lock` at all. `engine/pyproject.toml` declares only floating lower
bounds, so **every worker image resolved whatever was newest on PyPI that day**,
while CI ran `uv sync --frozen` and Grype scanned the lockfile. The tested and
scanned dependency set was not the one that shipped, and an SBOM generated from
the lockfile would have described neither. `backend-api/Dockerfile` already did
this correctly, which made the engine case look intentional.

It now builds from `uv.lock` with a digest-pinned `uv`, and
`tools/tests/test_phase10_supply_chain.py` **builds the image and compares its
installed versions against the lockfile** rather than asserting the Dockerfile
says the right thing.

`ci.supply-chain.yml` adds CycloneDX SBOMs for the worker and API images, an
image-level vulnerability scan (the existing Grype job scans the source
*directory* and cannot see a base image or an apt layer), a release manifest, and
`pre-commit --all-files` — the detect-secrets and detect-private-key hooks ran
only on developer machines, so a contributor who never ran `pre-commit install`
bypassed the repository's secret controls entirely.

Release traceability comes from `tools/ops/release_manifest.py` plus the existing
`ENGINE_GIT_SHA` chain. Phase 10 deliberately did **not** add a `/version`
endpoint: PR #300 already adds one to `main.py`, a file with four other PRs
queued on it, and a fifth contender would help nobody.

## Things that were quietly false

Corrected, because a reader planning against them would plan against a system
that does not exist:

- **`README.md`** described a `staging` branch, Docker Hub pushes, a GCP Cloud
  Build trigger and Artifact Registry. None exists. The only registry push in the
  repository is mutable `pr-<n>` preview tags to GHCR.
- **The monitoring README** said rules "are deployed via Helm charts to the AKS
  cluster". There is no chart, no manifest and no cluster.
- **`workflow-documentation.md`** contradicted the workflows on five points,
  including **inverting the Grype gate** — it said `fail-build` is false when
  Phase 4 had set it true.
- **`cleanup-workflows.js`** never read `RETENTION_DAYS` and deleted by run
  *duration* instead: under 10s delete, 10s–2min delete, over 2min keep. Fast
  gates were deleted regardless of age while slow ones were kept for ever; it
  read only the newest 20 runs and swallowed its own errors. CI history could not
  have been cited as retained evidence.
- **`ops.short-test.yml`** filtered on `short-test.yml` while the file is
  `ops.short-test.yml`, so it could never trigger — and it is the canary for the
  cleanup workflow, meaning that behaviour had never been exercised by its own
  test.

## The Compose overlay has now been started

Phases 7, 8 and 9 each carried forward: *"The Compose overlay was not exercised
against a running container."* It had only ever been rendered.

`tools/ci/production_overlay_smoke.py` starts `db` and `redis` from
`docker-compose.production.yml` with synthetic disposable TLS material and
asserts what rendering cannot: both reach healthy, **neither container has a host
port binding**, Redis refuses a plaintext connection and completes a TLS
handshake, and PostgreSQL accepts connections on the private network. It ran, and
it passes. `tools/ci/container_smoke.py` was also re-run and passes.

Doing that found a real defect in this phase's own work: the Redis healthcheck
required `PONG`, but a reviewed ACL disables the default user, so a healthy
server answering `-NOAUTH` was marked unhealthy. It now accepts either, which
proves the server is listening *and* enforcing auth without a credential in the
compose file.

The production template also gained what only the *development* compose had:
healthchecks, resource-ordered startup, bounded logs and `no-new-privileges`. The
reviewed production topology was measurably less defended at runtime than a
developer's laptop. Its API healthcheck probes `/readiness`, not `/liveness` —
the latter returns a constant and would report healthy with an unreachable
database.

`DRIFT_FACT_HMAC_KEY` is now required. It appeared in no manifest, no
`env.example` and no operator document, and **with it unset no factprint row is
ever written and drift reports `fingerprints_unavailable`** — Phase 8's feature
shipped switched off with nothing saying so.

PostgreSQL was 17 in the development compose while CI, `container_smoke.py` and
the production template all ran 16. A dump from a developer's volume would not
have restored into production. Aligned, and gated.

## The CC1–CC9 register

`engine/mappings/soc2/organizational/v1.0.0/register.json` carries one row per
criterion with control statement, cadence, evidence, owner, reviewer, operating
status and retention policy version.

It is a **separate artifact** from the crosswalk on purpose: `mapping.json`'s
SHA-256 is pinned into every scan at creation and covered by the Phase 3
immutability trigger, so adding organizational fields to it would change the
mapping digest of every future scan and desynchronise it from every historical
scan's pinned snapshot.

Every row has `owner: null`, `operating_status` of `not_designed` or
`designed_not_operating`, and never `operating` — the validator rejects that
value outright, because no control in this program has an execution record and an
engineering change cannot create one. `counted_in_automated_coverage` is
structurally `false`.

`tools/ci/check_organizational_register.py` gates it in `ci.engine.yml`, and
`tools/tests/test_phase10_register.py` runs a fifteen-case mutation table plus
source assertions proving the validator can neither write a file nor assign a
human-owned value — the Phase 7 crosswalk convention, for the same reason.

## Evidence lifecycle

Phase 7 built the schema — `retention_expires_at`, `legal_hold`, an append-only
audit trail with `retention_expired` / `legal_hold_applied` /
`legal_hold_released` in its vocabulary, and two indexes that exist purely to
support a sweep. Nothing read any of it.

- **Legal hold is now settable.** It was enforced but unsettable: the only way to
  place one was a DBA running raw SQL against production, itself an unaudited
  privileged action on the control whose entire purpose is accountability.
  Auditor-or-above and deliberately **not** ownership-scoped, because a hold has
  to survive the data owner's wish to delete.
- **The access log is now readable.** It recorded every allowed and denied
  access and no endpoint could read it, so "who downloaded this evidence" needed
  database access. Auditor-only, deliberately: the trail carries `actor_user_id`,
  so an owner-scoped version would tell one customer which other accounts touched
  an object.
- **Retention reports and deletes nothing.** `tools/ops/retention_report.py`
  separates "past expiry" from "expired and not held" — a hold outranks expiry,
  and conflating them is how a sweep deletes something a court said to keep.

**The reason the deleting half is not built is not caution, it is arithmetic.**
Every retention and expiry column in the Phase 7 schema is timezone-**naive** UTC,
unlike `auth_session.expires_at`. Phase 7 documented what a naive comparison
against `now()` did to the dispatcher: it judged every scan instantly past its
deadline. A sweep making that mistake on an Australia/Melbourne cluster would
consider ten hours' more evidence expired than actually is — and delete it. CI
runs PostgreSQL at UTC, which is exactly why it would never have shown up there.
Every comparison is pinned with `(now() AT TIME ZONE 'UTC')` and tested under
three server timezones.

Beyond that, D04 governs retention, has no named owners, and states that no
automatic cleanup is authorized by it.

## Defects this phase found and fixed in its own work

Two independent passes ran over the code that landed: the fallback reviewer on
the two highest-risk modules, then a six-dimension adversarial review — 60 candidate
findings, three independent refuters each, 186 agents. **15 survived all three
refuters and every one is fixed**; 45 were refuted; none were left unverified.
[review.json](review.json) records all of them with their verdict counts.

The single most serious finding is one the author did not see and the six
reviewers' first read did not surface either:

- **The encryption key ring reached no container.**
  `ENCRYPTION_KEY_DECRYPT_ONLY` existed in `config.py`, in `env.example` and in
  the rotation tool's documented step 1 — and appeared in **no compose file**.
  Compose reads `.env` for interpolation, not injection, so every service booted
  with a one-key ring. An operator following the procedure verbatim would have
  found every legacy credential unreadable, while the rotation tool, run from the
  host shell where the variable *is* exported, reported a healthy two-key ring.
  The runbook's own remediation — "restore the removed key to
  `ENCRYPTION_KEY_DECRYPT_ONLY`" — silently did nothing. The phase's headline
  capability was unusable, and every test passed, because no test asserted the
  setting reached a container. One does now.

The rest, in order of seriousness:

- **The dispatcher refreshed its metrics only after a *successful* cycle.** So a
  database outage — the exact condition `ScanExporterDown` exists to catch — left
  the HTTP server serving a stale `autoaudit_collector_exporter_up 1`, and the
  alert could never fire. The one alert guarding the exporter was blind to the
  failure it guards.
- **`--check` could never return 0.** The rotation tool's own documented step 3
  is "run `--check`, then drop the retired key". It also failed on unrotatable
  evidence excerpts, which by design never reach zero — so the procedure was
  unreachable the moment a single historical evidence row existed.
- **`scans_past_deadline` was quieter than the behaviour it described.** The
  reconciler expires on `COALESCE(deadline_at, last_progress_at + deadline)`; the
  gauge filtered on `deadline_at IS NOT NULL`, so a scan the reconciler itself
  considers overdue reported zero.
- **A status series that blinks out of existence breaks `delta()`.**
  `GROUP BY status` returns no row at zero, and `delta()` over a series that has
  just reappeared *extrapolates* across the whole window: four errors three
  minutes into a thirty-minute window read as forty, firing
  `ControlErrorRateHigh` at a fifth of its threshold. Every status is now emitted
  every time, including zero.
- **A partial metrics collection left some gauges fresh, one cleared to nothing
  and the rest stale**, while reporting `up=0` — which this module's own contract
  says means "previous values". Read-then-apply fixes that and shrinks the
  `clear()` race a concurrent scrape could land in from a database round-trip to
  microseconds.
- **The Redis healthcheck marked a healthy server unhealthy**, found by actually
  starting the overlay rather than rendering it.
- `del plaintext` implied a memory wipe CPython does not perform; removed rather
  than left as a misleading gesture.
- The metrics exporter bound `0.0.0.0` implicitly; now explicit and configurable.
- **A double-quoted `expr:` erased every metric name before the alert gate saw
  it** — a silent bypass of the phase's own headline gate, because the string
  stripper ran before the label stripper and the whole expression is one quoted
  string. All four YAML forms are now parametrised.
- **A register claiming every criterion is designed while pointing at nothing
  passed the honesty gate.** The check rejected artifacts-without-design and not
  the inverse, which is the direction that flatters.
- **The documented restore put the evidence store one directory too deep**, so
  every restored object would have been unreachable.
- `restore` had no guard on its target and ran `pg_restore` without
  `--single-transaction --exit-on-error`, which continues past errors and exits
  0. A wrong `--target-url` merged two datasets and reported success.
- libpq error paths echoed the connection string, password included, into
  exceptions that reach stderr and CI logs.
- Legal hold and delete were a check-then-act pair with no row lock.
- `read_audit_events` appended to the permanently-immutable audit table for any
  object id, before checking the object existed.
- A legal-hold reason of pure whitespace validated, and the audit writer then
  dropped it — committing a hold with no recorded reason, the exact
  unaccountable action the field exists to prevent.
- `cleanup-workflows.js` deleted while paginating by offset, skipping roughly
  half the eligible runs while reporting success.
- Two rewritten documentation lines said the scheduled cleanup deletes; it is a
  dry run. Workflow-run history is **not** currently retained to any period by an
  automated process, and the documentation now says so.

## Findings recorded rather than fixed

- **CORS preflights and outer-middleware 500s are still unobserved.**
  `add_middleware` prepends, so the stack is CORS → CSRF → RequestLogging →
  router, and only the innermost calls `observe_request`. CSRF rejections are now
  recorded where they happen, but an `OPTIONS` preflight and a 500 raised above
  RequestLogging still reach no metric. Fixing that properly means a pure-ASGI
  middleware outside the user stack, and the ordering is load-bearing for
  Phase 9's conditional-poll 304 — a change worth making deliberately, not as a
  side effect of this phase.
- **No scheduler exists anywhere in the product.** No Celery beat, no cron, no
  periodic task; Phase 8 recorded the same for drift. Every operator tool this
  phase adds — backup, retention report, rotation — is an entry point, and a
  backup that is never run is worth what one that does not exist is worth.
- **Acknowledgement does not exist.** Alertmanager silences an alert; it cannot
  record that a human accepted responsibility. That needs a paging tool with an
  on-call roster, which is an organisational control with a named owner.
- **`DELETE /v1/manual-verification/{detail_id}` is still an unaudited hard
  delete**, still registered alongside its own documented audited replacement.
  Out of scope here; recorded so it is not lost.
- **`legal_hold` is enforced on exactly one code path.** The user CASCADE,
  `delete_scan` and the manual-verification delete all bypass it.
- **Deleting a scan 500s when manual evidence exists for it** — the FK is
  `ondelete="RESTRICT"` and nothing catches the violation.
- **`backend-api/entrypoint.sh` runs `alembic upgrade head` on every container
  start**, which races itself with more than one replica.
- **The evidence audit trail cannot be pruned by any statement**, by design, and
  has no retention columns of its own. That is a decision someone must make
  explicitly rather than discover.
- **Retention exists only for `evidence_artifact`.** The drift and factprint
  tables carry a `retention_policy_version` label and nothing behind it, and
  Phase 8 records that they hold plaintext observed values.

Inherited and unchanged from earlier phases:

- Phase 0 decisions D01–D10 remain unapproved with no named owners.
- Phase 4's required status checks were still never applied to branch
  protection, so a green local run is not an enforced gate — and that applies to
  every gate this phase adds.
- `alembic/env.py` still does not enable `compare_server_default`.
- Phase 8's three candidate policies are still blocked.
- PR #351, the hard conflict Phase 9 recorded, is still open and unresolved.

## Independent review

**The designated second reviewer (an external, automated, read-only code review)
was unavailable for the fourth consecutive phase** — rate-limited, with
the limit resetting at 12:38 on 2026-09-07. The fallback reviewer substituted on
the two highest-risk modules and found the `--check` lockout, the exporter
blindness and three other real defects, all fixed above. That substitution is
weaker than the standing instruction, and four consecutive phases is not an
accident: **this stack should get an independent human review, or a pass by the
designated second reviewer, before merge.**

## Verification

Exact commands and results are in [verification.json](verification.json). Both
suites were also run in full on an `Australia/Melbourne` database cluster and are
byte-identical to the UTC results.

## Standard handoff

- **Phase:** 10 — local engineering implemented; platform selection, control
  ownership and all operating evidence externally blocked.
- **Baseline:** `8736fcb9` plus the exact 972-file Phase 9 prerequisite snapshot.
  Upstream `main` has moved to `0a074cc9` and this branch is not based on it.
- **Branch/commit/PR:** `fix/soc2-phase-10-production-operations`;
  uncommitted/unpushed; no PR.
- **Findings addressed:** the plan defines **no numbered finding identifiers for
  Phase 10** — there are no `OPS-*` findings, and none of the Section 3.1
  identifiers close here. Work is against plan items 18.1.1–18.1.10 and 18.2.
  Items 4 (metrics), 6 (backups), 7 (key rotation), 8 (SBOM/provenance/release
  traceability) and 9 (evidence lifecycle, less the deleting sweep) are
  implemented. Items 2 and 3 (topology) are hardened and now gated. Items 1
  (platform) and 10 (production exercises) are recorded as owner decisions;
  18.2 is delivered as a structure with no owners.
- **Files changed:** [phase-10-changes.json](phase-10-changes.json) — 40 added,
  38 modified, 8 removed.
- **Decisions:** database-derived gauges rather than in-process counters, so the
  numbers an operator alerts on and an auditor reads come from the same rows; no
  collection-duration series at all rather than a misleading one; alert rules
  retired with recorded reasons rather than fed invented metrics; the retention
  sweep built as a report and left inert pending D04; the CC1–CC9 register as a
  separate artifact so the scan-pinned mapping digest does not move; no `/version`
  endpoint, deferring to PR #300; no competing Helm chart, deferring to PR #266.
- **Tests:** see [verification.json](verification.json).
- **Security/GRC review required:** no rating moves and no new evidence is
  persisted. Four asks: approve or reject the deployment platform; approve D04 so
  retention has a named policy and the deleting sweep can be built; appoint
  owners for CC1–CC9; and confirm that auditor-or-above is the right authority
  for applying a legal hold and reading the evidence access log, since neither is
  ownership-scoped.
- **Known gaps:** above, plus everything in
  [coordination-review.md](coordination-review.md) — in particular **PR #361,
  which creates the same `health.py` and the same `/readiness` endpoint this
  phase created independently**, and PR #266, which is the platform decision in
  draft form.
- **Next unblocked phase:** Phase 11 (final verification and audit-readiness
  release) depends on the whole stack being integrated with upstream, which is
  still outstanding from Phase 7 and is now four upstream revisions behind. That
  integration, not Phase 11, is the next work.
