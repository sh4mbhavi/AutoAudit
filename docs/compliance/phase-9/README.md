# Phase 9 — Performance and maintainability

Date: 2026-09-06 (Australia/Melbourne).

Local engineering implemented. Upstream integration, hosted checks and live-tenant
load measurement remain pending. No public PR, production service, external
tenant, credential or repository setting was changed.

## Baseline and workspace

- Worktree: `/Users/clupa/Documents/projects/autoaudit/AutoAudit-phase-9`.
- Branch: `fix/soc2-phase-9-performance`; uncommitted and unpushed.
- Git base: Phase 1 `8736fcb9`, overlaid with the complete Phase 8 working source.
  [phase-8-snapshot.json](phase-8-snapshot.json) records SHA-256 for all 943
  prerequisite files; the overlay was verified byte-identical, and `git status`
  compared entry-for-entry against the Phase 8 worktree, before any Phase 9
  change. Every earlier worktree is preserved and untouched.
- **Upstream moved.** Phase 8 recorded `bba14810`; it is now `bfb8edd4` (PR #292,
  merged 2026-09-06 18:24). One of the eighteen changed files is a Phase 9 file.
  [Coordination review](coordination-review.md) records that, the 46 open PRs,
  and the two that collide with Phase 9 in substance rather than merely in text.
- Phase 8's recorded results were reproduced here before any change:
  engine 1,764 passed / 1 skipped / 11 xfailed; backend and tools 588 passed;
  `opa check --strict` clean; `opa test` 582/582.
- Phase 9 changes only: [phase-9-changes.json](phase-9-changes.json).

## The census this phase exists for

69 ready CIS v6.0.0 controls resolve to **43** distinct `data_collector_id`
values. The engine ran one collector per control, so a full scan performed 26
collections whose evidence it already held — seven controls share
`entra.policies.authorization_policy`, four share
`exchange.organization.organization_config`, four share
`entra.devices.device_registration_policy`.

That number is now a test, not a sentence in a document
(`test_a_full_benchmark_scan_plans_one_collection_per_distinct_collector`).

## What changed

### The durable unit of work is a collection, not a control

`worker/execution_plan.py` turns the pending result rows into an ordered plan of
collection groups, one per distinct collector. `run_scan` writes one outbox row
per group; `evaluate_collection` collects once and fans the evidence out to every
control that names that collector, evaluating each control's own Rego policy.

What is shared: the client, the token, the engine identity, the collection window
and its `input_digest`, and the declared scalar projection of that collection.
What stays per control: the policy source and digest, the OPA evaluation, the
evaluation timestamps, the provenance record, the result row and the factprint
row. **A shared collection fans its failure out exactly as it fans its evidence
out** — one terminal row per affected control, each with its own reason code.

Phase 6's guarantees had to survive that, and they are what most of the new
tests are about: the outbox is still the sole authorisation to publish, a
collection row's identity is still a deterministic `uuid5` (over the scan and the
collector rather than the scan and the result), the whole fan-out writes in one
transaction so a mid-group death rolls back rather than half-writing, and
redelivery is still first-write-wins.

`evaluate_control` is retained and still registered. An outbox row written before
this deploy names it, and a redelivery of one must not be stranded; a group of
one takes the same path a fanned-out group takes.

### The collection is bounded, pooled and throttling-aware

- `GraphClient` owns one pooled `httpx.AsyncClient` and one token for the life of
  a client. Before, a new client — a new pool, TCP connection and TLS handshake —
  was built for **every single Graph request, including every page**, and a fresh
  MSAL app per control.
- Explicit retry for 429 with `Retry-After` (delta-seconds *and* HTTP-date), 5xx,
  timeouts and connection resets, bounded by attempts **and** by wall-clock so a
  tenant asking for ten minutes cannot park a worker for ten minutes. An
  authorization or invalid-request answer is never retried. 401 is deliberately
  retryable: the token now lives for a whole group, so a mid-group expiry
  presents as 401 and a fresh attempt acquires a new one.
- `collectors/concurrency.py` gives the four per-item collector loops a bound
  where they previously had no concurrency at all. Results keep input order —
  which is load-bearing, because `provenance.input_digest` is `canonical_digest`
  and that preserves list order, so a reordering changes a published audit digest
  for an unchanged tenant. `asr_rules` publishes the *name* of the first weakest
  profile, so the order decides which profile is named on a tie.
- Concurrency is measured, not inferred: reverting those collectors to a serial
  loop leaves their order and their request count unchanged, so only a test that
  observes overlap can tell the two apart, and that is what the new tests do.

### PowerShell sessions are batched, and the service's blocking work is bounded

Every reviewed cmdlet was its own `pwsh` process, its own `Connect-*` and its own
`Disconnect-*`. A tenant with 200 shared mailboxes opened 201 Exchange sessions
for CIS 1.2.2 alone. `/execute-batch` runs several reviewed operations of one
module in one session.

The trust boundary does not move, and that is asserted first: every entry is
validated against **its own** collector id, a batch is exactly one module and one
tenant identity, the pwsh child still receives the environment allowlist plus
exactly one module's secrets, and one failing cmdlet aborts the whole batch —
a partial batch is a smaller population, not a tenant's configuration. Phase 5's
"every client execution path validates before any I/O" gate was widened to all
three new entry points rather than left describing three of six.

The service's `/execute` was a plain `def`, so Starlette ran it on its shared
40-slot threadpool: off the event loop, but on a framework default that also
serves every other threadpool user, with each slot able to hold a 120-second
subprocess. The offload is now explicit and the pool is the service's own,
bounded by `POWERSHELL_MAX_CONCURRENCY` (default 4; Compose sets 2 for the
512 MB development container, because each child loads
`ExchangeOnlineManagement` and may now live for a 300-second batch).

### Polling costs what it is worth

`GET /scans/{id}` carries every control result, and each result carried its full
provenance record **including the complete Rego source text** — about 180 KB of
policy source across a 69-control scan, re-sent every three seconds to move a
progress bar that reads scalar counts.

- The scan detail page polls `GET /scans/{id}/summary`, which is now conditional:
  a weak ETag derived from the response model itself, so a field added to
  `ScanSummary` is covered by the validator without anyone having to remember. An
  unchanged scan answers 304 with no body and without running the per-control
  query at all.
- When the counts *do* move, the page fetches the results that moved with them.
  That is the same liveness the page had before Phase 9, at a fraction of the
  size, and it costs nothing on the 304 path.
- **`policy_source` is no longer published.** Phase 7's SOC 2 projection has
  always withheld it, for a documented reason — the worker stores the complete
  Rego source there and file content does not leave in a response — while
  `GET /scans/{id}` and `/results` published it verbatim on every row. The two
  now apply the same rule. This is the phase's one deliberate response-contract
  change; the SOC 2 tuple itself is byte-identical to Phase 7's.
- `usePoll` replaces a bare `setInterval` that could overlap with itself, never
  paused in a hidden tab, and re-armed a flat three-second timer forever after an
  error. It waits for each response, pauses when hidden, backs off on repeated
  failures and aborts in flight on teardown.
- `GET /{scan_id}/results` gains an **optional** bounded page and
  `X-Total-Count`. Omitting `limit` returns exactly what it always returned,
  which the Phase 6 real-database test still proves by equality.

### Typed frontend contracts

`tools/frontend/generate_api_types.py` generates the scan response types from the
backend's own OpenAPI schema and `--check` fails on drift, gated in CI — the same
shape as `tools/docs/generate_control_status.py --check`. A hand-written type
agrees with the API until someone edits a Pydantic model.

It immediately found three real disagreements the untyped client had hidden:
`connection_name` and `message` are nullable and the frontend said they were not;
`semantics_version` is any string and the frontend pinned it to one literal; and
`POST /scans` returns an acknowledgement, not a scan row — the page was
prepending it to the list, producing a row missing every column the table
renders.

Scope is what the plan asked for: the scan paths Phase 9 touches. Twenty-two
`Promise<any>` signatures remain on auth, contact, settings, platforms,
connections, benchmarks and evidence paths this phase does not touch.

## What the load harness measured, and what it did not

`tools/perf/scan_load_report.py`, recorded in [load-report.json](load-report.json)
at `--tenant-size 25`:

| | pre-Phase-9 shape | Phase 9 | delta |
|---|---|---|---|
| collector executions | 69 | 43 | −26 |
| Graph requests | 86 | 72 | −14 |
| PowerShell sessions | 58 | 23 | −35 |

**No tenant was contacted.** These are exact counts of what the engine *would*
issue against a synthetic tenant, not latency measured against Microsoft. Two of
43 collectors reject the synthetic tenant's shape outright; they are named in the
report and excluded from both columns equally.

Read the Graph row honestly: the collector-execution saving is 38%, the Graph
request saving is smaller, because the collectors that are *shared* are mostly
cheap single-request ones while the expensive per-item loops
(`cloud_only_admins`, `admin_license_footprint`) are each used by exactly one
control. Fan-out does not help those; bounded concurrency helps their latency,
not their request count.

## Defects this phase found and fixed in its own work

Two independent passes ran over the code that actually landed: the fallback
reviewer on the two highest-risk modules, then a six-dimension adversarial
review with three independent refuters per finding. 38 candidate findings;
[review.json](review.json) records all of them and what was done. The most
serious:

- **A group failure took the FIRST member's reason code and retryability.** A
  control whose policy file was missing was recorded as `evaluation_error`
  because some other control in its group happened to fail at OPA first — and
  worse, one deterministic member suppressed the retry that would have recovered
  every other control in the group. Each member now keeps its own reason code,
  and the group is retryable if *any* member's failure is one a retry could clear.
- **A transient OPA failure was classified as deterministic.**
  `opa_client._execute` raises a bare `ValueError` for *any* non-zero exit of the
  `opa` subprocess, and the first version of `_is_retryable` declared every
  `ValueError` deterministic — so a momentary OPA blip would have been written as
  a permanent error row for every control in the group, with no retry at all.
  The classification is now stage-aware: our own evidence validation is
  deterministic, a subprocess failure is not.
- **A member the code itself marked retryable was written straight to a terminal
  error row.** The partial-failure path never read `outcome.retryable`. The
  successes are now committed first and the group is failed, so the retry budget
  reaches the member that could still be assessed.
- **A rolling deploy could collect the same control twice.** A scan orchestrated
  by a pre-Phase-9 build carries per-result rows; reconciled by this build it
  would also get collection rows for the same controls, and the dispatcher would
  publish both.
- **A pending non-ready control could fail the whole scan.** 29 non-ready CIS
  controls name a collector. Planned into a group, the task refuses it and writes
  nothing, so the row stayed live and was republished until `reconcile` failed
  the entire scan with `dispatch_retry_exhausted`.
- **The batch client gave up at 120 s while the service was allowed 300 s.** Any
  batch the service completed between the two was abandoned as a transport error
  while the `pwsh` child ran on unheard.
- **The batch JSON depth was off by one.** The `{index, data}` wrapper costs two
  levels, not one, so batched evidence was serialised one level shallower than
  the same cmdlet run singly — and PowerShell replaces anything past `-Depth`
  with a type name rather than failing.
- **`POWERSHELL_MAX_BATCH` was a dead setting**, documented as the bound on how
  many operations share one session and read by nothing.
- **A single failed follow-up read stranded the scan detail page.** The ETag was
  committed before the work it gated, so one transient failure left the page
  answering 304 forever — rendering a finished scan as still running, with a
  stale results list and no error at all.
- **`usePoll` forked a second chain on visibility change.** The timer handle was
  used as the "a tick is pending" guard, but `tick()` clears it before awaiting,
  so the whole in-flight window read as "nothing pending".
- **`verify_sharepoint_tenant` leaked a pooled client** on every SharePoint
  collection group, and closing it naively would have turned a cleanup failure
  into an unverified tenant.

Several review findings were about the tests rather than the code, and those were
the most useful: the one assertion that named connection pooling could never
fail; `test_phase9_concurrency.py` asserted only order and count, both of which a
serial loop already satisfies; the load harness's time and memory rows were
measurement-order artefacts whose sign flipped when the columns were swapped;
`getScanSummary` — the only code that reads the ETag, echoes it and turns a 304
into a value — had no test at all; and two pre-existing "stops polling" tests
were left watching `getScan` after the poll target moved, so they no longer
detected continued polling.

## Findings recorded rather than fixed

- **A rolling deploy can still collect one control twice.** The reconciler no
  longer *plans* a control that already holds a per-result row, but
  `evaluate_collection` resolves its members from the database at execution time
  and will pick that control up if a group exists for its collector. The cost is
  bounded (one extra collection) and evidence-safe (first-write-wins means only
  one assessment can land), and it occurs only while both builds are running.
  Eliminating it needs cross-task coordination that would cost more than the
  overlap does.
- **A pending non-ready control still ends in `dispatch_retry_exhausted`.** It
  now falls back to the Phase 6 per-result row, which is exactly what would have
  been written before Phase 9 — `evaluate_control` refuses it before any result
  write, the row exhausts, and the deadline path is the backstop. Phase 9 stops
  making this worse; it does not fix it, and it is pre-existing.
- **Drift has no recovery.** A worker death between the finalising commit and
  `_drift_after_finalisation` loses that comparison permanently, and the
  reconciler's own finalising path never calls drift. Pre-existing from Phase 8.

Inherited and unchanged from earlier phases:

- Phase 0 decisions D01–D10 remain unapproved with no named owners.
- Phase 4's required status checks were still never applied to branch protection,
  so a green local run is not an enforced gate.
- `alembic/env.py` still does not enable `compare_server_default`, so no gate can
  see a server-default divergence between a model and the database.
- The Compose overlay was not exercised against a running container.
- Phase 8's three candidate policies are still blocked and still evaluate in no
  scan; `promote_candidate.py --check` is unchanged and still refuses.

## Independent review

**The designated second reviewer (an external, automated, read-only code review)
was unavailable for the third consecutive phase** — rate-limited until
2026-09-07 12:38, the same limit Phase 7 and Phase 8 recorded. The fallback
reviewer substituted on the two highest-risk modules and found three real
defects. That substitution is weaker than the standing instruction, and three
phases is a pattern rather than an accident: this stack should get an
independent human review, or a pass by the designated second reviewer, before
merge.

Twelve of the 120 review agents hit a session limit, leaving three findings with
no refuter verdict. All three were adjudicated by hand, all three were real, and
all three are fixed.

## Verification

Exact commands and results are in [verification.json](verification.json). Both
suites were also run in full on an `Australia/Melbourne` database cluster and are
byte-identical to the UTC results.

## Standard handoff

- **Phase:** 9 — local engineering implemented; external acceptance pending.
- **Baseline:** `8736fcb9` plus the exact 943-file Phase 8 prerequisite snapshot.
  Upstream `main` has moved to `bfb8edd4` and this branch is not based on it.
- **Branch/commit/PR:** `fix/soc2-phase-9-performance`; uncommitted/unpushed; no PR.
- **Findings addressed:** PERF-01 (collector-once fan-out, 69 → 43 collections),
  PERF-02 (pooled client, bounded Retry-After-aware retry; the silent-pagination
  half of PERF-02 was already fixed by an earlier phase and is now covered by a
  named exception type), PERF-03 (bounded per-item concurrency, measured),
  PERF-04 (session batching and an explicit bounded offload; the "blocking in the
  async request thread" half was already fixed by Phase 5's sync handler and is
  reported as such), PERF-05 (conditional summary polling, provenance projection,
  optional result paging, typed scan APIs).
- **Files changed:** [phase-9-changes.json](phase-9-changes.json) — 27 added,
  46 modified, 0 removed.
- **Decisions:** the collection group as the durable unit of work rather than a
  persisted evidence cache, because persisting raw collector payloads is a D05
  retention decision this phase has no authority to make; `evaluate_control`
  retained so a pre-deploy outbox row is never stranded; retry classification by
  stage rather than by exception type; one allowlist for published provenance,
  with the scan-result projection a documented superset of the SOC 2 one;
  generated frontend types with a CI drift gate rather than hand-written ones.
- **Tests:** see [verification.json](verification.json).
- **Security/GRC review required:** no rating moves and no new evidence is
  persisted, so no new GRC question is raised. One response-contract change needs
  sign-off: `policy_source` is no longer published by `GET /scans/{id}` or
  `/results`. It aligns those responses with the rule Phase 7 already applied to
  the SOC 2 projection.
- **Known gaps:** above, plus everything in
  [coordination-review.md](coordination-review.md) — in particular PR #351, which
  rewrites the same function Phase 9 rewrote and must be rebased deliberately by
  someone who has read both.
- **Next unblocked phase:** Phase 10 (production operations and organizational
  SOC 2 evidence) may proceed. Phase 11 depends on the whole stack being
  integrated with upstream, which is still outstanding from Phase 7.
