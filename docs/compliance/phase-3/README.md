# Phase 3 — Result semantics, scoring and provenance foundation

Date: 2026-09-05 (Australia/Melbourne).

**Engineering implementation is ready for review. Formal GRC acceptance and
production release remain pending.** The user explicitly requested Phase 3;
this authorizes the local engineering patch, not approval of the Phase 0 draft.

## Branch and prerequisites

- Worktree: `/Users/clupa/Documents/projects/autoaudit/AutoAudit-phase-3`.
- Branch: `fix/soc2-phase-3-result-provenance`; changes are uncommitted.
- Base: Phase 1 commit `8736fcb9`; fetched `upstream/main` remains
  `be241f52beb5ffec10904771bf7cfa4b98233ab0`.
- This tree includes an exact copy of the 31 changed/new Phase 2 files. Their
  SHA-256 values are recorded in [phase-2-snapshot.json](phase-2-snapshot.json).
  The original Phase 2 worktree remains uncommitted and untouched. When stacking
  or splitting commits, treat these files as Phase 2 prerequisites, not new
  Phase 3 policy work. The Phase 2 handoff is preserved unchanged.
- Phase 1, Phase 2 and the original Phase 0 checkout remain in place. Nothing
  was pushed, merged, published or changed in a deployment or tenant.

## Implemented contract

| Outcome | Meaning |
|---|---|
| `passed` | Explicit true from a valid typed policy result |
| `failed` | Explicit false from a valid typed policy result |
| `indeterminate` | Explicit null, or unusable non-object collector output |
| `error` | Collection, policy evaluation, contract or provenance execution failure |
| `skipped` | Valid but unselected control |
| `not_assessable` | Selected control outside current automation, including disabled PowerShell assessment |

`pending` remains a lifecycle state. No `unknown` or `not_applicable` stored state
was added. Missing output, string/integer booleans, malformed result fields,
undefined Rego decisions and evaluation conflicts cannot become assessed results.
Known collector error envelopes become errors. Exceptions and OPA diagnostics are
redacted before retries and terminal persistence.

The API rejects unknown IDs, an explicit empty list and a benchmark with no
controls with structured 422 responses before any scan/result write or task
submission. Null selection means all controls. Duplicate valid IDs are
normalized. Selected manual, blocked, deferred and not-started controls remain
in the frozen selection and coverage denominator.

For new `phase3-v1` scans:

- Compliance among assessed = `100 × passed / (passed + failed)`, null if none
  were assessed.
- Automated coverage = `100 × (passed + failed) / selected_count`, null if the
  selected population is zero. There is no applicability exclusion in this patch.
- All state counts, selected count and both score denominators are exposed.
- The worker derives counters from persisted rows instead of delivery increments.
  The first terminal write wins. The scan lock is acquired before reading counts,
  so concurrent final tasks see committed predecessors and finalize correctly.

The detail page, dashboard, scan list and chart share these semantics. A partial
assessment is labelled explicitly even when compliance among assessed is 100%.
The chart had contained a duplicate detail page and is now a presentational
chart with explicit state counts and separate historical score series.

## Provenance and immutability

Scan creation freezes the public benchmark metadata snapshot, canonical metadata
SHA-256, requested selection, benchmark identity and correlation UUID. Each
executed result captures the policy source and digest, collector ID, actual engine
source identity and source-file digest, OPA version, normalized input digest, and
collection/evaluation timestamps. Results link to the immutable scan metadata.
Nonexecuted results carry `not_executed` provenance with explicit null execution
fields; collection-only and failed attempts distinguish unavailable fields.
Failed policy execution retains the available OPA runtime/version and completion
time. No historical source or selection is fabricated for legacy rows.

Phase 3 uses a local OPA **1.20.2** binary inside the worker to evaluate a private
temporary copy of the exact retained policy source. The input goes over stdin,
not an argument, task result, log or temporary evidence file. The OPA subprocess
receives an empty environment, cannot read worker credentials through runtime
environment inspection, and has bounded execution time. The same successful
evaluation returns its runtime version. The existing HTTP client remains typed;
the worker does not attribute a local digest to mutable remote-service policy.
The current policy corpus has no cross-file data imports requiring a bundle.

This uses the documented [OPA CLI evaluation interface](https://www.openpolicyagent.org/docs/cli).
Remote evaluation remains available through the documented
[OPA REST API](https://www.openpolicyagent.org/docs/rest-api), but does not provide
this patch's captured-source guarantee.

**Deliberate evidence limitation:** the worker stores generic outcome messages and
an affected-resource count, rather than the prior arbitrary policy details and
resource identities. It retains no additional raw tenant payloads. This reduces
diagnostic detail; an input digest alone cannot replay a historical assessment.
Approved, redacted normalized evidence retention and detailed remediation remain
Phase 7 work after D04/D05 approval. Source snapshots plus input digests are the
minimum foundation, not a claim of complete audit-grade evidence.

Migration `c4e91a73b620` follows the Phase 1 merge `2899a0e678b6`. It adds nullable
legacy attribution and database triggers that freeze scan source/selection and
ownership/connection IDs, result identity/selection from creation, and terminal
status/evidence/provenance/reasons/timestamps. Re-delivery cannot overwrite the
first terminal result. Deletion remains possible through the existing authorized
path; retention, holds and append-only deletion history are later work. A new
scan is required for reassessment. The migration has no destructive downgrade;
use a reviewed forward fix or verified restore. Existing migration bodies were
not edited. The Phase 1 fixture now targets its merge revision explicitly so its
no-op merge test remains independent of the new forward-only migration.

Legacy pending scans are marked failed with a rerun instruction rather than
inventing selection or provenance. Drain old tasks and rerun those scans during
rollout. Legacy completed scores remain stored and visibly labelled legacy;
coverage stays unavailable.

## Development and rollout

Commit the reviewed source and supply its full Git SHA when building the worker:

```sh
export ENGINE_GIT_SHA="$(git rev-parse HEAD)"
docker compose --profile worker build worker
```

The Dockerfile rejects a missing/malformed source SHA during build, and the
entrypoint verifies runtime identity and OPA availability before starting Celery.
Standalone image deployments may also provide `ENGINE_IMAGE_DIGEST` in the form
`sha256:<64 hex digits>`. For local development, Git identity is discovered from
the checkout; dirty state and a digest of the engine source are recorded. Set
`OPA_BINARY` to the pinned local executable. The image includes the binary, so it
does not require an extra operator download.

Before rollout: obtain GRC decisions; review Phase 1/2 dependencies and overlapping
PRs; drain workers; apply the forward migration; deploy matched API, worker and
frontend versions; then create a new synthetic/non-production scan. Do not run an
old worker against new scans: it does not understand the explicit selection or
immutable result contract. No rollout was performed here.

## Verification

Reproducible commands from this worktree (the PostgreSQL URL must identify a
local disposable cluster; fixtures create and drop their own databases):

```sh
export OPA_BINARY=/tmp/autoaudit-phase-2-tools/opa
export MIGRATION_TEST_ADMIN_URL=postgresql://postgres@127.0.0.1:55433/postgres
uv run --project engine --extra dev pytest engine/tests -q
uv run --project backend-api --with pytest python -m pytest backend-api/tests/test_phase3_scans.py backend-api/tests/test_phase3_migrations.py backend-api/tests/test_migrations.py backend-api/tests/test_phase1_security.py tools/tests/test_secret_scanning.py -q
"$OPA_BINARY" check --strict engine/policies/cis/microsoft-365-foundations/v6.0.0
"$OPA_BINARY" test engine/policies engine/tests
npm exec --yes --package=node@20 -- npm --prefix frontend test
npm exec --yes --package=node@20 -- npm --prefix frontend run build
npm exec --yes --package=node@20 -- npm --prefix frontend run lint
git diff --check
```

- Engine baseline before Phase 2/3 integration: 496 passed, 1 skipped. Final engine
  suite: **636 passed, 1 skipped**, including 58 Phase 3 cases and 82 Phase 2 cases.
  Existing Pydantic class-config deprecation warning remains.
- Real PostgreSQL tests cover migration preservation, fresh upgrades, frozen
  attribution, every terminal state, nullable zero-assessment scoring, mixed
  populations, concurrent final controls and duplicate delivery. Three tests run
  the actual migration, orchestrator, OPA binary and persistence together for
  true, false and null evidence, with a selected manual control in each scan.
- Strict v6 OPA check passes; semantic OPA suite **204/204 passed**.
- Full frontend suite has six existing failures in AccountPage (five) and
  SignupFormPanel (one). The unchanged Phase 1 baseline reproduces those exact
  failures under Node 20: 198 passed, 6 failed. The unrelated TypeScript baseline
  error remains at `SignUpPage.tsx:73` (handler type variance).
- The legacy manual-verification tests require a separately running API at
  localhost:8000 and valid test credentials; they fail with connection refused
  here and are excluded from the reproducible isolated suite above.
- Independent backend, frontend and engine reviews found and drove regression
  fixes for immutable attribution, dashboard score tone and failure provenance.
  Review does not constitute GRC approval.

The final verification record below includes the complete rerun counts.

## Coordination and remaining acceptance

The live public GitHub PR inventory was refreshed. `gh` GraphQL authentication
returned 401; public read-only REST access worked. Relevant candidate diffs were
retrieved and overlap reviewed: #351 shares the worker collection seam; #292
shares scan authorization; #355 shares backend testing; #350 shares authentication
and frontend baseline tests; #352 supplies the migration merge already in Phase 1.
This patch preserves the existing collector client-selection seam and authorization
checks. No candidate PR was merged, closed or represented as reviewed approval.
Owner coordination is still required before merge; no external messages were sent.

Pending GRC decisions include D01/D02 (result/score semantics), D04/D05 (retention
and detailed evidence redaction), D07 (authoritative benchmark source/versioning)
and D10 (migration/deletion implications). The Phase 2 D03/D09 decisions for
6.1.2 and 5.1.6.1 remain open. Phase 1 credential revocation and legacy privileged
account audit remain externally blocked. No supplied SOC 2 rating changed.

The Phase 5 credential-bearing task payload and wider runtime trust boundaries,
Phase 6 outbox/orchestration recovery/cancellation, and Phase 7 retained normalized
evidence/manual audit history remain separate dependencies. Basic first-write
idempotency and final-count serialization here do not close those entire phases.

## Standard handoff

- **Phase:** 3 — engineering implemented for review; acceptance pending GRC.
- **Baseline:** Phase 1 `8736fcb9`, upstream `be241f52`, exact Phase 2 snapshot.
- **Branch/commit/PR:** `fix/soc2-phase-3-result-provenance`; uncommitted; no PR/push.
- **Findings addressed:** COR-01, COR-02, worker null-result collapse; EVI-02 minimum
  source-provenance foundation. Full evidence reproducibility remains open.
- **Files changed:** backend models/schemas/scan API/new migration and tests;
  worker task/database/OPA/provenance/contract modules and tests; worker image and
  startup; shared frontend types/summary/chart/detail/dashboard/list and tests;
  this handoff plus the exact copied Phase 2 prerequisite files.
- **Decisions:** six-state plan minimum, frozen selected denominator, null when
  unassessed, captured local policy evaluation, explicit legacy unknowns,
  conservative count-only evidence, first immutable terminal result.
- **Tests:** exact commands and results above and final record below.
- **Security/GRC review:** approvals and non-production rollout verification remain
  required; no technical test substitutes for them.
- **Known gaps:** full raw/normalized evidence replay, GRC decisions, external
  Phase 1 incident actions, legacy frontend baseline failures and later phases.
- **Next work:** Phase 4 CI can enforce the supplied suites after decision/review
  coordination; production acceptance must not silently assume those approvals.


## Final verification record

- Isolated backend API, PostgreSQL migration/integrity, Phase 1 regressions and
  scanner canaries: **59 passed**, one existing Pydantic warning.
- Complete engine suite including the Phase 2 prerequisite tests and real
  migrated-database/OPA tests: **636 passed, 1 skipped**, one existing Pydantic
  warning. The same skip was already present in the baseline.
- OPA v6 strict check passed; **204 OPA tests passed**.
- Phase 3 frontend suite: **43 passed**. Complete frontend suite: **225 passed,
  6 failed**, with the same six failures reproduced on the unchanged baseline.
- Frontend production build passed under Node 20; the existing large-chunk
  advisory remains. Frontend lint exits 0 with 10 existing warnings.
- TypeScript still reports the existing `SignUpPage.tsx:73` handler type error;
  no Phase 3 type errors were reported by the supported local compiler.
- All eight pre-commit hooks passed on Phase 3-owned changed/new files. The
  copied Phase 2 prerequisites were verified byte-for-byte against their
  manifest and original worktree rather than reformatted. Scanner exceptions
  are line-specific annotations for a migration revision and synthetic fixture.
- The worker image built successfully with the full source Git SHA. A container
  with networking disabled evaluated the captured Phase 2 policy using OPA
  **1.20.2** and returned **indeterminate** for missing evidence. This is a local
  container smoke test, not an M365 or deployment validation.
- Final independent backend/frontend/engine reviews have no remaining actionable
  findings in their scoped reviews. GRC and release acceptance remain pending.
- Original checkout still has only its existing untracked plans/Phase 0 files;
  Phase 1 remains clean; all 31 original Phase 2 changed/new files match exactly.
  Phase 3 remains uncommitted and unpushed.
- Disposable PostgreSQL cleanup verified **0 remaining test databases**; the
  Phase 3 test cluster was stopped.
