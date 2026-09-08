# Phase 7 — Audit-grade evidence and SOC 2 productization

Date: 2026-09-06 (Australia/Melbourne).

Local engineering implemented. Upstream integration, hosted checks, deployment
acceptance and GRC approval remain pending. No public PR, production service,
external tenant, credential or repository setting was changed.

## Baseline and workspace

- Worktree: `/Users/clupa/Documents/projects/autoaudit/AutoAudit-phase-7`.
- Branch: `fix/soc2-phase-7-audit-evidence`; uncommitted and unpushed.
- Git base: Phase 1 `8736fcb9`, overlaid with the complete Phase 6 working source.
  [phase-6-snapshot.json](phase-6-snapshot.json) records SHA-256 for all 274
  prerequisite files. Every earlier worktree is preserved and untouched.
- Read-only upstream refresh: `bba14810f558190ee5221017c11864d300f8078a`,
  unchanged from the Phase 5 and Phase 6 handoffs. This stack still needs
  reviewed integration with current upstream and is not represented as based on it.
- [Coordination review](coordination-review.md) records the 43 open PRs and the
  overlaps that must be resolved before merge.
- Phase 7 changes only: [phase-7-changes.json](phase-7-changes.json) — 67 files
  (51 added, 16 modified), separated from the prerequisite stack.

## The crosswalk is now an artifact, not prose

`engine/mappings/soc2/common-criteria/v1.0.0/mapping.json` carries Appendix A
verbatim: 47 points of focus across CC6/CC7, **13 Yes, 16 Partial, 18 No**, the
44 unique CIS controls they cite, each control's resolved policy file and
collector id, per-row residual limitation and scope, the CC1–CC9 coverage
summary, and an approval block that records `approved: false` with null reviewer
fields. Ratings are transcribed, never computed.

`worker.crosswalk` loads it, digests it and validates it. `validate_mapping`
proves every referenced control exists in the pinned benchmark, is `ready`, has
the stated `.rego` on disk, and resolves to a registered collector — and returns
structured findings instead of raising, so all drift is visible at once. It
assigns, promotes and infers no rating and writes no file; tests prove both by
monkeypatching every write API and deep-comparing inputs. Against today's tree it
returns **zero findings**.

Two digests now exist where one did. `mapping_digest` is SHA-256 of the mapping
file bytes. `policy_corpus_digest` covers every `.rego` in the benchmark version —
closing a real gap, because `metadata_digest` never covered the policies that
actually decide compliance, so a policy edit changed no recorded digest.

## What a scan freezes, and what a report renders from

Scan creation now pins `mapping_id`, `mapping_version`, `mapping_digest`, the
full `mapping_snapshot`, `policy_corpus_digest` and `evidence_version` in the same
INSERT as the existing metadata snapshot. `GET /v1/scans/{id}/soc2-report` renders
from that pinned snapshot, never from the file on disk, so a historical report is
reproducible after the mapping changes. A scan whose benchmark does not match the
mapping gets null columns and an explicit "no SOC 2 projection" answer rather than
an invented one.

The migration also extends the Phase 3 immutability trigger. Its `ROW(...)` list
was written before Phase 6 added `connection_snapshot`, so the frozen tenant
identity was in fact mutable after creation; it and the six Phase 7 columns are
now covered. This was verified live: an `UPDATE` of either raises.

## Semantics that Phase 7 deliberately does not bend

A `No` stays `No` for M365 configuration coverage no matter what a scan found.
Approving manual evidence changes no scan result, no state count and neither
score — proved by a test that byte-compares every counter before and after an
approval. Manual and inherited evidence is reported as a separate residual stream
alongside the automated one. Coverage is always returned with numerator and
denominator, never a bare percentage, and a 100%-of-assessed scan with incomplete
coverage is labelled a partial assessment.

## Evidence is now owned, bounded and audited

Authorization is by opaque `object_id` resolved together with `user_id` in one
query, answering 404 rather than 403 so the endpoints are not existence oracles.
Storage keys are tenant-scoped and random and contain no part of the display
filename. The four unauthenticated cross-tenant debug routes are deleted, and a
structural test enumerates the router so a future route cannot regress.

Every bound fails closed with a stable code: size, magic-byte type (an extension
that disagrees with content is a rejection, not a coercion), PDF pages, image
pixels, archive entries and expansion ratio, extracted characters, and a wall
clock. Extraction happens exactly once per upload — it previously ran twice — off
the event loop. The untimed `soffice` subprocess is gone.

`evidence_audit_event` and `manual_evidence_revision` reject `UPDATE` and `DELETE`
at the database. Manual evidence has an explicit state machine whose every
transition writes a numbered revision under a row lock, and independent review is
a CHECK constraint (`reviewer_user_id <> user_id`), not a convention.

The legacy `security/evidence_ui` app no longer builds a server, wildcard CORS or
a static mount on import; serving requires an explicit opt-in and refuses in
production. The stored-XSS sink is escaped at the sink, the unauthenticated
log-injection endpoint is removed, and `/frontend/app.py` no longer serves source.

## Documentation is generated

`tools/docs/generate_control_status.py` renders `controls.md` for all four
benchmarks from `metadata.json`, deterministically and with no timestamp, and
`--check` fails CI on drift. That gate is wired into `ci.engine.yml`. The old v6
page claimed 47 automated / 21 blocked / 14 manual / 46 not-started against a
metadata reality of 69 / 31 / 11 / 17, and conflated three different "manual"
questions (24 `is_manual`, 23 `benchmark_audit_type`, 11 `automation_status`);
the generated page reports them separately.

## Verification

Exact commands and results are in [verification.json](verification.json), with
output under [verification/](verification). Backend and tools **453 passed**;
engine **1,375 passed, 1 skipped, 11 xfailed**; `opa check --strict` clean and
**550/550** Rego; frontend typecheck, **243** tests, lint (9 pre-existing
warnings) and build; the documentation gate; Bandit clean over `backend-api/app`
and `backend-api/tests`; all **8** pre-commit hooks; actionlint; `git diff --check`.

Each of the six implementation streams was independently reviewed by Codex
read-only, per the standing review instruction. Those reviews found and drove
fixes for 12 evidence defects (including an unbounded ingress that spooled a body
to disk before authentication, a cross-tenant folder read, and a delete that
tombstoned a row whose bytes had not actually been removed), 10 manual-evidence
defects (including a reviewer able to read another account's draft, and caller
free text copied into provenance), 6 SOC 2 projection defects, and 7 crosswalk
defects. Engineering review is not GRC approval.

**The integration work itself was not Codex-reviewed.** The migration, the three
new models, the config block, the mapping artifact, the Compose/Dockerfile and CI
changes were written by the orchestrating session, and the Codex account hit its
usage limit before that review could run (it resets 2026-09-07). Deterministic
self-verification was substituted and is recorded in
[verification.json](verification.json): the mapping validates structurally
(47 points of focus, 44 unique ids, ratings in vocabulary, no `No` row carrying
evidence, both reference directions closed, CC1–CC9 covered, `approved: false`);
`alembic revision --autogenerate` proposes **no change to any Phase 7 table**,
so models and migration agree; the rewritten `protect_phase3_scan_inputs`
protects all 15 original columns plus the 7 new ones, with none dropped; the
Compose mounts match the `config.py` defaults exactly and both source paths
exist; the CI gate is in the `test` job and fails on drift. That substitution is
weaker than an independent reviewer and this work should get one before merge.

## Defects this phase found in existing code

- **The Phase 3 scan freeze did not cover `connection_snapshot`.** Phase 6 added
  the column; the trigger's `ROW(...)` list was never extended, so frozen tenant
  identity was mutable. Fixed here.
- **`test_wiring.py` never checked collectors for non-`ready` controls.** Eleven
  v6 controls (7.2.1–7.2.11, 7.3.2) reference `sharepoint.spo_tenant` and
  `sharepoint.spo_sync_client_restriction`, which exist as files but are absent
  from `registry.py`, and nothing failed. Now pinned as 11 explicit xfails so new
  drift fails while the existing debt is recorded honestly. `registry.py` was not
  edited.
- **A pre-existing timezone defect in the Phase 6 dispatcher.** The API writes
  `deadline_at` as naive UTC; the dispatcher compares it against PostgreSQL
  `now()`. When the database server is not UTC, every new scan is immediately
  judged past its deadline, reconcile terminalizes it, and the dispatcher
  publishes nothing. `test_phase4_worker_contract` fails on a non-UTC server and
  passes on a UTC one — confirmed both ways, and reproduced identically on the
  untouched Phase 6 worktree. CI's `postgres:16` container defaults to UTC, which
  is why it has never fired there. **Not fixed here** (Phase 6 owns the lifecycle);
  it needs either timezone-aware columns or a UTC-normalised comparison.
- `test_phase5_cookie_auth.py` pinned a literal migration head, so it broke in
  Phase 6 and again here. It now derives the head from the migration graph.
- `alembic/env.py` imported models by hand and had already drifted (missing
  `ScanDispatch`, the manual detail and contact tables), so autogenerate would
  propose dropping them. It now imports the model package.

## Standard handoff

- **Phase:** 7 — local engineering implemented; external acceptance pending.
- **Baseline:** `8736fcb9` plus the exact 274-file Phase 6 prerequisite snapshot.
- **Branch/commit/PR:** `fix/soc2-phase-7-audit-evidence`; uncommitted/unpushed; no PR.
- **Findings addressed locally:** AUTH-01, AUTH-02, EVI-01, EVI-02, EVI-03, DOC-02.
- **Files changed:** [phase-7-changes.json](phase-7-changes.json) — 67 files.
- **Decisions:** mapping as a versioned artifact with a byte digest; render reports
  from the pinned snapshot; opaque object ids with single-query ownership;
  fail-closed bounds; append-only history enforced in the database; independent
  review as a CHECK constraint; manual evidence never alters automated scoring;
  documentation generated from metadata.
- **Tests:** see [verification.json](verification.json).
- **Security/GRC review:** local code and Codex reviews performed. GRC approval,
  maintainer integration and deployment validation remain external.
- **Known gaps:**
  - **Item 15.1.9 is not finished.** Report generation and OCR still run
    synchronously in the API. They are now fully bounded and time-limited, and the
    untimed converter subprocess is gone, but moving them to the worker was
    deliberately deferred: the worker owns no evidence consumer yet, and a
    half-moved pipeline would leave every scan without a report. The worker image
    also installs no OCR stack.
  - **No external object storage.** `EvidenceStorage` has a local filesystem
    backend on a named volume; S3/MinIO is a deployment decision still gated on
    unapproved decision D04. Adding a dependency is also blocked by `--frozen` locks.
  - **Retention is structural, not scheduled.** Rows carry a retention policy
    version and expiry and the expiry helper exists, but no periodic job runs it.
  - **No frontend for the new surfaces.** Types only; the SOC 2 report and the
    manual-evidence workflow have no UI.
  - Phase 0 decisions D01–D10 remain unapproved drafts with no named owners, so
    the mapping records `approved: false` and the retention defaults are labelled
    `phase7-draft-1`.
  - Phase 4's required status checks were still never applied to branch
    protection, so a green local run is not an enforced gate.
  - The Compose evidence volume and mappings mount were not exercised against a
    running container; `container_smoke.py` was not re-run.
- **Next unblocked phase:** Phase 8 may build on this mapping and evidence
  foundation. Production acceptance still requires the owner actions above, and
  the dispatcher timezone defect should be fixed before any non-UTC deployment.
