# Phase 3 implementation design and plan

User instruction: implement Phase 3. Engineering implementation is authorized;
GRC acceptance remains pending. Base: Phase 1 commit 8736fcb9, incorporating its
single migration head without modifying either prior worktree.

Architecture: preserve Scan and ScanResult, add explicit selection and immutable
provenance snapshots, validate OPA output with strict Pydantic types, and derive
scan counters/scores from persisted outcomes. Six terminal outcomes: passed,
failed, indeterminate, error, skipped (unselected only), not_assessable.
Pending remains a lifecycle state. No not_applicable state or GRC rating changes.

Compliance = passed / (passed + failed), null when none assessed. Coverage =
(passed + failed) / selected_count, null for zero selected. Selected controls
outside automation remain in the denominator. Existing records without frozen
selection/provenance retain explicit legacy/unknown attribution; do not invent
historical provenance or reinterpret old skipped outcomes as known selection.

Prefer additive columns over a replacement schema; retain metadata and policy
snapshots (public source artifacts), hash normalized input without storing extra
raw tenant payloads, and bind evaluation to the exact policy bytes submitted to
OPA. Store build source identity and actual OPA version. Terminal records cannot
be overwritten by redelivery. This is the minimum evidence foundation, not the
Phase 6 outbox/cancellation lifecycle or Phase 7 retention/report audit system.

- [x] Backend models, forward migration from Phase 1 head, typed schemas and API
  selection validation. Add failing API tests for unknown IDs, [] and empty
  metadata, mixed automation readiness and deduplicated IDs; migration tests
  preserve legacy rows and prohibit terminal provenance mutation.
- [x] Typed OPA contract and worker status mapping. Failing tests cover true,
  false, null, missing/malformed output, collector envelopes/exceptions and OPA
  failures; tests prove policy submitted matches persisted digest.
- [x] Persist provenance and derive separate scores/counts. Failing tests cover
  mixed outcomes, all errors, no selected controls, selected manual controls,
  duplicate delivery and immutable terminal records. PostgreSQL integration
  validates SQL, migration and persistence.
- [x] Frontend shared typed statuses/scores and detail/chart/dashboard rendering.
  Tests cover all states, null scores and 100% assessed with partial coverage.
- [x] Integrate, run focused and existing suites, migration upgrade, frontend
  build/typecheck/lint; review spec and code quality; write standard handoff
  with exact results, PR overlaps, pending GRC decisions and rollout limits.

Run engine tests with `uv run --project engine --extra dev pytest engine/tests`.
Run backend tests using `uv run --project backend-api --with pytest python -m
pytest backend-api/tests/test_phase3_scans.py backend-api/tests/test_phase3_migrations.py`. Use the Phase 1 disposable PostgreSQL fixture for real
migration/database tests. Frontend uses lockfile dependencies and Node 20.
