# Phase 6 — Reliable scans and selected-tenant SharePoint

Date: 2026-09-06 (Australia/Melbourne).

Local engineering implemented. Upstream integration, hosted checks, deployment
acceptance and live Microsoft tenant acceptance remain pending. No public PR,
production service, external tenant or repository setting was changed.

## Baseline and workspace

- Worktree: `/Users/clupa/Documents/projects/autoaudit/AutoAudit-phase-6`.
- Branch: `fix/soc2-phase-6-reliable-scans`; uncommitted and unpushed.
- Git base: Phase 1 `8736fcb9`, overlaid with the complete Phase 5 working source.
  [phase-5-snapshot.json](phase-5-snapshot.json) records SHA-256 hashes for all
  240 changed/new prerequisite files. Every earlier worktree remains preserved.
- Read-only upstream refresh: `bba14810f558190ee5221017c11864d300f8078a`, unchanged
  from the Phase 5 handoff. This local stack still needs reviewed integration
  with current upstream; it is not represented as already based on main.
- [Coordination review](coordination-review.md) records the overlapping PRs.

## Implemented behavior

The API commits the scan, frozen metadata/selection/connection identity, result
rows and initial dispatch intent in one PostgreSQL transaction. It returns 201
without contacting Redis. Scan creation therefore succeeds during a broker
outage and preserves the work needed for recovery.

`scan_dispatch` stores fixed task identity, scan/result identifiers, publish
attempt count, next attempt, last successful publish timestamp and a redacted
failure code. The orchestrator commits all child intents with the transition to
running. The publisher uses deterministic task IDs and sends only identifiers,
with the database request ID in Celery headers. Delivery remains at least once;
Celery task IDs are not treated as deduplication enforcement.

Every result writer locks its parent scan before touching a child. A conditional
pending-to-terminal write preserves the first recorded evidence. Finalization
locks before counting and derives all summaries from result rows. Terminal scans
cannot reopen. Duplicate task delivery and worker death after a committed result
do not double-count. A rejected late result or exhausted retry reports a safe
`ignored` outcome.

The independent dispatcher process polls PostgreSQL, even while Redis is down.
It recovers missing root/child intents, retries failed or stale publication, and
terminalizes unresolved work at a deadline or retry exhaustion. Locked scans are
skipped before limiting candidate work, allowing unrelated scans to progress.
Legacy scans whose selection is unknown fail visibly while preserving null
selection/score attribution and existing terminal evidence.

`POST /v1/scans/{id}/cancel` is owner-authorized and idempotent. It locks the scan,
marks unresolved results indeterminate with cancellation provenance, derives
counts, removes dispatch work and records the terminal `cancelled` state. Delete
uses the same parent-first lock and removes dispatch/results before the parent.
In-flight read-only operations may finish, but their later writes cannot change
a cancelled/deleted scan. The frontend offers cancellation and stops polling
terminal scans. Polling waits for each response before scheduling another request,
including when a response takes longer than the normal polling interval.

Each M365 connection now optionally holds its SharePoint admin URL, tenant GUID
and certificate alias. These fields are frozen with tenant/client identity when
the scan is created. Workers reject changed/inactive connections before decryption.
SharePoint controls validate the selected tenant against authenticated Graph
`/sites/root` evidence, including `sharepointIds.tenantId` and the root hostname,
before constructing a PowerShell client. Missing configuration, mismatched identity,
missing permissions or malformed proof produces `indeterminate` with
`sharepoint_tenant_unverified`. No global SharePoint URL/alias is substituted.
Readiness includes the additional Graph `Sites.Read.All` runtime requirement.

The original safe request ID is persisted on the scan, sent in task headers,
propagated through collector/Graph/PowerShell HTTP calls, recorded in OPA execution
events and provenance, and logged by the PowerShell service. Per-execution context
is reset after each evaluation. Events contain identifiers and fixed stage names,
not tokens or raw evidence.

## Runtime and compatibility

See [lifecycle-runbook.md](lifecycle-runbook.md) for state transitions, recovery,
configuration and rollout. Migration `e6a13c95d842` follows Phase 5 and preserves
existing data. It adds nullable attribution for historical scans and a durable
outbox; it never invents historical SharePoint bindings.

Both Compose templates include a supervised `dispatcher` service using the worker
image. The dispatcher does not depend on Redis startup health. The optional
SharePoint overlay provisions certificates only; URL and alias selection now
belong to the saved M365 connection. Existing global worker settings are accepted
for compatibility but are ignored for scan execution.

## Verification

Exact commands and results are recorded in [verification.json](verification.json).
The checks include the complete engine and backend/tools suites with required
PostgreSQL and OPA integration, all Rego tests/strict check, frontend tests and
build checks, lint/security hooks, and actual container startup/recovery.

The container smoke test creates an internal disposable network, migrates the
actual API image, starts a real Celery worker, commits synthetic scan/outbox data,
stops Redis, observes a durable redacted publication failure, restarts Redis and
observes the dispatcher/worker reach a terminal scan. It removes its containers
and network afterward. This verifies actual process/broker integration, without
calling Microsoft or using tenant credentials.

Independent review identified and corrected legacy NULL-selection recovery,
locked-batch starvation, certificate alias validation mismatch, cancellation
provenance, late task outcome reporting and slow frontend polling. Adversarial
regressions cover each corrected behavior.

## Standard handoff

- **Phase:** 6 — local engineering implemented; external acceptance pending.
- **Baseline:** `8736fcb9` plus the exact 240-file Phase 5 prerequisite snapshot.
- **Branch/commit/PR:** `fix/soc2-phase-6-reliable-scans`; uncommitted/unpushed; no PR.
- **Findings addressed locally:** REL-01, REL-02, REL-03, REL-04, TEN-01.
- **Files changed:** [phase-6-changes.json](phase-6-changes.json) separates this phase
  from its prerequisite stack.
- **Decisions:** PostgreSQL outbox; independent polling recovery; parent-first
  locking; immutable first result; bounded at-least-once delivery; terminal
  cancellation; connection-frozen tenant binding; fail-closed SharePoint proof.
- **Tests:** See the exact verification record and commands below.
- **Security/GRC review:** Local code/spec reviews performed; maintainer integration,
  deployment validation, incident follow-up and GRC acceptance remain external.
- **Known gaps:** Real Microsoft certificate/module/tenant acceptance; sovereign
  cloud and multi-geo SharePoint are not inferred from the commercial-cloud proof;
  prerequisite hosted gates and GRC decisions remain pending. In-flight operations
  are not forcibly revoked by cancellation. Existing frontend dependency/lint/chunk
  advisories remain, outside this lifecycle change.
- **Next unblocked phase:** Phase 7 may build locally on this provenance/lifecycle
  foundation. Production acceptance still requires the owner actions above.
