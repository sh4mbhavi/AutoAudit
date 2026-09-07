# AutoAudit SOC 2 Execution Plan

- **Plan status:** Ready for execution
- **Baseline date:** 2026-09-05 (Australia/Melbourne)
- **Baseline commit:** `be241f52beb5ffec10904771bf7cfa4b98233ab0`
- **Baseline merge:** PR #303 — Intune Settings Catalog collector
- **Benchmark scope:** CIS Microsoft 365 Foundations Benchmark v6.0.0
- **SOC 2 scope:** Common Criteria CC1–CC9, with the authoritative automated crosswalk limited to CC6 and CC7
- **Estimated engineering effort:** 85–135 person-days for the full program
- **Expected elapsed time:** 10–14 weeks with three engineers, a part-time GRC reviewer, and infrastructure support

## 1. Purpose

This document is the execution source for bringing AutoAudit's code, scan evidence, operational controls, and SOC 2 reporting to an audit-ready state.

It is intentionally written so that a fresh implementation session can execute one phase without relying on the original audit conversation. Each phase includes:

- prerequisites and dependencies;
- exact scope and expected deliverables;
- repository sources and patterns to copy;
- tests and acceptance criteria;
- explicit anti-pattern guards;
- a copy-ready session brief.

This plan does not declare AutoAudit SOC 2 compliant or certified. A SOC 2 examination also requires organization-level controls, operating evidence, management assertions, and an independent auditor.

## 2. Non-negotiable control rules

1. The SOC 2 Yes/Partial/No ratings in Appendix A are human-owned GRC judgments. Engineering may prove or disprove technical evidence but must not silently change a rating.
2. A SOC 2 `No` caused by organizational, process, physical, endpoint, recovery, or vendor scope must remain `No` for M365 configuration coverage. Record manual or inherited evidence separately.
3. CIS identifiers are fixed to Microsoft 365 Foundations v6.0.0. Do not reuse control numbers from another benchmark version.
4. A policy filename existing is not sufficient evidence. The collector, policy semantics, result state, provenance, and test coverage must all be trustworthy.
5. Missing, incomplete, unauthorized, truncated, or failed collection must never become `pass`.
6. A failed collection must not be represented as tenant noncompliance. Use an explicit indeterminate or error state.
7. AutoAudit must remain read-only by construction. Current read-only behavior based only on collector convention is insufficient.
8. Open PRs are implementation candidates, not current coverage. Rebase, inspect, test, and resolve overlaps before merging.
9. Never place credentials, access tokens, refresh tokens, tenant secrets, or raw sensitive evidence in logs, URLs, task messages, test fixtures, or tracked example files.
10. Do not rewrite Git history, rotate an external credential, alter branch protection, or change production infrastructure without the appropriate repository or platform owner coordinating the action.

## 3. Current baseline and known gaps

At the baseline commit:

- local `main` matched `upstream/main`;
- the worktree was clean;
- the repository contained 140 CIS v6 controls;
- 69 controls were `ready`, 31 `blocked`, 12 `deferred`, 11 `manual`, and 17 `not_started`;
- all 44 unique CIS controls cited by the supplied CC6/CC7 crosswalk resolved to a ready metadata entry, registered collector, and real Rego policy;
- the prior statement that the repository had 61 automated policies was stale;
- engine Python tests returned 496 passed and 1 skipped;
- the existing OPA suite returned 31/31 passed, but only three of the 69 CIS policies had dedicated semantic Rego test files;
- `opa check --strict` found eight unused-variable or unused-argument errors;
- frontend build passed, TypeScript had one error, and the local Node 26.4 test run had 180 passes and 24 failures; CI currently uses Node 20;
- Alembic had two active heads;
- backend CI had no meaningful unit or integration test job;
- required GitHub status-check enforcement was off.

### 3.1 Stable finding identifiers

Use these identifiers in commits, PR descriptions, tests, and handoffs.

| ID | Priority | Finding |
|---|---|---|
| SEC-01 | Critical | A live-looking Google OAuth client secret is tracked in `env.example`. |
| SEC-02 | Critical | The PowerShell `/execute` boundary accepts unauthenticated caller-controlled cmdlets and parameters. |
| SEC-03 | Critical | Backend startup creates or resets a known administrator and prints its password. |
| SEC-04 | High | Password-reset and verification tokens are logged in plaintext. |
| SEC-05 | High | Decrypted M365 client secrets are serialized into Redis/Celery messages once per control. |
| SEC-06 | High | Browser authentication tokens are returned through the URL and stored in browser-accessible storage. |
| SEC-07 | High | OAuth provider access and refresh tokens are stored as plaintext database text. |
| AUTH-01 | High | Evidence report retrieval lacks object-level ownership authorization. |
| AUTH-02 | High | The legacy evidence application exposes unauthenticated logs/pages and unsafe stored content if deployed. |
| EVI-01 | High | Evidence uploads and OCR are synchronous, unbounded, extension-trusting, locally retained, and collision-prone. |
| EVI-02 | High | Completed scans do not preserve immutable policy, metadata, collector, engine, OPA, and input provenance. |
| EVI-03 | High | Manual verification is mutable and lacks reviewer approval, attachments, expiry, provenance, and append-only history. |
| COR-01 | High | Invalid or empty effective control selections can complete at 100% while nothing was assessed. |
| COR-02 | High | Errors and skipped controls are excluded from the score, overstating posture and hiding coverage. |
| DB-01 | High | Alembic has two active heads while startup runs `alembic upgrade head`. |
| REL-01 | High | Scan creation commits before queueing, so broker failures leave orphaned pending scans. |
| REL-02 | High | Final tasks can both miss finalization and leave a completed scan in `running`. |
| REL-03 | High | Celery redelivery can double-increment counters because updates are not idempotent. |
| REL-04 | High | Orchestration exceptions can leave scans without a terminal state or recovery path. |
| TEN-01 | High | SharePoint evidence can originate from a globally configured tenant different from the selected Graph/Exchange tenant. |
| POL-01 | Critical | CIS 2.1.5 fails open for absent or partially disabled Safe Attachments configuration. |
| POL-02 | Critical | CIS 2.4.4 produces conflicting outputs when ZAP is false. |
| POL-03 | High | CIS 1.1.1, 1.1.4, and 1.3.1 can pass with empty essential evidence. |
| POL-04 | High | CIS 5.1.6.1 is heuristic and its collector does not return the documented domain fields. |
| POL-05 | Medium | Policy/metadata permission annotations disagree for multiple ready controls. |
| CI-01 | High | Backend, policy behavior, migration, container startup, and important engine tests are not fully gated. |
| CI-02 | High | Main can merge with failed or absent required checks. |
| CI-03 | Medium | OPA is downloaded as mutable `latest`, Grype is non-blocking, and dependency automation is disabled. |
| PERF-01 | Medium | 69 ready policies use 43 unique collectors, but evidence is recollected per control. |
| PERF-02 | Medium | Graph clients/tokens are reconstructed, retry behavior is incomplete, and pagination can silently truncate. |
| PERF-03 | Medium | The Settings Catalog collector performs serial N+1 requests. |
| PERF-04 | Medium | PowerShell opens a new blocking remote session per control in a single-process async service. |
| PERF-05 | Low | Frontend polling repeatedly transfers full scan/result/evidence payloads. |
| DOC-01 | High | Public SOC 2 Type II, zero-knowledge, bank-level encryption, and related claims are not substantiated by repository evidence. |
| DOC-02 | Medium | CIS status documentation is stale and contradicts current metadata. |

## 4. Execution protocol for every session

Every implementation session must follow this protocol.

### 4.1 Start-of-session checks

```bash
git fetch upstream --prune --tags
git status --short --branch
git rev-parse HEAD
git rev-parse upstream/main
git log -5 --first-parent --date=iso --pretty='%h %ad %s'
```

If `main` no longer equals the plan baseline, the session must:

1. inspect changes since `be241f52`;
2. refresh any affected findings and open-PR assumptions;
3. record the new baseline in its handoff;
4. avoid destructive reset or checkout commands.

Use a dedicated branch or worktree for each phase. Do not run two sessions against the same files unless the work is explicitly coordinated.

### 4.2 Open-PR check

Before implementing, search open PRs for the finding and inspect the full diff. Relevant candidates at the plan baseline are listed in Section 7.

Do not merge a PR solely because its title matches the phase. Confirm:

- it is based on current `main`;
- it solves the complete finding rather than one symptom;
- it does not weaken read-only behavior or evidence semantics;
- it has tests required by this plan;
- overlapping PRs have been resolved or closed.

### 4.3 Development rules

- Add a failing test that reproduces each deterministic defect before fixing it.
- Reuse documented repository patterns rather than inventing new framework APIs.
- Keep schema, migration, API, worker, frontend, and documentation changes synchronized.
- Store migrations as forward-only changes; never edit already-deployed migration history without explicit approval.
- Keep externally visible behavior backward compatible unless the phase explicitly defines a breaking contract.
- Redact test fixtures and error messages.
- Update generated/status documentation from metadata instead of duplicating status by hand.

### 4.4 Handoff contract

Every phase must end with a handoff containing:

```text
Phase:
Baseline commit:
Branch/commit/PR:
Findings closed:
Files changed:
Decisions made:
Tests run and exact results:
Security/GRC review required:
Known gaps or follow-up work:
Next unblocked phase:
```

Do not report a phase complete if a required test is failing or an external decision is still silently assumed. Mark the phase blocked and identify the exact owner or decision needed.

## 5. Documented implementation surfaces

Phase 0 must reconfirm these before implementation because dependencies and Microsoft APIs can change.

### 5.1 Allowed repository APIs and patterns

| Surface | Existing pattern to copy | Constraint |
|---|---|---|
| Graph collection | `engine/collectors/graph_client.py` and `engine/collectors/README.md` | Use read-only GET collection, explicit pagination, documented Graph endpoints, and throttling-aware behavior. |
| Collector registration | `engine/collectors/registry.py` | A ready metadata collector ID must resolve exactly once. Do not dynamically import arbitrary collector names from user input. |
| Policy metadata | `engine/policies/cis/microsoft-365-foundations/v6.0.0/metadata.json` | Preserve the fixed benchmark version; validate file, package, collector, status, and permission consistency. |
| Policy behavior tests | `engine/tests/test_cis_1_2_2_shared_mailbox_signin.rego` | Copy table-style pass, fail, missing, malformed, and boundary cases. |
| Structural policy tests | `engine/tests/test_wiring.py` | Extend existing metadata/registry/package assertions instead of creating a disconnected validator. |
| PowerShell input validation | `engine/powershell/service/schemas.py` | Reuse Pydantic validation form, but replace the permissive cmdlet dictionary with closed operation schemas. |
| PowerShell certificate resolution | `engine/powershell/service/executor.py` | Reuse certificate-alias resolution; never accept a raw certificate path or arbitrary script from the caller. |
| Resource ownership | `backend-api/app/api/v1/m365_connections.py` and `backend-api/app/api/v1/manual_verification.py` | Resolve the parent resource through the authenticated user before returning or mutating children. |
| Secret encryption | `backend-api/app/services/encryption.py` | Extend the existing abstraction with key versioning and rotation; do not add a second incompatible encryption path. |
| External-service error translation | `backend-api/app/services/m365_graph.py` | Reuse safe exception translation and blocking-call offload patterns. |
| Request correlation | `backend-api/app/core/middleware.py` | Propagate the existing request ID into scan, task, OPA, and PowerShell events. |
| Current scan orchestration | `backend-api/app/api/v1/scans.py`, `engine/worker/tasks.py`, `engine/worker/db.py` | Replace unsafe transitions with an explicit, idempotent state machine; do not layer new counters over existing races. |

### 5.2 API anti-patterns to reject

- Invented Microsoft Graph endpoints, undocumented query parameters, or assumed permissions.
- Raw or generic PowerShell cmdlet execution.
- Any PowerShell operation not mapped to an exact read-only operation identifier and typed parameter schema.
- A default-to-empty collection followed by a compliant result without a documented not-applicable rule.
- OPA results represented as an unvalidated free-form dictionary.
- Compliance scores without a separately displayed coverage denominator.
- Mutable scan evidence without history or provenance.
- Browser-stored bearer tokens after cookie authentication is introduced.
- Direct synchronous OCR or document parsing inside the async API process.
- Performance batching before idempotency and tenant isolation are proven.

## 6. Dependency and sequencing map

| Phase | Depends on | May run in parallel with | Must not overlap files with |
|---|---|---|---|
| 0 | None | Nothing; it establishes decisions | All implementation phases |
| 1 | 0 | Phase 2, using separate branches | Phases 5 and 7 where auth/config files overlap |
| 2 | 0 | Phase 1 | Phase 3 policy-result contract work |
| 3 | 1 and 2 | None recommended | Phases 6 and 7 |
| 4 | 2 and contract decisions from 3 | Documentation-only work | Any session editing the same workflows |
| 5 | 1 and 4 test foundations | Evidence UI work from 7 if coordinated | Phase 6 worker/task changes |
| 6 | 3 and 5 | Frontend-only work | Phase 9 task/collector batching |
| 7 | 3, 4, and 6 provenance foundation | Phase 9 frontend performance if separate pages | Phase 8 mapping/report changes |
| 8 | 4 and 7 | Parts of Phase 9 on unrelated collectors | Other sessions implementing the same CIS controls |
| 9 | 5 and 6 | Phase 8 only with collector ownership assigned | Worker/Graph/PowerShell files owned by other sessions |
| 10 | 3, 5, 6, and 7 | Late Phase 8/9 after interfaces stabilize | Infrastructure files used by security work |
| 11 | All selected phases | Nothing | All unfinished implementation |

Default to sequential execution. Parallelize only when branches, file ownership, and merge order are explicitly assigned.

## 7. Open PR coordination

Refresh this list during Phase 0. At the baseline, these PRs may contain reusable work:

| Area | Candidate PRs | Required disposition |
|---|---|---|
| Alembic heads | #352 | Rebase, confirm both upgrade histories, and add empty/current database tests. |
| Backend tests | #355 | Use as a foundation only if it tests current contracts and migrations. |
| Authentication/RBAC | #350, #292 | Review cookie flags, CSRF, role semantics, CORS, and ownership before merge. |
| CORS/headers/config | #305, #318, #330 | Consolidate environment validation and avoid contradictory configuration paths. |
| Secret/dependency scanning | #331, #326 | Secret scanning must cover tracked examples and history; scanners must block at an agreed severity. |
| Multi-client collectors | #351 | Reconcile with the collector-once/fan-out design before adopting. |
| CIS coverage | #297, #307, #328, #333, #348, #336, #325, #344 | Land only after policy semantic and result-state gates exist. |
| Overlapping CIS implementation | #320 and #342 | Select one implementation for 2.4.1/2.4.2 and close or supersede the other. |
| Tests for existing controls | #345, #356 | Rebase into the semantic-test tranche and ensure missing/malformed cases are included. |

PR links use `https://github.com/Hardhat-Enterprises/AutoAudit/pull/<number>`.

## 8. Phase 0 — Rebaseline, documentation discovery, and decision locks

**Objective:** Establish the current source of truth and resolve the decisions that otherwise cause later sessions to invent semantics.

**Estimated effort:** 2–3 person-days, including GRC review.

### 8.1 What to implement

1. Re-run the Git and PR inventory from Section 4.
2. Recalculate metadata status totals and the crosswalk's unique policy/collector resolution.
3. Read the repository and benchmark documentation before selecting implementation APIs:
   - `README.md`;
   - `backend-api/README.md`;
   - `engine/collectors/README.md`;
   - `engine/policies/README.md`;
   - `docs/engine/sharepoint-control-development.md`;
   - `docs/engine/sharepoint-local-runtime.md`;
   - `docs/engine/manual-collector-testing.md`;
   - `docs/features/pre-scan/prescan-readiness.md`;
   - `docs/DevSecOps/workflow-documentation.md`;
   - `docs/compliance/manual_control_classification.md`;
   - Appendix A of this plan.
4. Create a short decision record covering:
   - result states and their meanings;
   - compliance score versus coverage score;
   - zero-resource and not-applicable semantics;
   - evidence retention and deletion;
   - evidence redaction and permitted raw fields;
   - crosswalk approval owner and change workflow;
   - benchmark/mapping versioning rules;
   - public SOC 2 wording owner;
   - whether 6.1.2 can be not applicable for a legitimately mail-free tenant;
   - how 5.1.6.1 should be revalidated against the licensed CIS procedure.
5. Record the allowed APIs and Microsoft permission sources actually confirmed during the phase.

### 8.2 Documentation and patterns to copy

- Metadata schema: `engine/policies/cis/microsoft-365-foundations/v6.0.0/metadata.json`.
- Manual-control classification structure: `docs/compliance/manual_control_classification.md`.
- PASS/FAIL versus ERROR guidance: `docs/engine/sharepoint-control-development.md`.
- Risk prioritization: `docs/compliance/Risk_Impact_Prioritisation_Matrix.md`.

### 8.3 Verification checklist

- [ ] Current HEAD and upstream HEAD are recorded.
- [ ] Open and merged PR counts are refreshed.
- [ ] All Appendix B controls resolve to one ready metadata record, policy file, and registered collector.
- [ ] GRC approves result-state, score, retention, and rating ownership decisions.
- [ ] Current Microsoft API/PowerShell permission documentation is cited where permissions are changed.
- [ ] No SOC 2 rating was changed by engineering assumption.

### 8.4 Anti-pattern guards

- Do not begin database/API result-state work before the state meanings are approved.
- Do not treat repository marketing copy as evidence of certification.
- Do not use the stale `controls.md` status counts as the implementation source of truth.
- Do not infer that a Microsoft permission annotation is correct merely because it already exists in Rego or metadata.

### 8.5 Copy-ready session brief

```text
Execute Phase 0 of docs/compliance/SOC2_EXECUTION_PLAN.md. Refresh the Git/PR and CIS metadata baseline, read every Phase 0 source, validate Appendix B resolution, and create the required decision record. Do not implement control or runtime changes. Preserve the supplied SOC 2 ratings and return the standard handoff.
```

## 9. Phase 1 — Immediate credential, bootstrap, and migration containment

**Objective:** Remove immediately exploitable or audit-blocking defaults and restore a valid migration path.

**Findings:** SEC-01, SEC-03, SEC-04, DB-01, DOC-01.

**Estimated effort:** 2–4 person-days, plus identity/repository-owner coordination.

### 9.1 What to implement

1. Coordinate revocation and rotation of the Google OAuth credential exposed in `env.example`.
2. Replace the tracked value with a clear placeholder and ensure secret scanning does not exclude the affected example.
3. Assess Git history exposure. Propose history rewriting separately; do not perform it without repository-owner coordination.
4. Copy the environment-specific configuration approach from existing settings code and make administrator seeding explicitly development-only.
5. Remove password and token values from bootstrap, reset, and verification logs.
6. Ensure preview and production environments do not have a known default administrator.
7. Rebase or reproduce the candidate Alembic merge migration from PR #352.
8. Test the migration from both prior heads, a clean database, and a representative current database.
9. Remove or qualify unsubstantiated certification, zero-knowledge, bank-level encryption, and third-party-audit claims until GRC/legal provides approved wording.

### 9.2 Documentation and patterns to copy

- Settings: `backend-api/app/core/config.py`.
- Password hashing/user setup: `backend-api/app/db/init_db.py`.
- Existing structured middleware logging: `backend-api/app/core/middleware.py`.
- Migration guidance: `backend-api/README.md`.
- Relevant files: `env.example`, `.pre-commit-config.yaml`, `.secrets.baseline`, `backend-api/entrypoint.sh`, `backend-api/app/core/users.py`.

### 9.3 Verification checklist

- [ ] The exposed credential is revoked or its status is explicitly recorded as externally blocked.
- [ ] No actual credential remains in tracked examples or fixtures.
- [ ] Secret scanning includes `env.example` and fails on a seeded canary secret.
- [ ] `rg -n "admin@example.com|admin_password|verification token|reset token"` finds no production-known password or token logging.
- [ ] Production/preview startup does not create, promote, or reset a default account.
- [ ] `uv run alembic heads` returns exactly one head.
- [ ] `uv run alembic upgrade head` passes on clean and both supported prior histories.
- [ ] Public claims have GRC-approved substantiation or are removed/qualified.

### 9.4 Anti-pattern guards

- Do not print a generated bootstrap password to shared logs.
- Do not replace one hardcoded secret with another environment default.
- Do not edit existing migration revision IDs or deployed migration bodies.
- Do not rewrite shared Git history inside the implementation PR.
- Do not claim a credential is invalid unless the identity owner confirms revocation or validity.

### 9.5 Copy-ready session brief

```text
Execute Phase 1 of docs/compliance/SOC2_EXECUTION_PLAN.md. Address SEC-01, SEC-03, SEC-04, DB-01, and DOC-01 using the listed patterns. Inspect PR #352 before implementing migration work. Add regression tests, do not rewrite Git history, and return the standard handoff with any external revocation or legal wording dependencies.
```

## 10. Phase 2 — CIS policy evidence-correctness hotfixes

**Objective:** Fix the known policies that can pass incorrectly or fail to return a determinate result.

**Findings:** POL-01, POL-02, POL-03, POL-04, POL-05.

**Estimated effort:** 4–6 person-days.

### 10.1 What to implement

1. Copy the semantic test structure from `engine/tests/test_cis_1_2_2_shared_mailbox_signin.rego`.
2. Add failing tests before changing each policy.
3. Fix CIS 2.1.5 so that:
   - absent ATP policy cannot pass;
   - each required insecure condition independently causes noncompliance;
   - missing required properties do not pass;
   - true, false, null, absent, malformed, and mixed cases are covered.
4. Fix CIS 2.4.4 so exactly one complete-rule output exists for true, false, null, absent, and malformed inputs.
5. Harden CIS 1.1.1, 1.1.4, and 1.3.1 so empty essential evidence does not pass.
6. Apply the approved Phase 0 decision for an empty 6.1.2 mailbox population.
7. Revalidate CIS 5.1.6.1 against the licensed CIS audit procedure and current Microsoft documentation. Either:
   - implement the correct domain setting and collector output; or
   - move the control out of `ready` until it is technically defensible.
8. Reconcile the identified permission annotation/metadata mismatches using current Microsoft documentation, then add a consistency test.
9. Clear all current `opa check --strict` errors.

### 10.2 Documentation and patterns to copy

- Rego test pattern: `engine/tests/test_cis_1_2_2_shared_mailbox_signin.rego`.
- Policy contracts: `engine/policies/README.md`.
- Collector contracts: `engine/collectors/README.md`.
- Structural checks: `engine/tests/test_wiring.py`.
- Affected policies:
  - `engine/policies/cis/microsoft-365-foundations/v6.0.0/2.1.5_Safe_Attachments_SharePoint_OneDrive_MSTeams_Enabled.rego`;
  - `engine/policies/cis/microsoft-365-foundations/v6.0.0/2.4.4_Zero_hour_AutoPurge_MSTeams_is_On.rego`;
  - `1.1.1_admin_cloud_only.rego`;
  - `1.1.4_admin_license_footprint.rego`;
  - `1.3.1_password_expiration.rego`;
  - `5.1.6.1_restrict_collaboration_invite_domains.rego`.

### 10.3 Verification checklist

- [ ] Every defect has a test that failed before the fix.
- [ ] Each affected policy covers pass, fail, missing, null, malformed, empty, and boundary inputs where applicable.
- [ ] OPA returns exactly one defined result for every test case.
- [ ] `opa check --strict engine/policies/cis/microsoft-365-foundations/v6.0.0` passes.
- [ ] `opa test engine/policies engine/tests` passes.
- [ ] Python wiring/validator tests pass.
- [ ] Any readiness or rating change for 5.1.6.1 has explicit GRC approval.
- [ ] Permission changes cite a current Microsoft primary source.

### 10.4 Anti-pattern guards

- Do not use `object.get(..., [], ...)` followed by “zero failures equals pass” for essential evidence.
- Do not conflate absent, not licensed, unauthorized, and secure configuration.
- Do not change the supplied SOC 2 rating because a policy was fixed or removed from ready status.
- Do not weaken tests to preserve current behavior.

### 10.5 Copy-ready session brief

```text
Execute Phase 2 of docs/compliance/SOC2_EXECUTION_PLAN.md. Fix POL-01 through POL-05 test-first, using the existing Rego table-test pattern. Preserve human-owned SOC 2 ratings, cite current Microsoft documentation for permission changes, make strict OPA checking pass, and return the standard handoff.
```

## 11. Phase 3 — Result semantics, scoring, and provenance foundation

**Objective:** Make scan results accurately represent what was assessed and preserve enough provenance for later audit evidence.

**Findings:** COR-01, COR-02, EVI-02 and the worker's current collapse of uncertainty into failure.

**Estimated effort:** 5–8 person-days.

### 11.1 What to implement

1. Implement the Phase 0-approved result taxonomy. Recommended minimum:
   - `passed`;
   - `failed`;
   - `indeterminate` for insufficient or ambiguous evidence;
   - `error` for collection/evaluation/system failure;
   - `skipped` for a valid but unselected control;
   - `not_assessable` for controls outside automated M365 configuration scope.
2. Define and validate a typed OPA result contract instead of accepting an arbitrary dictionary.
3. Reject unknown control IDs at the API boundary with a structured 4xx response.
4. Prevent empty effective selections from producing a completed 100% scan.
5. Display and persist separate measurements:
   - compliance percentage over determinate assessed controls;
   - coverage percentage over the selected or applicable population;
   - pass/fail/indeterminate/error/skipped counts.
6. Add the minimum provenance fields needed by later phases:
   - framework, benchmark, and version;
   - metadata digest;
   - policy file and policy digest;
   - collector ID;
   - engine Git SHA or image digest;
   - OPA version;
   - correlation ID;
   - collection/evaluation timestamps.
7. Create forward-only migrations and API schema updates.
8. Update frontend status and score rendering so it cannot label an unassessed scan compliant.

### 11.2 Documentation and patterns to copy

- Current scan/result models: `backend-api/app/models/compliance.py` and `backend-api/app/models/scan_result.py`.
- Current result persistence: `engine/worker/tasks.py` and `engine/worker/db.py`.
- Scan creation and selection: `backend-api/app/api/v1/scans.py`.
- Policy invocation: `engine/opa_client.py`.
- Existing progress summary endpoint: `backend-api/app/api/v1/scans.py`.
- PASS/FAIL/ERROR guidance: `docs/engine/sharepoint-control-development.md`.

### 11.3 Verification checklist

- [ ] Unknown control IDs return a validated 4xx response.
- [ ] Zero assessed controls cannot return 100% compliance.
- [ ] A collector exception becomes `error`, not `failed`.
- [ ] Missing essential input becomes `indeterminate`, not `passed`.
- [ ] Compliance and coverage percentages are independently tested.
- [ ] API schemas and frontend labels cover every state exhaustively.
- [ ] Completed results contain the minimum provenance fields.
- [ ] Migration upgrade/downgrade policy follows the Phase 0 decision and tests from Phase 1.

### 11.4 Anti-pattern guards

- Do not encode result states only in free-form messages.
- Do not preserve compatibility by mapping every new state back to failed in storage.
- Do not calculate coverage from ready controls alone when the user selected a broader population.
- Do not store unredacted raw tenant secrets or complete Graph/PowerShell payloads as provenance.

### 11.5 Copy-ready session brief

```text
Execute Phase 3 of docs/compliance/SOC2_EXECUTION_PLAN.md. Implement the approved result taxonomy, reject invalid selections, separate compliance from coverage, and add the minimum immutable provenance foundation across database, API, worker, and frontend. Use forward-only migrations, add exhaustive tests, and return the standard handoff.
```

## 12. Phase 4 — Semantic tests, CI gates, and branch protection

**Objective:** Make evidence correctness and change control enforceable before merge.

**Findings:** CI-01, CI-02, CI-03 and the policy/collector semantic coverage gap.

**Estimated effort:** 7–10 person-days.

### 12.1 What to implement

1. Inspect and reuse viable work from PRs #331, #326, #345, #355, and #356.
2. Add direct semantic Rego tests for all 44 crosswalk controls in Appendix B.
3. Add mocked collector contract tests for each collector used by the crosswalk, emphasizing empty, malformed, pagination, permission-denied, throttled, and partial responses.
4. Run every engine Python test in CI, not only `test_wiring.py`.
5. Pin OPA to an explicit reviewed version and verify its checksum.
6. Add `opa check --strict` and `opa test` to the engine gate.
7. Add backend unit tests, migration tests, application startup tests, and at least one worker/API contract test.
8. Repair the frontend type and test failures and keep Node versions aligned across CI and container builds.
9. Make the agreed Grype severity threshold blocking.
10. Re-enable dependency update automation with a manageable grouping and PR limit.
11. Expand workflow path filters so shared root configuration, Compose, security, and schema changes trigger affected suites.
12. After the workflows are green, have a repository maintainer configure:
    - required checks;
    - required review count;
    - CODEOWNERS review for policy, security, migration, and workflow areas;
    - no unchecked administrator bypass for ordinary merges;
    - stale-review dismissal after new commits.

### 12.2 Documentation and patterns to copy

- Engine CI: `.github/workflows/ci.engine.yml`.
- Backend CI: `.github/workflows/ci.backend-api.yml`.
- Frontend CI: `.github/workflows/ci.frontend.yml`.
- Current OPA workflow: `.github/workflows/ci.opa-eval.yml`.
- Grype workflow: `.github/workflows/ci.grype.yml`.
- Dependency automation: `.github/dependabot.yml`.
- Structural tests: `engine/tests/test_wiring.py` and `engine/tests/test_validators.py`.

### 12.3 Verification checklist

- [ ] All 44 crosswalk controls have direct semantic behavior coverage.
- [ ] Collector output contract tests cover all crosswalk collectors.
- [ ] Backend tests do not require manually starting localhost services.
- [ ] Clean-database and upgrade-path migration tests pass in CI.
- [ ] OPA version is pinned and checksum-verified.
- [ ] Strict OPA check and all OPA tests pass in CI.
- [ ] Frontend lint, typecheck, unit tests, and build pass on the same supported Node version.
- [ ] Critical scanner findings fail the build.
- [ ] Required GitHub checks are visibly enforced on `main`.
- [ ] A deliberately failing test PR cannot merge through the normal path.

### 12.4 Anti-pattern guards

- Do not download mutable `latest` tooling.
- Do not use `if: always()` in a way that turns a failed test into an overall successful gate.
- Do not count report/comment jobs as the required test itself.
- Do not mark scanners blocking without documenting suppression and emergency override processes.
- Do not enable branch requirements until the workflow names are stable and green.

### 12.5 Copy-ready session brief

```text
Execute Phase 4 of docs/compliance/SOC2_EXECUTION_PLAN.md. Inspect the listed open PRs, build semantic coverage for every Appendix B control and its collector contracts, add backend/migration/startup gates, pin OPA, restore frontend gates, and prepare required branch checks. Separate repository-setting changes from code changes and return the standard handoff.
```

## 13. Phase 5 — Runtime trust boundaries and secret handling

**Objective:** Enforce read-only operation and prevent credentials from crossing unsafe boundaries.

**Findings:** SEC-02, SEC-05, SEC-06, SEC-07 and insecure environment defaults.

**Estimated effort:** 6–10 person-days, plus deployment-owner work.

### 13.1 What to implement

1. Replace the generic PowerShell `cmdlet` API with fixed operation identifiers.
2. Define an allowlist mapping each operation to:
   - one exact read-only cmdlet or approved read-only sequence;
   - one module;
   - a typed set of allowed parameter names and values;
   - the collector IDs permitted to request it.
3. Reject unknown operations, unknown parameters, shell metacharacters, command separators, script blocks, raw certificate paths, and non-read operations.
4. Authenticate the worker-to-PowerShell service boundary using the approved service mechanism, and place it on a private network without a production host port.
5. Add tests using malicious cmdlet, parameter-name, parameter-value, tenant, certificate, and module payloads.
6. Enforce Graph GET-only access at the collector client boundary.
7. Change Celery task messages to carry scan/result/connection identifiers only.
8. Retrieve and decrypt M365 credentials just in time inside the executing worker, minimize their lifetime, and prevent serialization into retries or error records.
9. Require Redis authentication, TLS/private networking, and appropriate retention in production configuration.
10. Inspect and complete the HttpOnly-cookie direction from PR #350 with explicit CSRF, SameSite, Secure, expiry, logout, CORS, and refresh behavior.
11. Remove browser bearer-token storage and token-bearing callback fragments once cookie auth is active.
12. Delete unused provider access/refresh tokens after account linking or encrypt them with the existing versioned encryption abstraction.
13. Make JWT, Fernet, database, Redis, and origin configuration fail closed outside development.

### 13.2 Documentation and patterns to copy

- PowerShell validation form: `engine/powershell/service/schemas.py`.
- Certificate alias handling: `engine/powershell/service/executor.py`.
- Current client: `engine/collectors/powershell_client.py`.
- Graph client: `engine/collectors/graph_client.py`.
- Secret encryption: `backend-api/app/services/encryption.py`.
- OAuth state cookie: `backend-api/app/api/v1/auth.py`.
- Current worker messages: `engine/worker/tasks.py`.
- Configuration: `backend-api/app/core/config.py`, `docker-compose.yml`.

### 13.3 Verification checklist

- [ ] The service has no arbitrary cmdlet/script endpoint.
- [ ] Every permitted PowerShell operation is read-only and has typed parameters.
- [ ] Malicious command/parameter payload tests are rejected before script construction.
- [ ] Production Compose/IaC does not expose PowerShell or Redis publicly.
- [ ] Unauthenticated service calls fail.
- [ ] No decrypted client secret appears in Celery message serialization, logs, traces, or result records.
- [ ] Graph mutation methods are unavailable to registered collectors.
- [ ] Authentication works without URL or browser-storage bearer tokens.
- [ ] CSRF, logout, cookie flags, refresh, and CORS are tested.
- [ ] Non-development startup fails if required secrets retain defaults or are missing.

### 13.4 Anti-pattern guards

- Do not attempt to sanitize arbitrary PowerShell text. Remove arbitrary text as an API concept.
- Do not use “cmdlet name starts with `Get-`” as the only allowlist; use exact operations and typed parameters.
- Do not move plaintext credentials from Celery into another unprotected message or cache.
- Do not implement HttpOnly cookies without a CSRF model.
- Do not introduce a second encryption library/path when the existing abstraction can be extended.

### 13.5 Copy-ready session brief

```text
Execute Phase 5 of docs/compliance/SOC2_EXECUTION_PLAN.md. Replace generic PowerShell execution with authenticated exact read-only operations, remove credentials from Celery messages, enforce GET-only Graph collection, and complete secure cookie authentication/configuration. Inspect PRs #292, #305, #318, #330, and #350 first. Add adversarial boundary tests and return the standard handoff.
```

## 14. Phase 6 — Reliable scan lifecycle and tenant isolation

**Objective:** Make scan dispatch, task execution, finalization, retry, cancellation, and tenant selection deterministic and recoverable.

**Findings:** REL-01, REL-02, REL-03, REL-04, TEN-01.

**Estimated effort:** 6–10 person-days.

### 14.1 What to implement

1. Define an explicit scan state machine with valid transitions and terminal states.
2. Make scan creation and task dispatch recoverable through a transactional outbox or an equivalently durable dispatcher.
3. Persist dispatch identity/count and reconcile stale pending/running scans.
4. Make result completion idempotent using an atomic pending-to-terminal transition, such as a conditional update with `RETURNING`.
5. Derive or reconcile aggregate counts from result rows instead of trusting unconditional increments.
6. Lock or otherwise serialize finalization before checking for remaining pending results.
7. Add a watchdog/reconciler for orphaned, stalled, or partially dispatched scans.
8. Define deletion/cancellation semantics so active tasks cannot update deleted resources silently.
9. Bind SharePoint URL, tenant identity, and certificate reference to the selected M365 connection.
10. Validate the SharePoint tenant identity against the Graph/Exchange tenant before executing a control.
11. Until tenant identity is provable, mark SharePoint controls indeterminate rather than using a global tenant.
12. Propagate the existing request correlation ID through scan records, Celery headers, collector calls, OPA, and PowerShell.

### 14.2 Documentation and patterns to copy

- Current scan creation: `backend-api/app/api/v1/scans.py`.
- Queue client: `backend-api/app/services/celery_client.py`.
- Task lifecycle: `engine/worker/tasks.py`.
- Database transitions/finalization: `engine/worker/db.py`.
- Celery delivery settings: `engine/worker/celery_app.py`.
- SharePoint runtime limitation: `docs/engine/sharepoint-local-runtime.md`.
- Request correlation: `backend-api/app/core/middleware.py`.

### 14.3 Verification checklist

- [ ] Broker failure after API commit cannot leave an unrecoverable pending scan.
- [ ] A task committed before worker death can be redelivered without changing counters twice.
- [ ] Two last tasks completing concurrently finalize exactly once.
- [ ] Partial dispatch and worker crashes reach a visible terminal/recoverable state.
- [ ] Cancellation/deletion prevents later task mutation or records a safe no-op.
- [ ] A cross-tenant SharePoint configuration is rejected or indeterminate.
- [ ] Concurrency tests run with real PostgreSQL transaction semantics rather than only mocks.
- [ ] Correlation IDs join API, task, collector, OPA, and PowerShell events.

### 14.4 Anti-pattern guards

- Do not solve queue atomicity by merely retrying the HTTP request.
- Do not rely on `SELECT FOR UPDATE` acquired after the decisive pending-count query.
- Do not keep non-idempotent increments with late acknowledgements.
- Do not silently substitute globally configured SharePoint identity.
- Do not optimize collector fan-out until this phase is complete.

### 14.5 Copy-ready session brief

```text
Execute Phase 6 of docs/compliance/SOC2_EXECUTION_PLAN.md. Implement the explicit scan state machine, durable dispatch, idempotent task completion, correct finalization, reconciliation, cancellation semantics, and connection-bound SharePoint tenant validation. Use real concurrent PostgreSQL tests and return the standard handoff.
```

## 15. Phase 7 — Audit-grade evidence and SOC 2 productization

**Objective:** Turn the validated crosswalk and scan results into reproducible, access-controlled SOC 2 evidence without overstating configuration coverage.

**Findings:** AUTH-01, AUTH-02, EVI-01, EVI-02, EVI-03, DOC-02.

**Estimated effort:** 10–16 person-days.

### 15.1 What to implement

1. Add the Appendix A crosswalk as a versioned machine-readable artifact with:
   - SOC criterion and point of focus;
   - human-approved rating;
   - CIS control IDs;
   - resolved policy files;
   - rationale and residual scope;
   - benchmark/mapping version;
   - reviewer, approval date, and mapping digest.
2. Add a validator that proves referenced CIS controls are present, ready, mapped to registered collectors, and backed by the expected policy files without changing ratings.
3. Snapshot the mapping version/digest into each relevant scan/report.
4. Add an API/report projection for SOC 2 that displays:
   - configuration rating;
   - actual scan state;
   - coverage percentage;
   - automated evidence;
   - manual/inherited residual evidence;
   - limitations and provenance.
5. Expand manual verification into an evidence workflow with:
   - control owner and evidence owner;
   - independent reviewer/approver;
   - attachments or external evidence references;
   - collection period and expiry/cadence;
   - immutable revisions and decision history;
   - reviewer comments and rejection reasons;
   - retention/deletion policy;
   - evidence hash and source provenance.
6. Add object-level ownership and authorization to uploaded evidence and generated reports.
7. Replace guessable filenames with tenant-scoped random object IDs.
8. Add size, MIME, page, pixel, archive, parser, OCR, CPU, memory, and timeout limits.
9. Move OCR/report generation to an isolated asynchronous worker and approved object storage.
10. Remove or protect unauthenticated legacy evidence pages and debug-log endpoints.
11. Generate CIS status documentation from `metadata.json` rather than maintaining stale hand-written totals.

### 15.2 Documentation and patterns to copy

- Parent ownership verification: `backend-api/app/api/v1/manual_verification.py`.
- Connection ownership: `backend-api/app/api/v1/m365_connections.py`.
- Current evidence API: `backend-api/app/api/v1/evidence.py`.
- Legacy processor: `security/evidence_ui/app.py`.
- Current manual model: `backend-api/app/models/manual_scan_result_detail.py`.
- Current scan/result models: `backend-api/app/models/compliance.py`, `backend-api/app/models/scan_result.py`.
- Machine-readable control schema: `engine/policies/cis/microsoft-365-foundations/v6.0.0/metadata.json`.
- Manual control templates: `docs/compliance/templates/manual_controls_v6.0.0.json`.

### 15.3 Verification checklist

- [ ] Every Appendix A mapping resolves through the validator.
- [ ] Changing a policy/metadata/mapping file changes the appropriate digest.
- [ ] Historical reports render from their pinned mapping and implementation provenance.
- [ ] A No row remains No for M365 configuration while allowing separate manual/inherited evidence.
- [ ] Only the owner/authorized reviewer can access an evidence object or report.
- [ ] Evidence mutations create immutable history rather than overwriting approval records.
- [ ] Oversized, malformed, mislabeled, decompression-bomb, and long-running files fail safely.
- [ ] OCR/report work does not block the API event loop.
- [ ] Storage retention and deletion behavior is tested and logged.
- [ ] Generated status documentation matches metadata totals.

### 15.4 Anti-pattern guards

- Do not store the crosswalk only in frontend code or prose.
- Do not allow the validator to assign or promote GRC ratings.
- Do not make approved evidence directly editable or deletable without an audit event.
- Do not authorize downloads by filename alone.
- Do not store raw credentials or unrestricted tenant payloads in evidence snapshots.
- Do not claim a governance control is automated because a document was uploaded.

### 15.5 Copy-ready session brief

```text
Execute Phase 7 of docs/compliance/SOC2_EXECUTION_PLAN.md. Productize Appendix A as a versioned human-approved mapping, add structural validation and scan/report pinning, implement immutable manual/inherited evidence workflow, and secure/bound evidence processing and downloads. Preserve rating ownership and return the standard handoff.
```

## 16. Phase 8 — Highest-value coverage expansion

**Objective:** Add technically defensible M365 automation where it strengthens existing Partial areas, while keeping governance residuals explicit.

**Estimated effort:** 18–28 person-days for DLP/labels and drift. Optional control families are estimated separately.

### 16.1 Wave A — Purview DLP and information protection

1. Confirm certificate-based Security & Compliance PowerShell authentication using current Microsoft primary documentation and a non-production licensed tenant.
2. Harden and promote the existing pending collectors:
   - `engine/collectors/_pending/compliance/dlp_compliance_policy.py`;
   - `engine/collectors/_pending/compliance/label_policy.py`.
3. Implement CIS 3.2.1, 3.2.2, and 3.3.1 policies using exact v6 audit procedures.
4. Add semantic tests and mocked/live collector contract tests.
5. Add readiness probes for licensing, permissions, authentication, and returned object shape.
6. Ask GRC to review whether the additional evidence changes the rationale for:
   - CC6.1 Restricts Access to Information Assets;
   - CC6.7 Restricts the Ability to Perform Transmission.
7. Do not assume Partial becomes Yes; endpoint, classification, governance, and DLP-scope residuals may remain.

### 16.2 Wave B — Real configuration drift

1. Define a tenant/benchmark baseline snapshot using the Phase 3 provenance model.
2. Compare normalized collected facts and determinate results across scans.
3. Record added, removed, and changed configuration separately from evaluation-status changes.
4. Create durable drift events with severity, affected controls, previous/current digests, and correlation.
5. Add notification routing with acknowledgement and remediation tracking.
6. Expose drift in the API/report without claiming real-time SIEM correlation.
7. Ask GRC to review the technical support this provides for CC4 and CC7.1 while preserving the supplied Partial rating.

### 16.3 Optional later waves

| Family | Current issue | Estimated effort |
|---|---|---:|
| SharePoint 7.2 controls | Finish connection-bound PnP collection and reconcile open PRs #325, #336, #344, #348 | 10–18 pd |
| Conditional Access 5.2.2 family | Deferred shared-collector policy design, exclusions, normalization, and tests | 10–15 pd |
| Teams 8.x | Current authentication approach is blocked | 3–5 pd spike, then 12–20 pd if viable |
| Fabric 9.1.x | Authentication/licensing path is not validated | 3–5 pd spike, then 8–15 pd if viable |

### 16.4 Documentation and patterns to copy

- Pending collector guidance: `engine/collectors/_pending/README.md`.
- Pending DLP/label collectors listed above.
- PowerShell certificate handling from Phase 5.
- Multi-control collected fact pattern: `engine/collectors/sharepoint/pnp/tenant.py`.
- Manual live-tenant testing: `docs/engine/manual-collector-testing.md`.
- Readiness service: `backend-api/app/services/scan_readiness.py`.

### 16.5 Verification checklist

- [ ] Every new control cites the exact CIS v6 audit procedure and current Microsoft API documentation.
- [ ] License, permission, authentication, missing, partial, and malformed cases are tested.
- [ ] Live validation uses an approved non-production tenant and sanitized evidence.
- [ ] Collectors are read-only by construction.
- [ ] Drift is reproducible from pinned normalized snapshots.
- [ ] Notifications include acknowledgement and do not expose sensitive evidence.
- [ ] Crosswalk rating/rationale changes have a named GRC approver.

### 16.6 Anti-pattern guards

- Do not copy a control implementation from another CIS benchmark version.
- Do not promote `_pending` collectors without authentication, permission, null, and live-tenant validation.
- Do not interpret periodic drift as real-time incident detection.
- Do not map Teams, Fabric, network, endpoint, physical, or organizational coverage without evidence and GRC approval.

### 16.7 Copy-ready session brief

```text
Execute Phase 8 of docs/compliance/SOC2_EXECUTION_PLAN.md, starting with Wave A and then Wave B. Validate current Microsoft documentation and a licensed non-production tenant, promote only defensible read-only collectors, add full semantic/contract/readiness tests, and request GRC review without automatically changing SOC 2 ratings. Return the standard handoff after each wave.
```

## 17. Phase 9 — Performance and maintainability

**Objective:** Reduce tenant API load and scan latency after lifecycle idempotency and tenant isolation are proven.

**Findings:** PERF-01 through PERF-05 and oversized/weakly typed frontend modules.

**Estimated effort:** 8–14 person-days.

### 17.1 What to implement

1. Build an execution plan keyed by `data_collector_id`.
2. Collect each normalized fact set once per scan and fan it out to all applicable OPA policies.
3. Preserve per-control timing, status, provenance, and error isolation even when evidence is shared.
4. Reuse token/client state within the bounded scan context.
5. Add explicit retry behavior for 429, `Retry-After`, transient 5xx, timeouts, and connection resets.
6. Treat pagination caps as explicit truncation/indeterminate errors rather than silently stopping.
7. Move collectors that bypass pagination onto the documented pagination path.
8. Add bounded concurrency to the Settings Catalog per-policy settings requests.
9. Batch compatible PowerShell operations into controlled tenant/module sessions and move blocking execution out of the async request thread.
10. Use the summary endpoint while scans run, fetch/paginate full result evidence when needed, abort overlapping requests, pause on hidden tabs, and add polling backoff.
11. Introduce generated OpenAPI frontend types or an equivalent typed contract and remove broad `Promise<any>` from touched API paths.
12. Split oversized pages only where required to test or maintain the changed behavior.

### 17.2 Documentation and patterns to copy

- Collector metadata relationship: `engine/policies/cis/microsoft-365-foundations/v6.0.0/metadata.json`.
- Graph pagination skeleton: `engine/collectors/graph_client.py`.
- Shared fact collector: `engine/collectors/sharepoint/pnp/tenant.py`.
- Settings Catalog collector: `engine/collectors/entra/devices/configuration_policies.py`.
- Summary endpoint: `backend-api/app/api/v1/scans.py`.
- Current polling: `frontend/src/pages/ScansPage.tsx` and `frontend/src/pages/ScanDetailPage.tsx`.
- Current API client: `frontend/src/api/client.ts`.

### 17.3 Verification checklist

- [ ] A full 69-control scan invokes no more than the expected unique collector executions, subject to documented partitioning.
- [ ] Shared evidence produces independent policy results and provenance.
- [ ] A failed policy does not force unrelated policies sharing a collector to fail.
- [ ] Graph throttling/retry tests honor `Retry-After` and remain bounded.
- [ ] Pagination cannot silently truncate.
- [ ] Settings Catalog concurrency is bounded and measurable.
- [ ] PowerShell session reuse preserves tenant/module isolation.
- [ ] Load tests report Graph calls, PowerShell sessions, scan duration, error rate, and worker memory before/after.
- [ ] Frontend polling transfers summary data while running and does not overlap requests.
- [ ] Touched frontend API code has concrete generated/declared types.

### 17.4 Anti-pattern guards

- Do not use a cross-scan or cross-tenant evidence cache unless isolation, expiry, and provenance are explicitly designed.
- Do not retry authorization, invalid request, or deterministic policy failures.
- Do not add unbounded concurrency.
- Do not batch work before Phase 6 idempotency is verified.
- Do not hide truncation, throttling exhaustion, or partial collection as success.

### 17.5 Copy-ready session brief

```text
Execute Phase 9 of docs/compliance/SOC2_EXECUTION_PLAN.md after Phase 6 is complete. Add collector-once/fan-out execution, pooled throttling-aware Graph behavior, bounded Settings Catalog concurrency, safe PowerShell session batching, summary polling, and typed touched frontend APIs. Capture before/after load measurements and return the standard handoff.
```

## 18. Phase 10 — Production operations and organizational SOC 2 evidence

**Objective:** Implement the operational and governance controls that code and tenant configuration cannot prove alone.

**Estimated effort:** 15–25 engineering/operations person-days plus 25–45 GRC/management person-days. Ongoing operation is required after implementation.

### 18.1 Engineering and operations work

1. Select and document the production deployment platform.
2. Create reviewed IaC for private networking, database, Redis, OPA, PowerShell workers, object storage, secrets, backups, logging, and environment separation.
3. Remove production host publication for PostgreSQL, Redis, OPA, and PowerShell.
4. Emit the metrics currently referenced by alert rules or replace those rules with actual emitted metrics.
5. Add scan/task/control correlation, stuck-scan SLOs, dashboards, alert routing, acknowledgement, and runbooks.
6. Define backup coverage, retention, encryption, restore objectives, and recurring restore tests.
7. Add key rotation for application encryption and secrets.
8. Add dependency/SBOM/container provenance, artifact retention, and release traceability.
9. Define evidence retention, legal hold, secure deletion, customer export, and access logging.
10. Conduct failure, recovery, and security exercises against the production-like environment.

### 18.2 Governance evidence by criterion

| Criterion | Required organizational evidence |
|---|---|
| CC1 | Control owners, governance charter, board/management oversight, code of conduct, HR screening/termination, responsibility matrix, inherited physical-control assessment. |
| CC2 | Security policies, role communication, training, customer/security communications, change and incident notification procedures. |
| CC3 | Scoped risk register, annual and change-triggered risk assessments, fraud risk, risk treatment, acceptance and review evidence. |
| CC4 | Recurring control evaluations, AutoAudit scan cadence, exception/remediation workflow, deficiency escalation and management review. |
| CC5 | Control catalogue, owner, frequency, evidence, reviewer, approval, technology baseline selection and residual-risk rationale. |
| CC6 | Asset inventory, joiner/mover/leaver, access reviews, physical/provider inheritance, data classification, disposal, endpoint/removable-media and encryption evidence. |
| CC7 | Incident response plan, severity model, on-call roles, SIEM/tool-health monitoring, tabletop exercises, incident records, postmortems, recovery tests. |
| CC8 | Required checks, reviews, change tickets, segregation of duties, deployment approvals, rollback, emergency changes and migration evidence. |
| CC9 | BCP/DR, vendor/subprocessor inventory, due diligence, contracts, annual reviews, concentration risk and disruption mitigation. |

### 18.3 Documentation and patterns to copy

- Intended monitoring: `infrastructure/monitoring/alerts/README.md` and alert YAML files.
- Runbooks: `runbooks/RUNBOOKS.md`.
- Current deployment status: `README.md`, `docker-compose.yml`, preview workflows.
- Request correlation: `backend-api/app/core/middleware.py`.
- Evidence workflow implemented in Phase 7.

### 18.4 Verification checklist

- [ ] Production architecture and data flows have security/GRC approval.
- [ ] No internal stateful or execution service is publicly exposed without an approved control.
- [ ] Dashboards use metrics actually emitted by the deployed applications.
- [ ] Alert delivery and acknowledgement are tested.
- [ ] A backup restore succeeds and is documented.
- [ ] Key rotation succeeds without losing evidence access.
- [ ] Incident tabletop and recovery exercises produce approved evidence.
- [ ] Every CC1–CC9 organizational control has an owner, cadence, evidence, reviewer, and retention rule.
- [ ] Vendor and inherited controls identify the source report/contract and validity period.
- [ ] Public SOC 2 wording matches actual audit status.

### 18.5 Anti-pattern guards

- Do not treat conceptual monitoring YAML as proof that monitoring operates.
- Do not treat a written policy as operating evidence without execution records.
- Do not claim Microsoft inherited controls without reviewing the applicable provider report and responsibility boundary.
- Do not conflate backup existence with a tested restore.
- Do not claim certification before an independent report exists and approved wording is supplied.

### 18.6 Copy-ready session brief

```text
Execute Phase 10 of docs/compliance/SOC2_EXECUTION_PLAN.md with the infrastructure, security, and GRC owners. Implement production IaC/observability/backups/evidence retention and build the CC1–CC9 organizational evidence register. Validate operating evidence rather than documents alone, preserve inherited-control boundaries, and return the standard handoff.
```

## 19. Phase 11 — Final verification and audit-readiness release

**Objective:** Prove that the selected program scope works together and generate an evidence-backed release decision.

**Estimated effort:** 2–4 person-days plus GRC review and live-tenant coordination.

### 19.1 What to verify

1. Re-read Phase 0 sources and confirm implementation still matches documented APIs.
2. Re-run Git/PR/branch-protection inventory.
3. Verify the mapping validator against Appendix A and Appendix B.
4. Run all repository gates from a clean checkout.
5. Build and start all production-target container images with non-development configuration.
6. Run migrations from clean and supported prior database states.
7. Execute a full approved non-production M365 scan with Graph, Exchange, SharePoint, Defender/Purview as licensed.
8. Exercise pass, fail, indeterminate, error, skipped, and not-assessable behavior.
9. Verify a complete scan can be reproduced from stored provenance.
10. Exercise broker failure, task redelivery, concurrent finalization, cancellation, tenant mismatch, throttling, and PowerShell rejection cases.
11. Verify evidence ownership, approval, retention, expiry, deletion, and report access.
12. Generate a SOC 2 evidence pack and have GRC trace a sample from report → mapping → result → policy → collector → normalized evidence → source/provenance.
13. Run secret, dependency, SAST, container, SBOM, and IaC scans.
14. Review public documentation and claims against actual status.

### 19.2 Expected commands

Adjust environment setup to the repository's approved lockfiles and pinned tool versions.

```bash
git status --short --branch

cd engine
PYTHONDONTWRITEBYTECODE=1 .venv/bin/pytest -p no:cacheprovider -q
opa check --strict policies/cis/microsoft-365-foundations/v6.0.0
opa test policies tests

cd ../backend-api
uv run alembic heads
uv run alembic upgrade head
uv run pytest

cd ../frontend
npm ci
npm run lint
npx tsc --noEmit
npm test
npm run build
```

Also run the approved container, security, migration-path, integration, concurrency, and end-to-end commands introduced by earlier phases.

### 19.3 Release acceptance criteria

- [ ] Worktree and generated artifacts are controlled and reproducible.
- [ ] All required checks are enforced and green.
- [ ] Exactly one Alembic head exists.
- [ ] Strict OPA check and every policy test pass.
- [ ] Every Appendix B policy has semantic and collector contract coverage.
- [ ] No known credential, generic PowerShell execution, default admin, plaintext token log, or broker-secret serialization remains.
- [ ] Unknown/error results cannot appear as pass or ordinary noncompliance.
- [ ] Compliance and coverage are both displayed.
- [ ] Scan lifecycle failure and redelivery tests pass.
- [ ] Cross-tenant SharePoint execution is impossible.
- [ ] Evidence is owner-authorized, immutable after approval, retained, and reproducible.
- [ ] GRC approves the crosswalk version, limitations, and public wording.
- [ ] Remaining risks have named owners, due dates, and documented acceptance.

### 19.4 Anti-pattern guards

- Do not waive failed evidence-integrity tests to meet a release date.
- Do not use only mocked integrations for the final tenant validation.
- Do not mark the program complete with an unowned accepted risk.
- Do not describe technical readiness as a completed SOC 2 examination.

### 19.5 Copy-ready session brief

```text
Execute Phase 11 of docs/compliance/SOC2_EXECUTION_PLAN.md only after every selected prerequisite phase has a complete handoff. Re-run all clean-checkout, migration, policy, backend, frontend, container, security, concurrency, tenant, evidence, and traceability checks. Produce an evidence-backed release decision and risk register; do not implement unrelated fixes during final verification.
```

## 20. Timeline and staffing

| Milestone | Included phases | Person-days | Expected elapsed time |
|---|---|---:|---:|
| Immediate containment | 0–2 | 8–13 | 1–2 weeks with two engineers and GRC support |
| Evidence-correct core | 3–6 | 24–38 | Additional 3–5 weeks with two to three engineers |
| SOC 2 evidence product | 7 | 10–16 | Additional 2–3 weeks |
| DLP and drift wave | 8A–8B | 18–28 | Additional 3–5 weeks; can partially overlap Phase 9 |
| Performance/maintainability | 9 | 8–14 | 2–3 weeks, partially parallel after Phase 6 |
| Production operations | 10 | 15–25 engineering plus 25–45 GRC/operations | Depends on cloud platform and evidence cadence |
| Final verification | 11 | 2–4 | 1 week |

Recommended staffing:

- one backend/security engineer;
- one engine/policy/collector engineer;
- one frontend/platform engineer;
- a part-time GRC control owner/reviewer throughout;
- identity and infrastructure owners on Phases 1, 5, 8, and 10.

The critical path is Phase 0 → Phase 1/2 → Phase 3 → Phase 4 → Phase 5 → Phase 6 → Phase 7 → Phase 11. Do not put Phase 9 performance changes ahead of Phase 6 reliability.

## Appendix A — Authoritative SOC 2 → CIS M365 v6 crosswalk

These ratings are the supplied ground truth. The table is intentionally explicit so future sessions do not infer or invent mappings.

### A.1 CC6 — Logical and physical access

| Criterion | Point of focus | Rating | CIS evidence | Residual limitation |
|---|---|---|---|---|
| CC6.1 | Identifies and Manages the Inventory of Information Assets | No | None | Organization-level asset register. |
| CC6.1 | Restricts Logical Access | Yes | 5.2.3.4, 5.2.2.3, 5.3.1, 1.1.3 | Technical evidence still depends on reliable policy execution. |
| CC6.1 | Identifies and Authenticates Users | Yes | 5.2.3.4, 5.2.3.5, 5.2.3.6, 1.3.1 | Technical evidence still depends on reliable policy execution. |
| CC6.1 | Considers Network Segmentation | No | None | Not an M365 tenant setting. |
| CC6.1 | Manages Points of Access | Yes | 5.1.6.1, 5.1.6.2, 5.1.6.3, 1.2.1 | 5.1.6.1 requires technical revalidation. |
| CC6.1 | Restricts Access to Information Assets | Partial | 6.1.1, 6.1.2, 6.2.1 | Data classification and DLP are not currently automated. |
| CC6.2 | Controls Access Credentials to Protected Assets | Yes | 5.2.3.2, 5.2.3.3, 5.2.3.7, 1.3.1 | Technical evidence still depends on reliable policy execution. |
| CC6.2 | Removes Access to Protected Assets When Appropriate | Yes | 5.3.2, 5.3.3 | Organizational offboarding evidence remains separate. |
| CC6.3 | Creates or Modifies Access to Protected Information Assets | Yes | 5.3.1, 5.3.4, 5.3.5, 1.1.3 | Organizational authorization/change evidence remains separate. |
| CC6.3 | Removes Access to Protected Assets | Yes | 5.3.2, 5.3.3 | Organizational offboarding evidence remains separate. |
| CC6.3 | Uses Role-Based Access Controls | Yes | 1.1.1, 1.1.3, 1.1.4, 5.3.1 | Empty-evidence behavior must be corrected. |
| CC6.4 | Restricts Physical Access | No | None | Physical/provider inherited control. |
| CC6.4 | Protects and Monitors the Physical Infrastructure | No | None | Physical/provider inherited control. |
| CC6.5 | Identifies Data Requiring Disposal | No | None | Policy/process activity. |
| CC6.5 | Destroys and Disposes of Data and Assets in Accordance with Policy | No | None | Manual or retention-policy-driven process. |
| CC6.6 | Restricts Access | Partial | 2.1.1, 2.1.4, 6.2.3 | Email boundary only, not the full network boundary. |
| CC6.6 | Protects Identification and Authentication Credentials | Yes | 5.2.2.3, 5.2.3.5, 5.2.3.1 | Technical evidence still depends on reliable policy execution. |
| CC6.6 | Requires Additional Authentication or Credentials | Yes | 5.2.3.4, 5.2.3.6 | Technical evidence still depends on reliable policy execution. |
| CC6.6 | Implements Boundary Protection Systems | Partial | 2.1.7, 2.1.1, 2.1.4 | Firewalls and IDS are outside M365 tenant scope. |
| CC6.7 | Restricts the Ability to Perform Transmission | Partial | 6.2.1, 6.2.2, 6.5.5 | Full DLP is not currently automated. |
| CC6.7 | Uses Encryption Technologies or Secure Communication Channels | Partial | 6.5.1, 6.5.4 | Message encryption is not directly checked. |
| CC6.7 | Protects Removable Media | No | None | Endpoint/Intune scope, not current M365 tenant configuration. |
| CC6.8 | Restricts Installation of Unauthorized Software | Partial | 5.1.5.1, 5.1.2.2, 1.3.4, 4.2 | Covers the M365 application/device-enrollment angle only. |
| CC6.8 | Detects Unauthorized Software | Partial | 2.1.4, 2.1.11 | Malicious attachment detection, not general software inventory. |
| CC6.8 | Uses a Defined Change Control Process | No | None | Organizational CC8 process. |

### A.2 CC7 — System operations

| Criterion | Point of focus | Rating | CIS evidence | Residual limitation |
|---|---|---|---|---|
| CC7.1 | Uses Defined Configuration Standards | Yes | All automated CIS M365 v6 controls | Current repository has 69 ready controls; preserve version/provenance. |
| CC7.1 | Monitors Infrastructure and Software | Partial | 6.1.1, 6.1.2, 6.1.3 | M365-scoped; not wider CSPM monitoring. |
| CC7.1 | Implements Change-Detection Mechanisms | Partial | 6.1.1, 6.1.2, 6.1.3 | Audit logging is after-the-fact, not real-time drift detection. |
| CC7.1 | Detects Unknown or Unauthorized Components | Partial | 5.1.2.2, 1.3.4, 5.1.5.2 | Endpoint asset discovery is outside scope. |
| CC7.1 | Conducts Vulnerability Scans | No | None | Configuration compliance is not CVE vulnerability scanning. |
| CC7.2 | Implements Detection Policies, Procedures, and Tools | Yes | 2.1.1, 2.1.2, 2.1.4, 2.1.5, 2.1.7, 2.1.11 | CIS 2.1.5 must be corrected before reliance. |
| CC7.2 | Designs Detection Measures | Yes | 2.1.3, 2.1.6, 2.1.7 | Organizational alert response remains separate. |
| CC7.2 | Implements Filters to Analyze Anomalies | Partial | 2.1.2, 2.1.11, 5.2.3.1 | Full SIEM correlation is outside tenant configuration. |
| CC7.2 | Monitors Detection Tools for Effective Operation | Partial | 6.1.1, 2.1.6 | Tool-health meta-monitoring is a process. |
| CC7.3 | Responds to Security Incidents | Partial | 2.4.4 | CIS 2.4.4 must be corrected; human incident evaluation remains a process. |
| CC7.3 | Communicates and Reviews Detected Security Events | Partial | 2.1.3, 2.1.6 | Review is a human process. |
| CC7.3 | Develops and Implements Procedures to Analyze Security Incidents | No | None | Organizational incident-response procedure. |
| CC7.3 | Assesses the Effectiveness of Incident Response | No | None | Management review activity. |
| CC7.4 | Assigns Roles and Responsibilities | No | None | Organizational role assignment. |
| CC7.4 | Contains Security Incidents | Partial | 2.4.4 | ZAP covers a narrow delivered-item threat; 2.4.4 must be corrected. |
| CC7.4 | Mitigates Ongoing Security Incidents | No | None | Live incident mitigation process. |
| CC7.4 | Ends Threats Posed by Security Incidents | Partial | 2.4.4 | Narrow ZAP evidence only; 2.4.4 must be corrected. |
| CC7.4 | Restores Affected Systems | No | None | Recovery and backup process. |
| CC7.4 | Communicates About Security Incidents | No | None | Organizational communication process. |
| CC7.5 | Restores the Affected Environment | No | None | Recovery and backup process. |
| CC7.5 | Communicates Information About the Event | No | None | Organizational communication process. |
| CC7.5 | Evaluates the Effectiveness of Incident Response | No | None | Post-incident management review. |

### A.3 CC1–CC9 summary

| Criterion | Configuration coverage classification |
|---|---|
| CC1 | Governance only |
| CC2 | Governance only |
| CC3 | Governance only |
| CC4 | Governance; AutoAudit supports monitoring evidence |
| CC5 | Mostly governance with a technology-control pocket |
| CC6 | Strong automated overlap; fully mapped above |
| CC7 | Strong monitoring/detection overlap; fully mapped above |
| CC8 | Partial M365 pocket; broader change management is organizational |
| CC9 | Governance only |

## Appendix B — Crosswalk control resolution at the baseline

The policy filename and collector ID are factual repository evidence. A Phase 7 validator must resolve these from metadata and fail when they drift unexpectedly.

| CIS control | Policy file | Collector ID |
|---|---|---|
| 1.1.1 | `1.1.1_admin_cloud_only.rego` | `entra.roles.cloud_only_admins` |
| 1.1.3 | `1.1.3_global_admin_count.rego` | `entra.roles.privileged_roles` |
| 1.1.4 | `1.1.4_admin_license_footprint.rego` | `entra.roles.admin_license_footprint` |
| 1.2.1 | `1.2.1_no_unmanaged_public_groups.rego` | `entra.groups.groups` |
| 1.3.1 | `1.3.1_password_expiration.rego` | `entra.domains.password_policy` |
| 1.3.4 | `1.3.4_user_owned_apps_restricted.rego` | `entra.applications.apps_and_services_settings` |
| 2.1.1 | `2.1.1_SafeLinks_OfficeApplications_Enabled.rego` | `exchange.protection.safe_links_policy` |
| 2.1.2 | `2.1.2_Common_AttachmentTypes_Filter_Enabled.rego` | `exchange.protection.malware_filter_policy` |
| 2.1.3 | `2.1.3_Notifications_InternalUsers_sendingMalware_Enabled.rego` | `exchange.protection.malware_filter_policy` |
| 2.1.4 | `2.1.4_Safe_AttachementsPolicy_Enabled.rego` | `exchange.protection.safe_attachment_policy` |
| 2.1.5 | `2.1.5_Safe_Attachments_SharePoint_OneDrive_MSTeams_Enabled.rego` | `exchange.protection.atp_policy_o365` |
| 2.1.6 | `2.1.6_Exchange_OnlineSpam_Policies_Notify_Administrators.rego` | `exchange.protection.hosted_outbound_spam_filter` |
| 2.1.7 | `2.1.7_AntiPhishing_Policy_is_created.rego` | `exchange.protection.anti_phish_policy` |
| 2.1.11 | `2.1.11_Comprehensive_Attachment_Filtering_Applied.rego` | `exchange.protection.malware_filter_policy` |
| 2.4.4 | `2.4.4_Zero_hour_AutoPurge_MSTeams_is_On.rego` | `exchange.protection.teams_protection_policy` |
| 4.2 | `4.2_block_personal_device_enrollment.rego` | `entra.devices.enrollment_restrictions` |
| 5.1.2.2 | `5.1.2.2_block_third_party_integrated_apps.rego` | `entra.policies.authorization_policy` |
| 5.1.5.1 | `5.1.5.1_block_user_app_consent.rego` | `entra.policies.authorization_policy` |
| 5.1.5.2 | `5.1.5.2_admin_consent_workflow_enabled.rego` | `entra.policies.admin_consent_request_policy` |
| 5.1.6.1 | `5.1.6.1_restrict_collaboration_invite_domains.rego` | `entra.policies.b2b_policy` |
| 5.1.6.2 | `5.1.6.2_restrict_guest_user_access.rego` | `entra.policies.authorization_policy` |
| 5.1.6.3 | `5.1.6.3_limit_guest_invitations.rego` | `entra.policies.authorization_policy` |
| 5.2.2.3 | `5.2.2.3_block_legacy_auth.rego` | `entra.conditional_access.legacy_auth_block` |
| 5.2.3.1 | `5.2.3.1_mfa_fatigue_protection.rego` | `entra.authentication.mfa_fatigue_protection` |
| 5.2.3.2 | `5.2.3.2_custom_banned_passwords_enabled.rego` | `entra.authentication.password_protection` |
| 5.2.3.3 | `5.2.3.3_enable_on_prem_password_protection.rego` | `entra.authentication.password_protection` |
| 5.2.3.4 | `5.2.3.4_all_members_mfa_capable.rego` | `entra.authentication.mfa_registration_report` |
| 5.2.3.5 | `5.2.3.5_disable_weak_auth_methods.rego` | `entra.authentication.authentication_methods` |
| 5.2.3.6 | `5.2.3.6_enable_system_preferred_mfa.rego` | `entra.authentication.authentication_methods` |
| 5.2.3.7 | `5.2.3.7_disable_email_otp.rego` | `entra.authentication.authentication_methods` |
| 5.3.1 | `5.3.1_pim_enabled.rego` | `entra.governance.pim_role_policies` |
| 5.3.2 | `5.3.2_guest_access_reviews_configured.rego` | `entra.governance.access_reviews` |
| 5.3.3 | `5.3.3_privileged_role_access_reviews_configured.rego` | `entra.governance.access_reviews` |
| 5.3.4 | `5.3.4_ga_activation_requires_approval.rego` | `entra.governance.pim_role_policies` |
| 5.3.5 | `5.3.5_pra_activation_requires_approval.rego` | `entra.governance.pim_role_policies` |
| 6.1.1 | `6.1.1_audit_disabled.rego` | `exchange.organization.organization_config` |
| 6.1.2 | `6.1.2_mailbox_audit_actions.rego` | `exchange.mailbox.mailbox_audit_actions` |
| 6.1.3 | `6.1.3_audit_bypass.rego` | `exchange.mailbox.mailbox_audit` |
| 6.2.1 | `6.2.1_mail_forwarding_blocked.rego` | `exchange.transport.transport_rules` |
| 6.2.2 | `6.2.2_transport_whitelist.rego` | `exchange.transport.transport_rules` |
| 6.2.3 | `6.2.3_external_sender_tagging.rego` | `exchange.transport.external_in_outlook` |
| 6.5.1 | `6.5.1_modern_auth.rego` | `exchange.organization.organization_config` |
| 6.5.4 | `6.5.4_smtp_auth.rego` | `exchange.organization.transport_config` |
| 6.5.5 | `6.5.5_direct_send.rego` | `exchange.organization.organization_config` |

## Appendix C — Plan completion tracker

Update this table through reviewed plan-maintenance PRs as phases complete.

| Phase | Status | Branch/PR | Findings closed | Completed date | Handoff location |
|---|---|---|---|---|---|
| 0 | Planned |  |  |  |  |
| 1 | Planned |  |  |  |  |
| 2 | Planned |  |  |  |  |
| 3 | Planned |  |  |  |  |
| 4 | Planned |  |  |  |  |
| 5 | Planned |  |  |  |  |
| 6 | Planned |  |  |  |  |
| 7 | Planned |  |  |  |  |
| 8 | Planned |  |  |  |  |
| 9 | Planned |  |  |  |  |
| 10 | Planned |  |  |  |  |
| 11 | Planned |  |  |  |  |
