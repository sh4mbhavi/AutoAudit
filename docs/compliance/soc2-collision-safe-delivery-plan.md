# AutoAudit SOC 2 Collision-Safe Delivery Plan

- **Plan date:** 2026-09-05
- **Repository baseline:** `be241f52beb5ffec10904771bf7cfa4b98233ab0` (`main` / `upstream/main`, merged through PR #303)
- **Board source:** AutoAudit Project Board snapshot exported 2026-09-05
- **Plan owner:** Sham Polavarapu
- **Status:** Planning and coordination; this document does not create, reassign, or close tickets

## 1. Purpose

This plan coordinates the SOC 2-to-CIS Microsoft 365 work with the tickets and pull requests already owned by other contributors. Its goals are to:

1. complete the authoritative SOC 2 mapping without changing human-owned GRC judgments;
2. route audit findings into existing tickets wherever possible;
3. prevent multiple contributors from editing the same controls or shared files independently;
4. identify genuinely unclaimed implementation gaps;
5. define the order, acceptance criteria, verification and estimated effort for delivery.

The supplied SOC 2 crosswalk remains authoritative for all `Yes`, `Partial`, and `No` judgments. New collectors or policies may improve technical evidence, but they do not change a rating until a human GRC reviewer approves the change.

## 2. Executive summary

The current crosswalk is structurally valid: all 44 unique CIS controls referenced by CC6 and CC7 resolve to a ready metadata record, registered collector, and real Rego policy. The repository now contains 69 ready CIS M365 v6 controls rather than the older stated figure of 61.

Most of the broader improvement programme is already owned. Existing tickets cover the crosswalk, evidence definitions, result messaging, policy-test enablement, backend tests, RBAC, secrets, authentication cookies, CORS, metrics, SCA, multi-client collection and numerous individual CIS controls. Those areas must be handled by coordination or by adding acceptance criteria to the existing cards, not by opening parallel work.

The likely net-new work is limited to confirmed residual gaps such as policy evidence-correctness defects, reliable scan orchestration, an audit-grade result/provenance model, collector permission/readiness reconciliation, residual PowerShell hardening, evidence-artifact isolation, DLP automation and scan-to-scan drift detection.

## 3. Current factual baseline

### 3.1 CIS M365 v6 implementation status

| Status | Controls |
|---|---:|
| Ready / automated | 69 |
| Blocked | 31 |
| Deferred | 12 |
| Manual | 11 |
| Not started | 17 |
| **Total** | **140** |

Source: [`metadata.json`](../../engine/policies/cis/microsoft-365-foundations/v6.0.0/metadata.json).

### 3.2 Supplied SOC 2 CC6/CC7 coverage

| Criterion | Yes | Partial | No | Total |
|---|---:|---:|---:|---:|
| CC6 | 10 | 7 | 8 | 25 |
| CC7 | 3 | 9 | 10 | 22 |
| **Combined** | **13** | **16** | **18** | **47** |

The `No` rows for physical security, organization-wide asset inventory, disposal, removable media, vulnerability scanning, incident-response governance and recovery remain `No` within the fixed M365 configuration scope. They require organizational, manual, or inherited evidence rather than artificial CIS mappings.

## 4. Phase 0 — Documentation and ownership discovery

### Status

Completed for planning. Repeat the live-board and open-PR check immediately before creating or claiming implementation work because this document is a dated snapshot.

### Authoritative sources

- User-supplied SOC 2-to-CIS M365 v6 crosswalk.
- AutoAudit Project Board snapshot dated 2026-09-05.
- Current control inventory in [`metadata.json`](../../engine/policies/cis/microsoft-365-foundations/v6.0.0/metadata.json).
- Collector contract in [`engine/collectors/README.md`](../../engine/collectors/README.md).
- Registered collector surface in [`registry.py`](../../engine/collectors/registry.py).
- Policy structure in [`engine/policies/README.md`](../../engine/policies/README.md).
- Structural verification patterns in [`test_wiring.py`](../../engine/tests/test_wiring.py).
- CIS source material in [`CIS_M365_Benchmarks.json`](../engine/Framework/CIS_M365_Benchmarks.json).

### Allowed implementation surfaces

- Use existing registered collectors or extend them through the documented registry contract.
- Use versioned Rego packages and the current policy result shape; extend the result model only through an approved, tested contract.
- Use Graph read operations and exact, approved read-only PowerShell operations required by registered collectors.
- Reuse existing ownership, encryption, request-correlation and Rego-test patterns before creating new abstractions.
- Treat the board ticket and linked PR as the ownership source before editing shared files.

### Anti-pattern guards

- Do not invent CIS controls, mappings, Graph endpoints, permissions or policy files.
- Do not promote an organizational or physical SOC 2 gap to automated coverage.
- Do not flatten unavailable or malformed evidence into either `pass` or normal tenant `fail`.
- Do not expose a generic caller-controlled PowerShell cmdlet interface.
- Do not edit `metadata.json` or `registry.py` concurrently without one nominated integrator.
- Do not modify the v6 mapping as part of v7 analysis.

## 5. Sham Polavarapu delivery sequence

The critical path is:

`SP-006 -> SP-002 -> SP-003 -> SP-005 -> SP-007`

SP-004 may begin after the factual portion of SP-006 is stable. SP-009 remains blocked until Viet's v6-to-v7 transition work is accepted.

| Order | Ticket | Updated scope | Dependencies | Acceptance criteria | Remaining effort |
|---:|---|---|---|---|---:|
| 1 | **26T2-GRC-SP-006 — SOC 2 control-level crosswalk** | Reconcile the 61-to-69 policy-count change; preserve the supplied CC6/CC7 judgments; add CC1-CC9 summary, provenance and technical reliability caveats. | Viet VHT-001/002/003; Alisha AP-001 for public terminology. | Every point has rating, exact CIS IDs/files, rationale, scope limitation, source/version and separate factual-versus-GRC fields. | 2–4 days |
| 2 | **26T2-GRC-SP-002 — CIS automation-gap audit** | Classify all relevant gaps as automatable now, permission/API-blocked, manual, organizational, physical or out of scope. | SP-006; evidence framework; named collector owners; Emma EG-005. | Each candidate has SOC 2 benefit, required permissions, reusable collector opportunity, policy/test work, dependency, owner, priority and estimate. | 3–5 days |
| 3 | **26T2-GRC-SP-003 — Control-owner tracker** | Convert the prioritised inventory into a confirmed DRI/reviewer/dependency register. | SP-002 and owner confirmations. | One DRI and reviewer per item; owned paths, deliverables, dependencies and status recorded; unconfirmed ownership remains visibly unassigned. | 2–3 days |
| 4 | **26T2-GRC-SP-005 — Engine collaboration and delivery** | Route implementation to existing owners and coordinate shared-file integration and review. | SP-002/003; Jiuqi EL-002; Emma EG-005; collector owners. | Collector, metadata, Rego and tests remain paired; one shared-file integrator is named; error/unknown evidence is not recorded as tenant failure. | 2–4 days of GRC coordination |
| 5 | **26T2-GRC-SP-004 — Remediation-note backfill** | Produce sourced, read-only and version-labelled remediation guidance. | SP-006; Viet VHT-003; Alisha AP-001/AP-002. | Prerequisites, licensing, permissions and portal/PowerShell methods are clear; AutoAudit is explicitly read-only; unsupported guidance is not invented. | 3–5 days |
| 6 | **26T2-GRC-SP-007 — Lead onboarding guide** | Document the ownership and delivery workflow that is proven through SP-005. | SP-003/004/005; Viet, Alisha and Jiuqi outputs. | A contributor can identify ownership, reuse a collector, record permissions, add metadata/Rego/tests and request review without production credentials. | 2–4 days |
| 7 | **26T2-GRC-SP-009 — v7 gap analysis** | Limit scope to residual v7 automation and SOC 2 impacts after the factual transition mapping is approved. | Hard dependency on Viet VHT-004; reconcile with completed SP-008. | Added, removed, renumbered and changed controls are identified without modifying the v6 crosswalk or v6 policy directory. | 4–7 days |

**Estimated remaining Sham effort:** 18–32 person-days, or approximately 4–7 working weeks excluding individual collector implementation and external-owner delays.

## 6. Existing ownership — do not duplicate

| Work area | Existing owner and ticket | Required action |
|---|---|---|
| SOC 2 crosswalk and automation-gap coordination | Sham — SP-006, SP-002, SP-003, SP-004, SP-005 | Add findings to these tickets; do not open another crosswalk or generic gap ticket. |
| Evidence classification, collection and validation | Viet — VHT-001, VHT-002, VHT-003 | Treat these artifacts as the evidence-model input; do not design a competing framework. |
| Result messaging and data handling | Alisha — AP-001, AP-002 | Agree terminology and data constraints before changing API/UI behavior. |
| Policy implementation and test enablement | Jiuqi — EL-002 | Route OPA CI and semantic-test conventions through this ticket. |
| Backend test bootstrap and coverage | Peibing — PG-002, PG-003 | Supply missing audit cases as acceptance criteria rather than building another suite. |
| Scan and M365 connection RBAC | Peibing — PG-001 | Confirm whether evidence/report read, download and delete authorization is included. |
| Compose secrets and secret scanning | Raaid — RR-002, RR-003 | Reconcile scope with Irusha's overlapping hardcoded-secrets ticket. |
| Password-reset flow and plaintext token logging | Joshua — JN-002 | Do not implement a separate logging fix. |
| Secure HttpOnly authentication | Pratiyush — PK-001 | Review and merge the existing implementation with CSRF/CORS tests. |
| Secure CORS | Heet — HG-002 | Do not add a parallel CORS implementation. |
| Prometheus metrics | Pratiyush — PK-002 | Assess dashboards, alerts and SLOs only after the endpoint lands. |
| SCA improvements | Shival — SC-004, SC-005, SC-006 | Feed scanner-gating requirements into these tickets. |
| Multi-client collector support | Emma — EG-005 | Confirm the client lifecycle and tenant-isolation boundaries before worker/collector changes. |
| Frontend unit testing | DHR — DEV-DHR-004 | Route current Vitest failures to this review rather than creating a new frontend-test ticket. |
| Security baseline audit | Raaid — RR-001 | Reconcile PowerShell, default-admin and evidence-endpoint findings before new remediation work. |

Existing control ownership includes `1.2.2`, `1.3.3`, `1.3.6`, `1.3.9`, `2.4.1`, `2.4.2`, `5.1.4.2`–`5.1.4.4`, `7.2.3`–`7.2.5`, `7.2.9`, and `7.2.11`. Do not edit those controls without an owner handoff.

## 7. Open pull-request collision check

The following open PRs already cover important parts of the programme and must be reviewed before residual work is planned:

| PR | Area | Related board ownership |
|---|---|---|
| [#292](https://github.com/Hardhat-Enterprises/AutoAudit/pull/292) | Scan and M365 mutation RBAC | Peibing PG-001 |
| [#305](https://github.com/Hardhat-Enterprises/AutoAudit/pull/305) | Secure CORS | Heet HG-002 |
| [#318](https://github.com/Hardhat-Enterprises/AutoAudit/pull/318) | Security headers | Confirm against Raaid's security baseline |
| [#326](https://github.com/Hardhat-Enterprises/AutoAudit/pull/326) | Grype severity enforcement | Shival SCA stream |
| [#330](https://github.com/Hardhat-Enterprises/AutoAudit/pull/330) | Docker Compose secrets | Raaid RR-002 |
| [#331](https://github.com/Hardhat-Enterprises/AutoAudit/pull/331) | Full-history gitleaks | Raaid RR-003 |
| [#350](https://github.com/Hardhat-Enterprises/AutoAudit/pull/350) | Authentication / HttpOnly cookies | Pratiyush PK-001 |
| [#351](https://github.com/Hardhat-Enterprises/AutoAudit/pull/351) | Multi-client collector support | Emma EG-005 |
| [#352](https://github.com/Hardhat-Enterprises/AutoAudit/pull/352) | Alembic-head merge | Existing implementation; ensure it is represented on the board rather than recreating it |
| [#355](https://github.com/Hardhat-Enterprises/AutoAudit/pull/355) | Backend tests and coverage gate | Peibing PG-003 |

Open PRs are proposed work and do not count as current SOC 2 coverage until reviewed, merged and verified on `main`.

## 8. Candidate residual work packages

These are not authorisations to create tickets. Confirm scope through SP-005 and the named adjacent owners first.

### 8.1 P0 — v6 SOC 2 evidence-correctness hotfix

**Likely status:** Unclaimed implementation; coordinate with Jiuqi EL-002.

**Estimate:** 3–5 person-days.

#### What to implement

- Fix the fail-open behavior in [`2.1.5`](../../engine/policies/cis/microsoft-365-foundations/v6.0.0/2.1.5_Safe_Attachments_SharePoint_OneDrive_MSTeams_Enabled.rego).
- Remove the conflicting false/null results in [`2.4.4`](../../engine/policies/cis/microsoft-365-foundations/v6.0.0/2.4.4_Zero_hour_AutoPurge_MSTeams_is_On.rego).
- Prevent missing or empty essential data from passing `1.1.1`, `1.1.4`, and `1.3.1`.
- Obtain a product/GRC decision for a legitimate zero-mailbox result in `6.1.2`.
- Copy the table-driven test pattern from [`test_cis_1_2_2_shared_mailbox_signin.rego`](../../engine/tests/test_cis_1_2_2_shared_mailbox_signin.rego).

#### Verification

- Test secure, insecure, empty, missing, malformed and collector-error inputs.
- Run `opa check`, `opa check --strict`, and `opa test`.
- Confirm no missing evidence returns `compliant: true`.

#### Guardrails

- Do not change SOC 2 ratings as part of the code fix.
- Do not modify Jiuqi's CI/test harness without an explicit handoff.

### 8.2 P0/P1 — scan orchestration correctness

**Likely status:** Residual scope; confirm with Emma EG-005 and Peibing PG-001/003.

**Estimate:** 5–8 person-days.

#### What to implement

- Make scan creation and task enqueueing recoverable through an outbox or reconciliation mechanism.
- Make result transitions idempotent under Celery redelivery.
- Fix finalization so concurrent last tasks cannot leave a scan permanently running.
- Reject invalid/empty effective control selections and return `not_assessed`, not 100%.
- Keep multi-client safety distinct from the explicitly out-of-scope multi-tenant architecture.

#### Verification

- Broker-failure test after database commit.
- Duplicate-task and worker-loss redelivery tests.
- Concurrent final-control test.
- Invalid and empty selection API tests.

#### Guardrails

- Do not change shared client behavior covered by Emma's PR until its integration seam is agreed.
- Do not place decrypted credentials in additional task messages.

### 8.3 P1 — audit-grade result and provenance model

**Likely status:** Runtime implementation unclaimed; semantics already owned by Viet and Alisha.

**Estimate:** 9–15 person-days.

#### What to implement

- Add distinct `passed`, `failed`, `unknown`, `error`, `skipped`, and `not_assessable` outcomes after GRC approval.
- Publish compliance percentage and evidence-coverage percentage separately.
- Persist collector ID, evidence timestamp and digest, policy digest, source commit/image, benchmark snapshot and OPA version.
- Preserve an immutable history or append-only audit event when results or manual evidence change.
- Extend existing ownership checks for every evidence/report operation.

#### Verification

- Migration and backwards-compatibility tests.
- API/schema tests for every result state.
- Provenance verification reproduces the policy and metadata snapshot used for a historical scan.
- Cross-user evidence/report access is rejected.

#### Guardrails

- Do not create a competing evidence taxonomy.
- Do not store unrestricted raw tenant data where a digest or redacted snapshot is sufficient.
- Do not treat hashing alone as complete provenance.

### 8.4 P1 — collector, permission and readiness contract hardening

**Likely status:** Unclaimed implementation; coordinate through SP-005 and Jiuqi.

**Estimate:** 6–10 person-days.

#### What to implement

- Revalidate CIS `5.1.6.1` against the licensed CIS procedure and correct Microsoft setting/API.
- Reconcile metadata/Rego permission mismatches and service annotations.
- Add readiness probes or explicit unsupported-probe classifications.
- Add mocked collector contract tests for `None`, empty, singleton, list, malformed and API-error responses.

#### Verification

- Metadata, policy annotations and tested runtime permissions agree.
- A readiness warning is not represented as proof that evidence can be collected.
- Collector outputs match the Rego input contract for each tested shape.

#### Guardrails

- Do not assume which permission source is correct without current Microsoft documentation and tenant validation.
- Do not retain heuristic compliance under a misleading control title.

### 8.5 P1 — residual security boundaries

**Likely status:** Confirm with Raaid, Peibing, Pratiyush, Kunal and the evidence/report owners.

**Estimate:** 7–12 person-days if absent from their scopes.

#### What to implement

- Replace generic PowerShell cmdlet execution with fixed operation identifiers, typed parameters, service authentication and private networking.
- Pass scan/connection identifiers through Celery rather than decrypted tenant secrets.
- Make default-admin bootstrap explicitly development-only.
- Add evidence/report ownership, tenant-scoped object keys, upload limits, parser timeouts and retention cleanup.

#### Verification

- Arbitrary and non-read PowerShell requests are rejected.
- Redis task payloads contain no tenant secrets.
- Preview/production startup cannot create or reset a known administrator.
- Cross-user report download and oversized/malformed uploads are rejected.

#### Guardrails

- Do not reopen the completed tenant-ID injection fix as though it solved service authentication and allowlisting.
- Do not duplicate RR-002/RR-003, JN-002, PK-001, HG-002 or PG-001.

### 8.6 P2 — DLP and sensitivity-label automation

**Status:** Discovery belongs in SP-002; implementation owner not yet confirmed.

**Estimate:** 12–20 person-days.

#### What to implement

- Complete CIS `3.2.1`, `3.2.2`, and `3.3.1` using the pending DLP and label collectors.
- Reuse the existing certificate-alias mechanism without accepting caller-provided secret paths.
- Add collector schemas, registration, Rego policies and semantic tests.
- Move metadata to ready only after a licensed test-tenant run.

#### Verification

- Test against a non-production Purview-licensed tenant.
- Validate missing, empty and variant PowerShell output.
- Confirm no write operation is performed.

#### Guardrails

- This work may strengthen CC6.1 and CC6.7 but does not automatically change their `Partial` ratings.
- Do not confuse SharePoint sharing-link settings with DLP enforcement.

### 8.7 P2 — configuration-drift evidence

**Status:** No direct board ticket found; define scope before creating one.

**Estimate:** 10–15 person-days.

#### What to implement

- Compare normalized evidence between scans of the same tenant, connection, benchmark and control.
- Record added, removed and changed configuration with collection timestamps and source provenance.
- Add baseline selection, duplicate suppression, retention and notification hooks.
- Reuse stored scan evidence rather than recollecting solely for comparison.

#### Verification

- Tests cover no change, material change, missing evidence and benchmark-version mismatch.
- Alerts link to the immutable before/after evidence.
- A v6-to-v7 benchmark change is not mislabeled as tenant configuration drift.

#### Guardrails

- Keep tenant drift separate from benchmark-version gap analysis.
- This strengthens CC4 and CC7.1 but does not automatically change their GRC coverage judgments.

### 8.8 P2/P3 — performance and operational follow-up

**Status:** Confirm overlap with Emma EG-005 and Pratiyush PK-002.

**Estimate:** 8–13 person-days, excluding full infrastructure delivery.

#### What to implement

- Build a scan execution plan keyed by collector so 69 policies do not independently repeat 43 logical collections.
- Pool Graph clients and tokens; add `429`/`5xx` retry and `Retry-After` handling.
- Apply bounded concurrency to the Settings Catalog collector.
- Poll the lightweight scan-summary endpoint while a scan is running.
- Extend `/metrics` into dashboards, alerts, queue health and stuck-scan SLOs after PK-002 lands.

#### Verification

- Count external requests per scan before and after batching.
- Load-test throttling, retries and bounded concurrency.
- Confirm evidence reused by multiple policies is identical and tied to one provenance record.
- Confirm dashboards alert on stuck, failed and error-heavy scans.

#### Guardrails

- Correct idempotency and tenant isolation before batching work.
- Do not duplicate Emma's client-lifecycle implementation or Pratiyush's metrics endpoint.

## 9. Board integrity issues to resolve

The following identifiers or ownership records are ambiguous and must be corrected before new dependencies reference them:

- `26T2-BE-SS-004` appears under both Sidharth Sabu and Yifeng Xu.
- `26T2-BE-SS-005` appears under both Sidharth Sabu and Subham Gupta.
- `26T2-DEV-SC-005` refers to unrelated SCA-validation and hardcoded-secrets cards.
- `26T1-SEC-AA-001` refers to unrelated CIS 1.2.2 and Teams External Access cards.
- `26T2-ENG-TT-001` refers to both CIS 1.3.6 and CIS 1.3.3.
- `26T2-SEC-KHS-001` appears twice with inconsistent Application Control descriptions/status.
- `26T2-ENG-VM-001` has conflicting active and merged meanings.
- SP-009 overlaps completed SP-008 and Viet's VHT-004 transition mapping.
- Raaid's RR-002 and Irusha's hardcoded-secrets ticket appear functionally duplicated.

Board buckets remain authoritative even where a card's internal status says `Completed`. No such card should be treated as available until the bucket or ownership is corrected.

## 10. Shared-file coordination protocol

Before editing shared files such as `metadata.json`, `registry.py`, common schemas, migrations or shared API types:

- [ ] Search the live board and open PRs for the control ID, feature and file area.
- [ ] Confirm the delivery owner and reviewer.
- [ ] Declare the control IDs and file paths that will change.
- [ ] Name one integrator for shared-file edits.
- [ ] Agree the collector input/output contract and permissions.
- [ ] Link collector, metadata, Rego and test work.
- [ ] Define missing, unavailable and malformed evidence behavior.
- [ ] Confirm whether GRC review is required.
- [ ] Rebase against current `main` before final review.
- [ ] Attach verification evidence before moving the board card to merged/completed.

## 11. Programme timeline

| Workstream | Effort | Expected elapsed time |
|---|---:|---:|
| Sham's seven existing GRC tickets | 18–32 person-days | 4–7 weeks |
| Confirmed residual SOC 2 engine work | 40–65 person-days | 5–8 weeks with two engineers |
| Conditional scan/security/evidence residuals | 15–25 person-days if not covered by active PRs | 2–4 additional weeks |
| Organizational governance evidence | 25–45 GRC/operations person-days | Runs in parallel |

With the existing team working in parallel, target approximately **8–12 calendar weeks** if the active PRs land cleanly and owners confirm integration boundaries. Retain the earlier **10–14 week** expectation if current work is delayed, rejected or needs substantial rework.

This timeline covers technical and evidence readiness. It does not include an auditor's observation period or a formal SOC 2 examination.

## 12. Final verification phase

Before declaring the programme technically ready:

### Repository and policy verification

- [ ] `main` matches the approved release commit and the worktree is clean.
- [ ] Metadata counts and generated documentation agree.
- [ ] Every SOC 2 crosswalk reference resolves to the pinned CIS version and exact policy.
- [ ] `opa check --strict` passes.
- [ ] `opa test` passes with semantic coverage for all crosswalk policies.
- [ ] Collector contract and wiring tests pass.

### Backend and worker verification

- [ ] A clean database upgrades from base to the single Alembic head.
- [ ] Backend unit, authorization and integration tests pass.
- [ ] Duplicate task delivery cannot double-count results.
- [ ] Concurrent last tasks cannot strand a running scan.
- [ ] Broker failure is reconciled or leaves an explicit terminal state.
- [ ] No credentials appear in task payloads or logs.
- [ ] Invalid/empty assessment scope cannot produce 100% compliance.

### Frontend and evidence verification

- [ ] Type checking, linting, unit tests and production build pass under the supported Node version.
- [ ] Compliance and evidence-coverage scores are displayed separately.
- [ ] Unknown/error/not-assessable states are distinguishable from tenant failure.
- [ ] Evidence and reports enforce object ownership and retention.
- [ ] Public SOC 2, certification and encryption claims have GRC/legal approval.

### Change-control verification

- [ ] Required CI checks are enforced on `main`.
- [ ] Relevant CODEOWNERS/reviewer approval is required.
- [ ] No failing required check can be bypassed without an auditable exception.
- [ ] Each release records approvals, migration outcome, rollback method and deployed commit.
- [ ] SOC 2 rating changes include a named human approver and rationale.

## 13. Definition of success

The programme is successful when AutoAudit can produce reproducible, tenant-scoped and access-controlled evidence showing exactly which M365 configuration was collected, which versioned policy evaluated it, whether the evidence was sufficient, and which human-approved SOC 2 mapping was applied. The product must continue to state honestly when a SOC 2 point of focus is organizational, physical, inherited, manual or otherwise outside M365 tenant-configuration scope.
