# Phase 0 decision record — proposed for approval

Date: 2026-09-05, Australia/Melbourne. Record version: draft 1.

Status: **Awaiting named GRC/product/security approval.** These proposals are not implemented and are not evidence of approval. The [handoff](README.md) records the verified repository baseline and sources. The supplied ratings remain 13 Yes, 16 Partial, and 18 No.

## Decisions already constrained by the execution plan

- Keep CIS Microsoft 365 Foundations **v6.0.0** identifiers and the supplied Appendix A ratings. Engineering may record evidence defects without changing a GRC judgment.
- Missing or failed collection cannot pass; a collection failure is not tenant noncompliance.
- Collection stays read-only. No runtime, policy, permission, migration, or public-copy changes are part of Phase 0.
- Proposed owner routing below is based on the dated collision-safe plan, not a confirmation of authority. No contributor has been contacted or assigned work.

## D01 — Result states

Proposed canonical vocabulary uses `indeterminate` from execution-plan Phase 3; do not add `unknown` as a competing stored state.

| State | Proposed meaning |
|---|---|
| `passed` | Complete, valid evidence satisfies the versioned control procedure. |
| `failed` | Complete, valid evidence demonstrates a control violation. |
| `indeterminate` | Collection returned evidence but required facts are missing, malformed, ambiguous, or incomplete; no defensible assessment is possible. |
| `error` | Authentication, authorization, transport, collection, evaluation, or system execution failed. |
| `skipped` | A valid control was outside the requested selection; never a substitute for a selected control that could not run. |
| `not_assessable` | Selected control is outside the automated assessment capability or requires manual/organizational evidence. This does not establish that it is inapplicable. |
| `not_applicable` | A control-specific applicability rule is satisfied with complete scope evidence and an approved, versioned rationale. This proposed additional state requires explicit approval. |

Use structured reason codes and provenance. A known execution failure takes `error`; an otherwise successful response with unusable evidence takes `indeterminate`. Manual evidence has its own reviewer/expiry lifecycle and must not silently increase automated coverage. A retry may supersede a result only with recorded history. Selection, applicability, and execution status remain separate concepts.

Approval required: named GRC and product owner; currently unassigned.

## D02 — Compliance and coverage

Freeze the requested valid control set `S` before execution, including selected manual, blocked, deferred, and not-started controls. Reject unknown IDs and empty effective selections. Let `N` be the subset with approved `not_applicable` evidence, `D = |S| - |N|`, `P` the passed count, and `F` the failed count.

- Compliance among assessed controls: `100 × P / (P + F)`; null with “Not assessed” when `P + F = 0`.
- Automated coverage: `100 × (P + F) / D`; null with “No applicable controls” when `D = 0`.
- Selected `indeterminate`, `error`, and `not_assessable` controls stay in `D`. Unselected `skipped` controls stay outside `S`. Never drop a selected control because collection failed.
- Always display numerator/denominator, all state counts, selected count, and approved N/A count together. A 100% assessed score with incomplete coverage must be labelled as a partial assessment, not overall compliance. Neither score expresses SOC 2 certification.

Review examples: 8 passed, 2 failed, 3 indeterminate, 2 error, 4 not assessable and 1 approved N/A yield `S=20`, `D=19`, compliance `80%`, coverage `52.63%`. Ten selected errors yield null compliance and `0%` coverage. All selected controls approved N/A yield two null scores, never `100%`. Weighting and mixing manual evidence into these formulas are excluded from this proposal.

Approval required: named GRC and product owner; currently unassigned.

## D03 — Zero resources, including CIS 6.1.2

Propose allowing `not_applicable` for 6.1.2 only when the licensed v6.0.0 procedure and GRC confirm that no in-scope user mailboxes makes this control inapplicable. Require successful tenant-bound authentication, authorized enumeration of the entire in-scope population, no truncation or hidden collection error, collection timestamps, and reviewer-approved applicability evidence. Reevaluate applicability at each scan; never carry a previous empty population forward without fresh evidence.

An empty list alone proves none of these conditions. The current collector converts `None` to `[]`, so its output cannot establish this exception by itself. Until approval and collection completeness are implemented, successful-but-unproven empty evidence should be `indeterminate`; a known failure should be `error`. Do not mark a mail-free tenant failed solely for having no mailboxes. Do not extrapolate this exception to administrators, domains, or other controls.

Approval required: named GRC reviewer and product owner; licensed v6.0.0 procedure review pending.

## D04 — Evidence retention and deletion

Proposed engineering defaults for review, **not a legal minimum or an existing product commitment**:

| Evidence class | Proposed retention / deletion behavior |
|---|---|
| Normalized inputs, results, provenance, approved manual evidence, report versions, approval/access/deletion history | 365 days from collection, approval or event as appropriate; bind each object to the retention-policy version. |
| Temporary uploads and OCR/extraction work files | Delete on processing completion, with a 24-hour maximum for failure cleanup. Retained approved attachments belong to the evidence class above. |
| Diagnostic raw responses | Off by default. Explicitly approved field-limited capture only, encrypted and access-logged, maximum 7 days. |
| Backups containing evidence | Proposed maximum 35-day expiry after primary deletion; restores must reapply deletion tombstones before serving data. |

Authorized deletion removes primary content within a proposed 30-day service window unless a documented hold applies. Retain a minimal deletion event (opaque artifact ID, actor, time, policy, outcome), without deleted raw content, under the approved audit-log policy. Legal holds need a named issuer, scope, review date, release event, and access controls. Immutable means append-only while retained; it does not authorize indefinite retention. Customer exports and termination requests need explicit ownership checks and logged outcomes.

GRC/privacy/legal must confirm examination window, contractual and jurisdictional requirements, residency, all durations, and hold exceptions; infrastructure must confirm enforceability. No automatic cleanup or retention change is authorized by this draft. All approvers are unassigned.

## D05 — Redaction and permitted raw fields

Propose a per-collector allowlist reviewed alongside its control contract. Persist only required normalized booleans/enums/counts, relevant audit-action lists, approved domain rules, pseudonymous resource references, and provenance (benchmark/version, metadata/policy/input digests, collector/code/image/OPA version, selected tenant reference, timestamps, completeness and request correlation).

For 6.1.2 retain AuditEnabled, AuditAdmin, AuditDelegate, AuditOwner and an opaque mailbox reference. Keep raw UserPrincipalName only if GRC approves an auditor need, in restricted encrypted evidence with retention and access logging. For 5.1.6.1, domain lists are permitted only when required by the confirmed procedure and treated as restricted configuration data. Preserve required comparisons before applying display redaction; record the normalization/redaction version.

Exclude secrets, bearer/refresh/reset tokens, passwords, private keys, authorization headers, message bodies, unrelated profile fields and unbounded service responses from logs, fixtures and routine reports. Manual screenshots/uploads require redaction review before approval. An input digest covers canonical retained evaluation evidence; it is not a reason to retain prohibited raw data.

Approval required: named security/privacy and GRC reviewers; currently unassigned.

## D06 — Crosswalk ownership and change workflow

Proposed routing: Sham Polavarapu / 26T2-GRC-SP-006 for mapping coordination, with a **separately confirmed named GRC approver**. This routing does not appoint Sham as approver. Engineering submits factual resolution, provenance, semantic tests, and scope limitations in a reviewed change. Rating/rationale changes require named GRC approval, timestamp, decision reason and mapping version; preserve prior versions for historical reports. Organizational and inherited evidence stay separate from automated M365 coverage. Structural checks must never generate or promote a rating.

Approval required: confirmation of accountable mapping owner and GRC approval authority.

## D07 — Benchmark and mapping versioning

Keep `(framework, benchmark, benchmark_version, control_id)` immutable as an identity. Version the mapping separately and bind reports to its version/digest and approval record. Add v6.0.1 or v7 under separate versioned artifacts only after source reconciliation and review; never renumber the v6.0.0 mapping in place. Re-runs create new evidence; historical reports retain their original provenance.

The checked-in benchmark extract says **v6.0.1 – 2-26-2026** and cannot establish the licensed v6.0.0 audit procedure. Record the licensed source edition/date, checksum and section/page references without copying licensed content into public artifacts. The public CIS download page does not resolve this mismatch.

Approval required: GRC confirms the authoritative licensed v6.0.0 source and mapping version policy.

## D08 — Public SOC 2 wording

Proposed routing: Alisha AP-001/AP-002 for editorial coordination; final approval by named GRC/legal owners, currently unassigned. Proposed factual description for later review: “AutoAudit assesses selected Microsoft 365 configuration controls and supports evidence collection for SOC 2 readiness. It does not determine SOC 2 compliance or provide certification.” No public copy is changed here. Claims about Type II examination, third-party audits, zero-knowledge or encryption require scoped substantiation and approved wording.

## D09 — CIS 5.1.6.1 revalidation

Require the licensed **v6.0.0** procedure before selecting final semantics. Compare its invitation-domain setting to the current collector and Rego heuristic; cross-tenant partner count and inbound access do not establish a configured invitation-domain allowlist. The local v6.0.1 extract explicitly describes a different procedure and includes an empty-allowlist boundary case; use this only as a discrepancy to investigate.

Current Microsoft documentation exposes `/beta/policies/b2bManagementPolicies` with `Policy.Read.B2BManagementPolicy`, while the collector uses cross-tenant access endpoints with `Policy.Read.All`. This is a documentation-confirmed candidate, not an approved substitution: beta production support, licensed-procedure equivalence, actual response schema, permissions, national cloud support, and a non-production tenant must be validated first. Do not copy the extract's `/beta/legacy/policies` endpoint without current documentation.

Required later evidence: source reference, exact returned fields, comparison with authorized portal observation, approved-domain ownership, and tests for allowlist, blocklist, absence, empty configured allowlist, malformed definition, unauthorized response and partial enumeration. GRC decides whether the technical result can be relied upon and approves any readiness/rationale change; existing SOC 2 ratings stay unchanged.

Approval required: named GRC reviewer, benchmark custodian and collector owner; currently unassigned. Source links are in the [API discovery register](README.md#api-and-permission-discovery).

## D10 — Migration and active-scan deletion policy

Propose forward-only deployed migrations. Phase 1 must test both existing Alembic histories and empty/current database upgrades. Downgrades may be tested in disposable databases when reversible; do not make production rollback depend on destructive downgrade. Production recovery uses a reviewed forward fix or a tested restore under the platform owner's authority. Deployed-history rewrites remain forbidden without explicit approval.

Deletion/cancellation must invalidate further task writes atomically or produce a logged idempotent no-op. Retain only the approved audit tombstone; workers must not resurrect deleted evidence. Exact state-machine implementation belongs to Phase 6.

Approval required: repository/platform owner and GRC for deletion/audit implications; currently unassigned.

## Approval record

For each D01–D10 record: approved/rejected/amended, exact record version or digest, approver name and role, UTC time, rationale, and review/change reference. No approvals have been received. Do not infer approval from elapsed time, this document's existence, the plan owner's name, or successful engineering tests.

Phase 0 remains blocked at its GRC acceptance gate until these decisions have confirmed owners and recorded outcomes, including the licensed-source resolution. Under the execution plan, dependent implementation phases remain gated.
