# Phase 8 — GRC review request

Date raised: 2026-09-06 (Australia/Melbourne). Raised by: engineering (Phase 8 session).
**Status: no rating, rationale, mapping row or coverage number has been changed by this phase.**

Plan section 16 asks engineering to *request* GRC review of specific crosswalk rows once Wave A and
Wave B land. This document is that request. It states what technical evidence now exists, what it does
and does not establish, and asks a named GRC approver to decide. Engineering has no authority to change
a rating (non-negotiable rule 1; Phase 0 decision D06, unapproved), and
`engine/mappings/soc2/common-criteria/v1.0.0/mapping.json` still records `approval.approved: false`
with null reviewer fields.

## What is being asked

For each row below: does the new technical evidence change your rationale, your residual limitation
text, or your rating? A decision of "no change" is a valid and expected outcome and should be recorded
as explicitly as a change would be.

## Rows in scope

### CC6.1-P06 — "Restricts Access to Information Assets" (currently **Partial**)

Recorded residual limitation, verbatim: *"Data classification and DLP are not currently automated."*

What changed technically: DLP and sensitivity-label collection is now implemented end to end —
a certificate-authenticated Security & Compliance PowerShell transport, two registered read-only
collectors, and three strictly-checked, semantically-tested policies for CIS 3.2.1, 3.2.2 and 3.3.1.

What has NOT changed, and why the residual text may still be accurate:
- The three controls remain `automation_status: "blocked"`. Their policies live outside the benchmark
  tree and **no scan evaluates them**. Coverage of this point of focus is unchanged today.
- Promotion is blocked on live-tenant validation and on obtaining the licensed CIS v6.0.0 procedure
  (see "Blocking gates" below). Until then this is capability, not coverage.
- Data *classification* remains broader than label-policy publication. 3.3.1 establishes that at least
  one sensitivity label policy is published; it does not establish that classification is applied,
  correct, or enforced.

### CC6.7-P20 — "Restricts the Ability to Perform Transmission" (currently **Partial**)

Recorded residual limitation, verbatim: *"Full DLP is not currently automated."*

Same technical change and same caveats as CC6.1-P06. Additionally note that CIS 3.2.2 is scoped
**E5 Level 1 only**, so in an E3 tenant it is not applicable rather than passing, and 3.2.1's audit
procedure is UI-only with an explicitly organizational criterion.

### CC7.1-P28 — "Implements Change-Detection Mechanisms" (currently **Partial**)

Recorded residual limitation, verbatim: *"Audit logging is after-the-fact, not real-time drift detection."*

What changed technically: configuration drift is now computed between comparable scans, producing
durable, append-only drift events that separate configuration change from evaluation-status change,
with previous/current digests, severity, correlation, acknowledgement and evidence-backed remediation
verification.

**Engineering's own assessment is that this residual limitation still stands and the rating should
remain Partial.** Drift is computed on scan finalisation. It is periodic, not continuous, and it is not
SIEM correlation. Plan section 16.6 states directly: *"Do not interpret periodic drift as real-time
incident detection."* Nothing in Phase 8 changes that.

### CC4 — criteria coverage summary line

Recorded classification, verbatim: *"Governance; AutoAudit supports monitoring evidence."*

Drift events are new monitoring evidence and may bear on this line. There are no CC4 points-of-focus
rows in the mapping to change; this is a summary-line question only.

## Blocking gates on the three CIS controls

Recorded machine-readably in `engine/policies/candidate/candidates.json` and enforced by
`tools/policies/promote_candidate.py`, whose `--apply` refuses while any gate is unresolved:

| Gate | State | Meaning |
|---|---|---|
| `live_tenant_validation` | unresolved | Certificate-based `Connect-IPPSSession` has been executed against no tenant by this build. |
| `licensed_v6_procedure` | unresolved | Only the extract declaring `v6.0.1 – 2-26-2026` is available; the licensed v6.0.0 procedure has not been obtained (Phase 0 D07). |
| `grc_rationale_review` | unresolved | **This document.** |
| `worker_client_wiring` | unresolved | The worker does not yet pass the Purview binding into `PowerShellClient`. |
| `readiness_call_site_wiring` | unresolved | `scans.py` does not yet pass Purview scope into readiness evaluation. |
| `policy_review_reason_code` | unresolved | The reason-code allowlist for a policy-authored review state is not agreed. |

## What engineering explicitly is NOT claiming

- Not claiming any point of focus should move from Partial to Yes.
- Not claiming DLP or labelling is *covered*; the controls are not evaluated by any scan.
- Not claiming drift is real-time detection, incident response, or SIEM correlation.
- Not claiming the v6.0.1 extract establishes the licensed v6.0.0 audit procedure.
- Not claiming an empty tenant result is a pass: zero DLP policies evaluates to `indeterminate`,
  and both 3.2.1 and 3.3.1 are structurally incapable of returning `compliant: true` because the
  benchmark assigns their pass decision to an auditor.

## Decisions needed, with owners

| # | Decision | Owner |
|---|---|---|
| 1 | CC6.1-P06 rationale/rating after Wave A | Named GRC approver (unassigned — D06) |
| 2 | CC6.7-P20 rationale/rating after Wave A | Named GRC approver (unassigned — D06) |
| 3 | CC7.1-P28 rationale/rating after Wave B | Named GRC approver (unassigned — D06) |
| 4 | CC4 coverage-summary wording | Named GRC approver (unassigned — D06) |
| 5 | Approve D04/D05 so drift fingerprint retention has a named policy rather than `phase8-draft-1` | GRC / privacy / legal (unassigned) |
| 6 | Confirm the licensed CIS v6.0.0 source for 3.2.1 / 3.2.2 / 3.3.1 | Benchmark custodian (unassigned) |

Phase 0's approval gate remains unsatisfied: D01–D10 are unapproved drafts with no named owners. This
request does not resolve that and must not be read as doing so.
