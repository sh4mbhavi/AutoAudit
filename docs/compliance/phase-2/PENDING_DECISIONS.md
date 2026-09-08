# Phase 2 — Outstanding GRC decisions

No named approvals were recorded in the Phase 0 decision draft supplied to this
session. The instruction to execute Phase 2 authorizes engineering work; it does
not establish a licensed benchmark source or silently approve a GRC judgment.
The following two dependent changes remain unapplied.

## CIS 5.1.6.1 / POL-04

The current collector calls `/beta/policies/crossTenantAccessPolicy/default` and
`/beta/policies/crossTenantAccessPolicy/partners`. It returns partner counts and
inbound/outbound access settings, with no invitation-domain allowlist. The policy
can return `compliant: true` for this synthetic input alone:

```json
{
  "partners_count": 1,
  "b2b_collaboration_inbound": {
    "usersAndGroups": {"accessType": "blocked"}
  }
}
```

Reproduce from the repository root:

```sh
opa eval --format=pretty \
  -d engine/policies/cis/microsoft-365-foundations/v6.0.0/5.1.6.1_restrict_collaboration_invite_domains.rego \
  'data.cis.microsoft_365_foundations.v6_0_0.control_5_1_6_1.result with input as {"partners_count":1,"b2b_collaboration_inbound":{"usersAndGroups":{"accessType":"blocked"}}}'
```

This response establishes no invitation-domain list. Microsoft's
[collaboration restriction documentation](https://learn.microsoft.com/en-us/entra/external-id/allow-deny-list)
separately describes domain allow/block lists and cross-tenant access checks.
The checked-in benchmark extract identifies itself as **v6.0.1**, while this
phase targets **v6.0.0**. It cannot establish the licensed v6.0.0 procedure.

Concrete containment proposed for the named GRC reviewer and benchmark custodian:
change only this control's `automation_status` from `ready` to `blocked`, set
`policy_file` to null, remove the heuristic Rego from the active policy tree
(retaining history in Git), and record the missing licensed-source and collector
validation in `notes`. Retain its collector registration if still referenced.
This would reduce ready controls from 69 to 68 and increase blocked controls from
31 to 32. SOC 2 Yes/Partial/No ratings would remain unchanged. Validate structural
checks and record that the supplied crosswalk no longer resolves this control to
a ready implementation; do not conceal the coverage reduction.

Approval needed: named GRC approver with role, decision reference/date, and
benchmark custodian confirmation. Collector owner must validate the replacement
against authorized portal evidence in a licensed non-production tenant before
it can return to ready. No approval or live-tenant validation was received here.
POL-04 remains open; the current heuristic is unchanged.

## CIS 6.1.2 empty mailbox population

The current collector turns `None` into `[]`; an empty array alone cannot prove a
successfully enumerated, complete population. The current Rego returns true for
`{"mailboxes": []}`. Phase 0 D03 proposes `compliant: null` until completeness and
control applicability are established. It explicitly does not authorize a pass,
tenant failure, or automatic not-applicable outcome solely because the array is
empty.

Concrete proposed change: guard the existing assessment with a non-empty valid
mailbox array, return a complete `compliant: null` result for empty/unusable
population evidence, and add secure/insecure/missing/null/malformed/empty tests.
Do not change the licensed audit-action sets or invent applicability rules.
This remains pending the named GRC/product decision required by Phase 2 item 6;
6.1.2 is unchanged in this branch.

## Runtime dependency on Phase 3

The five implemented policy hotfixes return a complete `compliant: null` result
for unusable evidence, consistent with the existing Rego result shape. However,
`engine/worker/tasks.py` currently tests truthiness and writes every falsey policy
value, including null, as `status="failed"`. Its collector exception path already
uses an error result. Phase 3 must distinguish null evidence from confirmed
noncompliance, persist the approved result states and correct score/coverage
handling. Do not describe these policy-only changes as an end-to-end fix for
scan status or audit readiness. No worker/schema/scoring changes are included.
