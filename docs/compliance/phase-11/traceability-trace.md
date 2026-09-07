# Phase 11 — the GRC traceability trace (plan item 19.1.12)

Plan item 19.1.12 asks for a SOC 2 evidence pack and a GRC reviewer tracing a
sample from **report → mapping → result → policy → collector → normalized
evidence → source/provenance**. The GRC reviewer is external and unavailable, so
this walks the chain technically and records exactly where it holds and where it
breaks. A reviewer following it needs a database connection and an authenticated
API session, and nothing else.

## The sample: CIS 1.1.1, "Administrative accounts are cloud-only"

### 1. Report

`GET /v1/scans/{scan_id}/soc2-report` (`backend-api/app/api/v1/soc2.py:468`).
This is the evidence pack surface. It renders **from the mapping snapshot pinned
into the scan at creation**, not from the file on disk —
`test_report_renders_from_the_pin_not_the_file_on_disk` is the assertion that
holds that true — and it transcribes every rating verbatim
(`test_report_transcribes_every_rating_verbatim`). The header carries the
unapproved-approval block and the disclaimer.

There is **no build target, CLI entry point or UI control that writes a durable
evidence-pack artifact** — and, more than that, **nothing in the product calls
this endpoint at all.** `frontend/src/types/soc2.ts` types the whole response
contract; `frontend/src/api/client.ts` contains no `soc2` function and no
reference to the route. The pack exists as an authenticated JSON response with no
caller. A GRC reviewer needs an engineer with a token to see it.

### 2. Mapping

`engine/mappings/soc2/common-criteria/v1.0.0/mapping.json`, 47 points of focus.
Exactly one cites 1.1.1:

```
point_id:          CC6.3-P11
criterion:         CC6.3
rating:            Yes
cis_control_ids:   ["1.1.1", "1.1.3", "1.1.4", "5.3.1"]
evidence_selector: null
residual_limitation: "Empty-evidence behavior must be corrected."
```

The mapping's own `status` is `proposed_pending_grc_approval` and
`approval.approved` is `false`. Its SHA-256 is pinned into every scan at
creation and covered by the Phase 3 immutability trigger, so the report a
reviewer reads today and the report they read a year ago describe the same
mapping bytes.

Note what `residual_limitation` says, and see §7.

### 3. Result

`scan_result`, joined on `scan_id` and `control_id`. Phase 3 added `selected`,
`reason_code` and a JSONB `provenance`; the parent `scan` carries
`metadata_snapshot`, `metadata_digest`, `semantics_version`, `selected_count`,
`coverage_score` and `correlation_id`.

The status vocabulary is closed and the aggregation is explicit: compliance is
computed over assessed results only, coverage over the frozen selection
(`engine/worker/result_contract.py:calculate_scores`). A reviewer can see both
numbers and what each divides by.

### 4. Policy

`provenance.policy_file` = `1.1.1_admin_cloud_only.rego`,
`provenance.policy_digest` = SHA-256, and — the link that makes this half work —
**`provenance.policy_source` stores the Rego text itself**, captured at
evaluation. `provenance.opa_version` records the evaluating binary.

A reviewer can therefore re-read the exact policy that produced the result
without trusting the current working tree, and re-run it under the same OPA
version. This half of the chain is genuinely reproducible.

### 5. Collector

`provenance.collector_id` = `entra.roles.cloud_only_admins`, which resolves
through `engine/collectors/registry.py` to the module that produced the
evidence. `metadata.json` records `requires_permissions`
(`User.Read.All`, `RoleManagement.Read.Directory`), so a reviewer can state what
access the assertion depended on.

### 6. Normalized evidence — **the chain breaks here**

`provenance.input_digest` is a SHA-256 of the collector output. **The output
itself is stored nowhere.** A digest is not invertible, so given a completed
scan a reviewer cannot see the evidence the judgement was made on, and cannot
re-derive the result by feeding it back to `opa eval`.

The digest proves *that the evidence has not changed*. It cannot show *what the
evidence was*. The only route to the input is to re-collect from the live
tenant, which is a different point in time and therefore a different fact.

Every other link is reproducible. This one is not, and it is the link an auditor
asks about first: *what did you see?*

### 7. Source / provenance

`engine_git_sha`, `engine_image_digest`, `engine_worktree_dirty`,
`engine_source_digest` (a canonical digest over `opa_client.py`, `worker/*.py`
and `collectors/**/*.py`), `metadata_digest`, `correlation_id`, four timestamps,
and `provenance_status` ∈ {`not_executed`, `collection_only`, `incomplete`,
`captured`}.

This is complete and honest: a result whose evaluation failed is marked
`incomplete` rather than being given a fabricated status.

## A second control, different collector family

CIS 1.2.2 (shared-mailbox sign-in blocked) is served by the Exchange PowerShell
path rather than Graph. The chain has the same shape and the same break at step
6, plus one more:

**1.2.2 is not in the crosswalk.** It is one of 25 `ready` controls that no
point of focus cites, so it appears in no SOC 2 report and has no crosswalk
semantic coverage. Phase 11 found it returns `compliant=true` with a fabricated
resource count on a malformed payload (P11-OWN-16). A reviewer tracing only
crosswalked controls would never reach it; a customer selecting it in the
product would.

## What a GRC reviewer can and cannot do unaided

| Link | Unaided? |
|---|---|
| report → mapping | yes — pinned snapshot, rating transcribed verbatim |
| mapping → result | yes — `control_id` join, selection frozen at creation |
| result → policy | yes — `policy_source` is stored verbatim, with `opa_version` |
| policy → collector | yes — `collector_id` resolves through the registry |
| collector → normalized evidence | **no — only a digest is stored** |
| evidence → source/provenance | yes for the engine identity; the evidence itself is absent |

Two further blockers are not technical:

- The mapping is `proposed_pending_grc_approval` with `approved: false`, so
  there is no approved crosswalk to trace *against*.
- `residual_limitation` on CC6.3-P11 reads **"Empty-evidence behavior must be
  corrected."** Phase 11 confirmed empty-evidence behaviour is still wrong in at
  least one control (P11-OWN-16), so that limitation is still live and the `Yes`
  rating it qualifies is still qualified.
