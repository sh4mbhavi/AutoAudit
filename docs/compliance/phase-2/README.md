# Phase 2 — CIS policy evidence-correctness handoff

Date: 2026-09-05 (Australia/Melbourne).

**Status: engineering hotfixes verified; phase acceptance blocked by the two
GRC decisions in [PENDING_DECISIONS.md](PENDING_DECISIONS.md).** POL-04 and the
6.1.2 applicability decision are not complete. The branch is for review, not a
claim of audit readiness or production release.

## Scope and baseline

The supplied `SOC2_EXECUTION_PLAN.md` Section 10 requests POL-01 through POL-05,
empty-mailbox handling after the Phase 0 decision, strict OPA validation, and
policy/wiring/validator tests. Implementation used a separate branch and worktree
as requested, preserving the original Phase 0 checkout and its untracked plans.

| Item | Value |
|---|---|
| Baseline and fetched upstream/main | `be241f52beb5ffec10904771bf7cfa4b98233ab0` |
| Branch | `fix/soc2-phase-2-policy-evidence` |
| Worktree | `/Users/clupa/Documents/projects/autoaudit/AutoAudit-phase-2` |
| Input execution-plan SHA-256 | `2a503ab2ff985a1d86f71abaa04d3f95e53ff17fe818c2ba21e52aa4eb995940` |
| Input Phase 0 decision draft SHA-256 | `bf85d12a26343c8d66ad87f4b3601c53b2c692492063f2a421017fcf4075a591` |
| Benchmark/version | CIS Microsoft 365 Foundations `v6.0.0` |
| Control inventory | 140 total; 69 ready, 31 blocked, 12 deferred, 11 manual, 17 not started; unchanged |
| PR/publishing | No PR opened, no remote push, no owner messages sent |

The input plan and Phase 0 decision draft were untracked files in the original
`AutoAudit` checkout. Their contents were read as task inputs, not copied into
this branch or represented as approved decisions.

Fetched upstream and checked live open PR paths on 2026-09-05. No open PR covered
the five targeted policy implementations. Full diffs of #332, #345 and #356 were
read: #332 checks Compose policies, while #345 and #356 add tests for different
CIS controls. Open PRs #348/#344/#342/#336/#333/#328/#320/#297 touch shared v6
metadata; this patch changes only the five permission arrays documented in
[PERMISSIONS.md](PERMISSIONS.md), not their controls. #351 touches the existing
wiring test module, which is unchanged here. No PR was adopted or merged, and
this check does not assert owner handoff or live project-board approval.

## Implemented behavior

| Finding | Result |
|---|---|
| POL-01 — 2.1.5 | All three required ATP properties must be valid booleans. Each insecure property independently produces false; only the secure combination passes. Missing/malformed evidence and collector-error envelopes return null. |
| POL-02 — 2.4.4 | True and false ZAP values produce one defined result. Null, missing and malformed values produce one complete null result, eliminating the false/null complete-rule conflict. |
| POL-03 — 1.1.1, 1.1.4, 1.3.1 | Require non-empty, valid essential account/domain evidence. Missing identities, malformed flags, incomplete managed-domain password settings and collection errors cannot pass. Unusable evidence takes precedence over known violations. |
| POL-04 — 5.1.6.1 | Reproduced the heuristic false assurance and documented source/collector mismatch. No readiness or policy change without the specified GRC decision. **Open.** |
| POL-05 | Reconciled 11 annotation/metadata mismatches against current Microsoft primary sources. Added 82 Python consistency/collector-requirement cases and verified OPA native annotation output. |
| Strict OPA | Cleared all eight baseline v6 unused-argument/variable errors, retaining existence guards and existing behavior. |
| 6.1.2 | Empty-mailbox change remains pending Phase 0 D03 approval; policy unchanged. |

The five policy hotfixes preserve the `compliant`, `message`,
`affected_resources`, and `details` shape. Null results include an explanatory
reason and `details.evaluation_status = "indeterminate"`. This does not introduce
a stored scan status. A valid normalized Teams `zap_enabled` field takes
precedence over its raw-policy fallback, including explicit null. For 1.1.1 the
collector already converts Graph null sync flags to false; raw null supplied
directly to the policy is unknown. An all-federated domain population is unknown
because no managed domain was assessed. Optional display names and role lists do
not determine compliance.

No SOC 2 rating, readiness classification, benchmark identifier, registry entry,
API grant, tenant setting, worker behavior, schema or CI workflow was changed.

## Verification

Toolchain: OPA **1.20.2**, darwin/arm64, build
`b2c26708e9d55645d7f837db495031f7e4152594`, downloaded from the official
versioned release and SHA-256 verified as
`54e7008e696d39e8e4f96594e2b71bcbe45fd9a4f838102bcf1240638bf3fbe1`.
Local executable: `/tmp/autoaudit-phase-2-tools/opa`. Python **3.13.9** through
`uv run --project engine --extra dev` and the existing lockfile. No lockfile
change. Tests use synthetic evidence and require no tenant credentials.

Before implementation:

- Existing OPA suite: **31/31 passed**.
- Existing engine Python suite: **496 passed, 1 skipped**.
- Strict v6 check: **8 expected compile errors**, reproduced from the plan.
- New five-policy tests before fixes: **127 assertion failures, 2 existing ZAP
  evaluation conflicts, 16 passes** out of 145 initial cases.
- New permission tests before fixes: **16 failures, 66 passes**. Failures cover
  all 11 mismatches plus five incorrect collector requirement declarations.

Final commands from this worktree root (with the verified OPA on PATH):

```sh
opa check engine/policies/cis/microsoft-365-foundations/v6.0.0
opa check --strict engine/policies/cis/microsoft-365-foundations/v6.0.0
opa test engine/policies engine/tests
uv run --project engine --extra dev pytest engine/tests -q
git diff --check
```

Results: both v6 checks **exit 0**; OPA **204/204 passed** (173 new cases);
Python **578 passed, 1 skipped** (82 new cases), with one pre-existing Pydantic
class-config deprecation warning; diff check **exit 0**. The Python run includes
the existing wiring and validator suites. OPA native `inspect -a` confirms all
**69** ready permission sets match metadata. Before/after comparisons across
**104** policy/input pairs confirm the strict cleanup preserves results,
including 10 pre-existing evaluation errors outside the five hotfixes.

Strict checking of the entire multi-version `engine/policies` tree still finds
two pre-existing unused arguments in v4.0.0 `5.2.2.3_block_legacy_auth.rego`;
the Phase 2 required strict target is v6.0.0. No claim of all-version strict
cleanliness is made. Current engine CI invokes only `test_wiring.py`; Phase 4
must include the new semantic and permission tests in its enforcement work.

Independent specification reviews of the five policy fixes and permission/strict
changes passed. The final code-quality review approved the complete scoped
change with no actionable findings. Reviewers independently reran strict v6
validation and the relevant suites; the policy reviewer also checked 128
adversarial inputs with exactly one expected result each.

## Standard handoff

- **Phase:** 2 — CIS policy evidence-correctness hotfixes; acceptance blocked.
- **Baseline commit:** `be241f52beb5ffec10904771bf7cfa4b98233ab0`.
- **Branch/commit/PR:** `fix/soc2-phase-2-policy-evidence`; local uncommitted
  changes based on the baseline above; no PR.
- **Findings closed:** POL-01, POL-02 and POL-03 at the Rego boundary; POL-05
  declaration mismatches. All eight v6 strict errors cleared. POL-04 remains open.
- **Files changed:** five core Rego policies and five new semantic-test modules;
  eight strict-error sites; seven permission annotation corrections plus LAPS
  custom-metadata repair; five permission arrays in `metadata.json`; two
  collector docstrings; `test_policy_permissions.py`; this handoff, permission
  source register and pending-decision record. Some files serve multiple fixes.
- **Decisions made:** retain existing result shape, use null for unusable
  evidence, preserve unknown precedence and all human-owned ratings; preserve
  strict-cleanup existence guards; choose permissions from all endpoints the
  collector actually calls, not just one endpoint's least-privilege table.
- **Tests run and exact results:** recorded above.
- **Security/GRC review required:** named GRC/product approval of 6.1.2 handling;
  named GRC/benchmark-custodian decision on 5.1.6.1, licensed v6.0.0 source and
  collector validation; non-production validation of changed permissions.
- **Known gaps or follow-up work:** the worker stores null as failed; Phase 3
  must correct persistence and scoring. Existing collector normalization can
  hide upstream omissions before Rego receives evidence, so complete-looking
  inputs do not prove collection completeness. No live-tenant test was run.
  Broader collector hardening and CI enforcement remain later-phase work.
- **Next unblocked phase:** no formal downstream acceptance claim while Phase 0
  decisions and POL-04 remain open. Phase 3 result semantics can be prepared
  against these tests after the relevant GRC decisions are approved.
