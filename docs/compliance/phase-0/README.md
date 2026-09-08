# Phase 0 — Rebaseline and decision handoff

Observed 2026-09-05 (Australia/Melbourne). Engineering discovery and structural verification are complete; **Phase 0 acceptance is blocked pending GRC decisions and licensed benchmark source confirmation**. Review the concrete proposals in [DECISIONS.md](DECISIONS.md).

## Repository and PR baseline

| Item | Observed value |
|---|---|
| HEAD and fetched upstream/main | `be241f52beb5ffec10904771bf7cfa4b98233ab0` |
| Baseline change since execution plan | None on main; upstream feature/google-sso-auth advanced during fetch. |
| Last main merge | [PR #303](https://github.com/Hardhat-Enterprises/AutoAudit/pull/303), Intune Settings Catalog collector |
| Working branch | `docs/soc2-phase-0-rebaseline` |
| Starting working-tree state | No tracked edits; the execution plan and collision-safe delivery plan were already untracked. Preserved byte-for-byte. |
| Open PRs / merged PRs | 45 / 183 across the repository, all base branches |
| Remote actions | Read-only GitHub inventory and upstream fetch; no push, PR, merge, comment, assignment or external configuration change. |

GitHub access used the sandbox configuration (`source ../sandbox-env.sh`, account `sh4mbhavi`). Counts came from `gh api search/issues` with `repo:Hardhat-Enterprises/AutoAudit is:pr is:open` and `is:pr is:merged`, respectively. The [PR snapshot](pull-requests-2026-09-05.json) captures all 45 open PRs, authors, target branches, exact head SHAs and links. An open PR contributes no current coverage.

All 22 Section 7 candidates remain open: #352, #355, #350, #292, #305, #318, #330, #331, #326, #351, #297, #307, #328, #333, #348, #336, #325, #344, #320, #342, #345 and #356. The candidate set was parsed from the plan and checked against the live inventory: no missing candidates.

Coordination implications from this inventory:

- #320 and #342 still overlap on priority-account protection; their owners and the integrator must choose a disposition before implementation.
- #294 is also open alongside #355 for backend tests; #229 touches manual-verification templates, #230 report generation, #332 policy checks, and #334 collector testing. Include them in the relevant later phase's diff review.
- #350's refreshed head is `9bcb2272f9eb3925bdf56ebde0f378c9dca582f3`; previous reviews cannot be assumed to cover it.
- #311 and #346 target the Settings Catalog feature branch, not main; account for that dependency when evaluating Essential Eight work.
- Full PR diffs, tests and merge readiness were not reviewed or approved in this inventory-only phase. The plan's Section 4.2 checks remain mandatory before adopting any PR. The live project board and owner acceptance were not independently verified; the collision-safe plan is a dated routing aid only.

## Metadata and crosswalk verification

| Status | Controls |
|---|---:|
| Ready | 69 |
| Blocked | 31 |
| Deferred | 12 |
| Manual | 11 |
| Not started | 17 |
| Total | 140 |

The ready population uses 43 unique collectors. All **44 explicit Appendix A/B control references** resolve to one ready metadata record, the exact Appendix B policy filename, the expected v6.0.0 Rego package, and exactly one registered collector key. Those 44 controls use **30 unique collectors**. Registry imports succeed; duplicate metadata and registry keys were checked. This proves structural resolution, not policy correctness or API permission sufficiency.

CC7.1's “All automated CIS M365 v6 controls” row denotes the whole 69-ready population and is distinct from the 44 explicitly enumerated IDs. Existing wiring tests also cover that ready population. Supplied ratings are unchanged: **13 Yes / 16 Partial / 18 No**, 47 points of focus.

The [baseline snapshot](baseline-2026-09-05.json) records each resolved policy and collector class plus SHA-256 digests of policies, metadata, registry, Appendix A/B and all required repository sources. The [read-only snapshot script](verify_baseline.py) reruns structural checks; it is a Phase 0 audit aid, not the Phase 7 runtime/CI mapping validator.

## Required source discovery

All sources in execution-plan Section 8.1 were read, together with Section 8.2 patterns and the relevant benchmark-extract entries. Source paths below are relative to repository root; exact bytes are identified in the baseline snapshot.

| Source read | Result / constraint for later phases |
|---|---|
| `README.md` | Monorepo and deployment conventions; assertions about branch protection are not proof of live enforcement. |
| `backend-api/README.md` | Existing FastAPI Depends/get_current_user/require_admin patterns and startup migration/bootstrap sequence. The GCP-only introduction is stale relative to M365 scope. |
| `engine/collectors/README.md` | BaseDataCollector, explicit DATA_COLLECTORS registration, shared logical datasets, Graph get/get_all_pages. Placeholder endpoint examples are not actual API contracts. |
| `engine/policies/README.md` | OPA annotations and package normalization; v3.1.0 examples are historical, not this task's benchmark version. Metadata.json is the current inventory despite the README's narrative about embedded metadata. |
| `docs/engine/sharepoint-control-development.md` | Reuse sharepoint.pnp.tenant, return normalized facts, explicitly handle missing data. PASS/FAIL is assessed evidence; ERROR is a runtime problem. |
| `docs/engine/sharepoint-local-runtime.md` | Certificate alias reuse and tenant matching are prerequisites. The guide expressly warns about mixed-tenant Graph/Exchange versus globally configured SharePoint evidence (TEN-01). No live tenant was used. |
| `docs/engine/manual-collector-testing.md` | Existing test_collector entry point. Live output can contain sensitive evidence; no raw tenant sample was collected here. |
| `docs/features/pre-scan/prescan-readiness.md` | Readiness is advisory and Graph-focused, with unprobed permissions; it does not guarantee successful collection. |
| `docs/DevSecOps/workflow-documentation.md` | Describes CodeQL/lint and non-blocking Grype. Do not equate a report comment or documented workflow with required test enforcement. |
| `docs/compliance/manual_control_classification.md` | Useful reason/evidence-type structure; counts and implementation claims need reconciliation. It says 14, but expands to 24 IDs (11 manual + 7.2.8 + 12 Fabric). Current metadata totals only 11 manual. |
| Execution plan Appendix A | Authoritative supplied ratings and residual limitations; preserved exactly. |
| `docs/compliance/Risk_Impact_Prioritisation_Matrix.md` | Reuse likelihood × consequence prioritization; its operational examples are not evidence that controls or retention policies operate. |
| `metadata.json`, registry and `engine/tests/test_wiring.py` | Current structural source and test patterns, verified by snapshot and tests. |
| `docs/engine/Framework/CIS_M365_Benchmarks.json` | Declares **v6.0.1 – 2-26-2026**, whereas runtime/plan are v6.0.0. Reviewed 5.1.6.1 and 6.1.2 for discrepancies only; licensed v6.0.0 procedure still required. |

Specific stale-source traps: manual-classification text recommends `sharepoint.spo_tenant`, which is **not registered**; metadata 7.2.8 is `not_started`, still references that obsolete ID, and has no policy file. The SharePoint development guide specifies `sharepoint.pnp.*`. This does not invalidate Appendix B (7.2.8 is not included), and no status was promoted. Do not use `controls.md` or the old count of 61 as a baseline. DOC-02 remains open for later reconciliation.

Repository APIs inspected in addition to the required documents: GraphClient.get/get_all_pages; DATA_COLLECTORS; the B2B and mailbox-audit collectors; Rego 5.1.6.1; ExecuteRequest validators and resolve_sharepoint_certificate; encryption.encrypt/decrypt; RequestLoggingMiddleware; manual-verification _check_ownership; readiness probe definitions. Reuse those abstractions subject to the plan's fixes. Existing generic cmdlet execution, generic Graph _request, permissive result dictionaries, and global SharePoint identity are not approved implementation boundaries.

## API and permission discovery

Documentation checked 2026-09-05. These are source-confirmed interfaces, **not live-tenant verification or a complete audit of all 69 controls' permissions**. No permissions were changed. Endpoint-specific application permissions must be reconciled with metadata, Rego, readiness, module versions, licensing and actual tenant access in later phases.

| Surface | Confirmed source and allowed-use constraint |
|---|---|
| Graph organization | `GET /v1.0/organization`, application `Organization.Read.All`; `$select` documented. Readiness currently adds `$top=1`, which this reference does not document: review in the readiness phase. [Microsoft reference](https://learn.microsoft.com/en-us/graph/api/organization-list?view=graph-rest-1.0). |
| Graph users | `GET /v1.0/users`, application `User.Read.All`; select only required fields, honor pagination. Additional fields may require extra permissions/licensing. [Microsoft reference](https://learn.microsoft.com/en-us/graph/api/user-list?view=graph-rest-1.0). |
| Graph active directory roles | `GET /v1.0/directoryRoles`, application `RoleManagement.Read.Directory`; activated roles are not a complete inventory of every possible role. [Microsoft reference](https://learn.microsoft.com/en-us/graph/api/directoryrole-list?view=graph-rest-1.0). |
| Cross-tenant default | `GET /v1.0/policies/crossTenantAccessPolicy/default`, application `Policy.Read.All`. Current collector uses beta; this API describes cross-tenant configuration, not proof of the CIS invitation-domain rule. [Microsoft reference](https://learn.microsoft.com/en-us/graph/api/crosstenantaccesspolicyconfigurationdefault-get?view=graph-rest-1.0). |
| B2B invitation policy candidate | `GET /beta/policies/b2bManagementPolicies`, application `Policy.Read.B2BManagementPolicy`, no optional query parameters documented. Beta is subject to change and not supported for production use; equivalence to the licensed v6.0.0 procedure remains unproven. [List API](https://learn.microsoft.com/en-us/graph/api/policyroot-list-b2bmanagementpolicies?view=graph-rest-beta), [resource definition](https://learn.microsoft.com/en-us/graph/api/resources/b2bmanagementpolicy?view=graph-rest-beta), [domain restriction guidance](https://learn.microsoft.com/en-us/entra/external-id/allow-deny-list). |
| Graph completeness/retry | Follow `@odata.nextLink` until exhausted and honor 429 Retry-After; preserve incomplete/error evidence if collection cannot finish. Current get_all_pages has a 100-page cap and no explicit truncated marker; _request has no retry loop. [Paging](https://learn.microsoft.com/en-us/graph/paging), [throttling](https://learn.microsoft.com/en-us/graph/throttling). |
| Exchange mailbox audit | `Get-EXOMailbox` supports `-PropertySets Audit,Minimum` and `-ResultSize Unlimited`. These are read operations but do not by themselves prove authorization, complete population or N/A. [Cmdlet reference](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-exomailbox?view=exchange-ps). |
| Exchange app-only permission | `Exchange.ManageAsApp` plus app role/RBAC assignment and admin consent; reuse approved authentication and validate exact read cmdlet access. Metadata's `Exchange.Manage` label is not a verified application-permission name. Permission grants do not enforce read-only execution. [Microsoft authentication reference](https://learn.microsoft.com/en-us/powershell/exchange/app-only-auth-powershell-v2?view=exchange-ps). |
| SharePoint tenant evidence | Existing PnP integration may use `Get-PnPTenant`. PnP documents access to the tenant administration site and warns that properties may be unavailable. The page does not establish an exact least-privilege app role; app permission/module/property completeness needs security and tenant verification. [PnP reference](https://pnp.github.io/powershell/cmdlets/Get-PnPTenant.html). |
| CIS source | [Official benchmark page](https://www.cisecurity.org/benchmark/microsoft_365) confirms the publisher/source route, not the licensed v6.0.0 procedure. Obtain authorized source/version evidence from the benchmark custodian; do not substitute the repository's v6.0.1 extract. |

## Verification evidence and scope

Run from repository root:

```sh
source ../sandbox-env.sh
git fetch upstream --prune --tags
git status --short --branch
git rev-parse HEAD
git rev-parse upstream/main
git log -5 --first-parent --date=iso --pretty='%h %ad %s'
uv run --project engine --extra dev python docs/compliance/phase-0/verify_baseline.py
uv run --project engine --extra dev pytest engine/tests/test_wiring.py -q
uv run --project engine --extra dev pytest engine/tests -q -rs
git diff --check
```

Observed results:

- Snapshot checks: exit 0; 44/44 explicit resolutions, no duplicate metadata/registry IDs, Appendix A/B explicit ID sets equal; hashes saved.
- Wiring suite: **466 passed, 1 skipped, 1 warning**, exit 0.
- Full engine Python suite: **496 passed, 1 skipped, 1 warning**, exit 0. Skip is the empty orphan-collector parameter set at test_wiring.py:248; warning is the existing Pydantic class Config deprecation.
- Tracked whitespace diff check: exit 0. Final snapshot/document checks also cover these newly created, untracked files.
- Frontend, backend integration, OPA semantics/strict check, Alembic runtime, branch-protection enforcement, production infrastructure and live tenant access were not revalidated in Phase 0. Prior results in Section 3 are historical, not fresh passing claims. OPA was not found on the current PATH.

## Phase 0 acceptance checklist

- [x] Current HEAD and fetched upstream HEAD recorded.
- [x] Open and merged PR counts refreshed; open PR heads captured.
- [x] Every Appendix B row resolves structurally to ready metadata, policy and registered collector.
- [x] Required repository documents and Appendix A read; mismatches documented.
- [x] Confirmed Microsoft/PnP API sources recorded; no permission changes.
- [x] No SOC 2 rating changed; metadata, registry, policies and input plans unchanged.
- [ ] Named GRC approval of result, score, retention and rating ownership decisions (D01–D10 as applicable).
- [ ] Licensed v6.0.0 procedure/source confirmed, particularly for D03 and D09.

The execution plan says, “Do not report a phase complete if ... an external decision is still silently assumed.” This handoff is therefore **blocked at acceptance**, not a Phase 1/2 implementation authorization. No skill creates this approval gate; it comes from execution-plan Sections 4.4 and 8.3 and the human-owned GRC judgment requirement.

## Standard handoff

```text
Phase: 0 — Rebaseline, documentation discovery, and GRC decision locks.
Baseline commit: be241f52beb5ffec10904771bf7cfa4b98233ab0; fetched upstream/main identical.
Branch/commit/PR: docs/soc2-phase-0-rebaseline; local uncommitted files; no PR.
Findings closed: None. Discovery/structural checks completed; remediation findings remain open.
Files changed: Added docs/compliance/phase-0/README.md, DECISIONS.md,
  verify_baseline.py, baseline-2026-09-05.json, pull-requests-2026-09-05.json.
  Preserved both pre-existing untracked planning files; no runtime/control changes.
Decisions made: Preserved plan constraints; D01–D10 are concrete proposals awaiting approval.
Tests run and exact results: Snapshot 44/44 resolutions, exit 0;
  wiring 466 passed/1 skipped/1 warning; engine 496 passed/1 skipped/1 warning;
  tracked whitespace check exit 0. See final verification below.
Security/GRC review required: Named GRC/product/security/privacy/platform owners approve
  relevant D01–D10; confirm benchmark custodian and licensed v6.0.0 procedure.
Known gaps or follow-up work: Benchmark version mismatch; stale manual docs/metadata;
  permission/readiness discrepancies; existing policy/evidence/runtime findings;
  full candidate PR diff review and owner confirmation before implementation.
Next unblocked phase: None until Phase 0's approval gate is satisfied.
  Then Phase 1 and Phase 2 are eligible under the plan, with coordinated separate branches.
```

Appendix C is intentionally unchanged: the plan requests tracker updates through reviewed plan-maintenance PRs, and both input plans predated this work as untracked files. This handoff is the explicit status record until that review occurs.

Final verification: the rerun snapshot matched the saved snapshot exactly, including metadata, registry, all 44 mapped policy digests, Appendix A/B and required-source hashes. All five new files passed JSON parsing where applicable, final-newline/trailing-whitespace checks, and six local-link target checks. The PR inventory contains 45 distinct open IDs and all 22 plan candidates. `git diff --name-only` reported no tracked edits. These checks do not replace the pending human approvals or establish semantic correctness.
