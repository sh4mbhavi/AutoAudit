# Phase 4 — Semantic coverage and CI gates

Date: 2026-09-05 (Australia/Melbourne).

**Engineering implementation is ready for review; local verification passed.**
Hosted checks, maintainer branch-protection verification and GRC acceptance
remain pending; these are not implied by green local tests.

## Workspace and prerequisites

- Worktree: `/Users/clupa/Documents/projects/autoaudit/AutoAudit-phase-4`.
- Branch: `fix/soc2-phase-4-ci-semantic-gates`; uncommitted and unpushed.
- Base: Phase 1 `8736fcb9`, with all 68 changed/new Phase 3 prerequisite files
  copied byte-for-byte before implementation. Their hashes are in
  [phase-3-snapshot.json](phase-3-snapshot.json). The prior Phase 2 manifest and
  Phase 2/3 handoffs remain available. Files changed again in Phase 4 are identified
  separately in the final Phase 4 change manifest.
- The original, Phase 1, Phase 2 and Phase 3 worktrees are preserved. No tenant,
  deployment, external credential, repository setting or public PR was changed.

Upstream advanced during this session: initial refresh `22adbe41`, final observed
`0bd9b9db4dd973cc617dc7ef2e98a64ee4de58fe`. Since the original `be241f52`, #326
merged critical Grype enforcement; #336 added SharePoint 7.2.2; #344 added
SharePoint 7.2.9, collector fields and a helper-script selector. The scanner
behavior is reused here. The SharePoint additions are outside Appendix B and
were inspected but not silently folded into the uncommitted Phase 1–3 stack.
Rebase/integrate the reviewed stack and rerun all gates before merge; resolve
metadata and shared collector seams explicitly. This branch is not represented
as already based on the new main.

## Coordination review

[coordination-snapshot.json](coordination-snapshot.json) records public PR state
and head SHAs. Candidate diffs were fetched and reviewed without merging:

- #331 remains open: pinned/checksummed full-history Gitleaks is viable, but its
  historical baseline suppressions require owner review and do not establish
  credential revocation. Keep Phase 1 scanner/canary coverage; do not import an
  unapproved historical baseline as part of this patch.
- #326 merged: reuse blocking critical threshold and upload reports after failures.
- #345 remains open: reuse its direct global-admin count cases; missing and
  malformed input now follow Phase 3 indeterminate semantics.
- #355 remains open: reuse the isolated API/mock-session test approach and
  replace localhost manual-verification tests. Its administrator-reset tests
  conflict with Phase 1 and must not be ported. Do not exclude the entire test
  tree from security scanning. PostgreSQL/OPA integration remains mandatory;
  its prior coverage percentage cannot be asserted for this expanded source.
- #356 closed without merge: 5.1.2.3 is outside Appendix B and its missing-setting
  `false` expectation conflicts with Phase 3. No blind cherry-pick.

Owner overlap coordination is still required before merging. No messages were
sent to PR authors, no candidate was closed, and no technical review counts as
GRC approval.

## Implemented scope

Direct semantic tests cover all 44 Appendix B controls, with typed pass, fail,
missing, malformed, boundary, partial and collector-error cases. A structural
coverage check resolves the fixture back to metadata, collector IDs, policy
files and direct policy decision references. Collector contracts cover all 30
unique collector IDs. See [policy coverage](policy-coverage.md) and [collector coverage](collector-coverage.md)
for behavior fixes and coverage details.

The new tests expose and fix deterministic evidence defects, including missing
fields becoming compliant defaults, pagination truncation, malformed envelopes,
and conflicting/inverted policy branches. Missing or incomplete evidence yields
indeterminate/error rather than compliance. Policies keep their validation local
to each captured source file so Phase 3 provenance still evaluates exactly the
retained source with no unrecorded shared module dependency.

The existing 5.1.6.1 collaboration heuristic and 6.1.2 expected action sets remain
subject to D03/D09 GRC review. Conservative missing/malformed/empty handling is
fixed without inventing a new benchmark interpretation. No supplied SOC 2 rating
or organization-level coverage claim changed.

CI now runs all engine tests, strict whole-corpus Rego checks, all semantic Rego tests, all
isolated backend tests, clean/upgrade migrations, real API-to-worker/OPA result
contracts, frontend lint/typecheck/tests/build, and disposable container startup.
Python 3.11 matches API/worker containers; Node 24 matches the frontend container
and supported LTS line. The six old frontend failures and signup handler type
error are repaired. Dependency updates resume with grouped minor/patch changes
and small PR limits.

OPA 1.20.2 CLI downloads verify source-controlled official SHA-256 values before
atomic installation. The worker's OPA stage is pinned to its OCI index digest.
A tampered-download regression proves checksum failures preserve the previous
binary. All affected required workflows run without path exclusions; comment
jobs cannot substitute for tests or call skipped dependencies successful.

[Change control and scanner operations](change-control.md) separates repository
settings from code, documents suppression/emergency ownership and provides a
reviewable minimum branch-protection proposal. Public GitHub says main is
protected; exact enforced checks and bypass rules could not be read (HTTP 401).

## Verification

Use only a disposable loopback PostgreSQL server; fixtures create and drop their
own unique databases. Container smoke tests create their own internal network
and remove their containers, anonymous volumes and network in a finally block.

```sh
python3 tools/ci/install_opa.py /tmp/autoaudit-phase4-tools/opa
export OPA_BINARY=/tmp/autoaudit-phase4-tools/opa
export MIGRATION_TEST_ADMIN_URL=postgresql://postgres@127.0.0.1:55434/postgres
export AUTOAUDIT_REQUIRE_INTEGRATION=1
uv run --frozen --project engine --extra dev python -m pytest engine/tests -q
uv run --frozen --project backend-api --extra dev --extra evidence python -m pytest backend-api/tests tools/tests -q
"$OPA_BINARY" check --strict engine/policies
"$OPA_BINARY" test engine/policies engine/tests
npm exec --yes --package=node@24 -- npm --prefix frontend test
npm exec --yes --package=node@24 -- npm --prefix frontend run typecheck
npm exec --yes --package=node@24 -- npm --prefix frontend run lint
npm exec --yes --package=node@24 -- npm --prefix frontend run build
python3 tools/ci/container_smoke.py
git diff --check
```

- Full engine: **1,065 passed, 1 skipped**. This includes 296 new collector cases
  and 133 crosswalk/collector-to-OPA tests. The one structural skip predates this
  phase. Real PostgreSQL integration ran; its absence is not hidden by skips.
- All backend and tool tests: **75 passed**, including clean/upgrade migrations,
  real app startup, manual-verification authorization, serialized API-task-worker
  contract, checksum-tamper and actual pytest-command prerequisite canaries.
- Whole-corpus strict OPA check passed; **550/550 semantic Rego tests passed**.
  After synthetic fixture naming cleanup, 133 crosswalk cases and 550 Rego tests
  passed again; no production behavior changed in that cleanup.
- Node 24 frontend: **232 passed across 24 files**; typecheck, lint and build
  passed. The agent also reproduced the original Node 20 failures before repair
  and verified all 232 tests under Node 20 afterward. Node 24 is the supported
  target ([Node release lifecycle](https://nodejs.org/en/about/previous-releases)).
- API and worker images rebuilt from the final production source; actual API
  entrypoint migrations/liveness and actual Celery startup/broker ping passed.
  Runtime containers had no published ports and used synthetic ephemeral secrets.
- Actionlint **1.7.12** passed on all six changed/new workflows. Bandit **1.8.6**
  passed on backend application and test code; ordinary pytest assertions are
  exempt only in tests, and fixed subprocess/synthetic SQL findings carry narrow
  reviewed `nosec` annotations. Test files are not excluded wholesale.
- Grype **0.118.0** scanning a clean-source snapshot: exit **0**, **0 critical,
  51 high, 49 medium, 12 low**. Existing lower-severity findings remain. A
  synthetic log4j-core 2.14.1 SBOM canary produced two critical findings and exit
  **2**, proving the critical threshold fails. No Grype suppression was added.
- All eight pre-commit hooks passed on Phase 4 changed/new files. Four hashed
  secret-scanner false positives were marked non-secret in the existing baseline:
  synthetic banned-password policy configuration and malformed test values in
  the JSON/Rego fixtures. No historical baseline entries were removed, and no
  file-wide scanner exclusion was added. Baseline validation used a temporary
  Git index so the real index remains unstaged.
- Existing warnings remain: Pydantic/Swig deprecations, ten frontend lint warnings,
  jsdom scrollTo notices and the frontend large-chunk advisory. None is reported
  as a new failing gate.

The individual CI commands match these test surfaces. Hosted GitHub execution
and the existing CodeQL/Super-Linter jobs have not been claimed as locally
executed. No workflow run or mergeability canary PR was published here.

## Remaining acceptance

The code can be reviewed locally. Phase 4 production/change-control acceptance
remains blocked on a maintainer publishing the reviewed stack, verifying green
hosted checks, inspecting/combining existing branch requirements, and proving a
failing test PR cannot merge normally. GRC approvals from earlier phases remain
pending. The code patch does not claim those external steps are complete.

Phase 5 runtime trust boundaries remain separate: queued credential minimization,
exact read-only operation APIs, service authentication and cookie/CSRF work are
not closed by these mocked contract and CI tests.


## Standard handoff

- **Phase:** 4 — local engineering implemented and reviewed; hosted/GRC acceptance pending.
- **Baseline:** Phase 1 `8736fcb9` plus exact 68-file Phase 3 snapshot; upstream
  observed at `0bd9b9db`. The stack still needs reviewed integration with main.
- **Branch/commit/PR:** `fix/soc2-phase-4-ci-semantic-gates`; uncommitted/unpushed;
  no PR created.
- **Findings addressed:** CI-01 local suites/startup/semantic gates; CI-03 pinned
  OPA, critical scanner behavior and dependency automation. CI-02 enforcement
  remains a maintainer verification item. No SOC 2 rating is changed.
- **Files changed:** [Phase 4 change manifest](phase-4-changes.json) distinguishes
  Phase 4 hashes from the prerequisite source. Source changes cover 39 v6
  policies, one v4 unused-argument fix, collectors, tests, frontend repairs,
  workflow/tooling and review documentation; no new migration body is introduced.
- **Decisions:** preserve Phase 3 null/error semantics; validate before filtering
  evidence; test captured source; retain D03/D09 interpretation caveats; require
  real CI prerequisites; use supported Node 24 and matched Python 3.11; reuse
  merged critical threshold and existing CODEOWNERS team.
- **Tests:** exact commands/results above and [verification record](verification.json).
- **Security/GRC review:** earlier GRC decisions remain pending. A repository
  maintainer must reconcile the proposed checks with actual current protection,
  confirm hosted green runs and demonstrate normal merges reject a failing PR.
- **Known gaps:** lower-severity dependency findings, no real M365 tenant smoke,
  historical incident/credential actions, later-phase runtime/evidence/lifecycle
  controls and current-main integration. Mocked contracts are not live API proof.
- **Next work:** Phase 5 runtime trust boundaries can be implemented locally;
  production release still depends on the pending reviews and change-control proof.
