# Phase 11 — Final verification and audit-readiness release

Date: 2026-09-07 (Australia/Melbourne).

**The decision is DO NOT RELEASE.** It is recorded, with its evidence, in
[release-decision.md](release-decision.md). This phase changed no repository
code: plan section 19.5 says *"do not implement unrelated fixes during final
verification"*, and every defect found is written into
[risk-register.json](risk-register.json) with a stated remedy rather than
repaired. No public PR, production service, external tenant, credential or
repository setting was touched.

## Baseline and workspace

- Worktree: `/Users/clupa/Documents/projects/autoaudit/AutoAudit-phase-11`.
- Branch: `fix/soc2-phase-11-final-verification`; uncommitted and unpushed.
- Git base: Phase 1 `8736fcb9`, overlaid with the complete Phase 10 working
  source. [phase-10-snapshot.json](phase-10-snapshot.json) records SHA-256 for
  all **1,004** prerequisite files; the overlay verified byte-identical — 0
  mismatches, 0 extra files — and `git status` compared entry-for-entry against
  the Phase 10 worktree before any Phase 11 work. Every earlier worktree is
  preserved and untouched.
- Phase 10's recorded results were reproduced first: engine 1,938 passed / 1
  skipped / 11 xfailed; backend and tools 803 passed; `opa check --strict`
  clean; `opa test` 582/582.
  - One step was needed, identical to the one Phase 10 recorded when overlaying
    Phase 9: git does not track directories, so the file-level overlay left
    `engine/collectors/_pending/compliance/` behind as an empty directory, and
    `test_phase8_compliance_collectors.py::test_registered_ids` correctly failed
    on it. Removing the empty directory reproduced the result exactly.
- **Upstream moved a third time.** Phase 9 recorded `bfb8edd4`, Phase 10
  `0a074cc9`; it is now `75b919d0`, **96 commits** ahead of the stack base.
  [coordination-review.md](coordination-review.md) has the detail.

## What a verification phase is for

Ten phases of engineering produced a stack whose gates are green and whose
discipline is unusually good. Phase 11 re-ran all of it and it is still green.
The value of this phase is not in the re-run: it is in the four checks nobody had
run yet, each of which found something the green gates could not see.

| The check nobody had run | What it found |
|---|---|
| Start **every** service in the production overlay | The topology cannot run a scan. Two of six services never start. |
| Evaluate the **ready** policies against the engine's own result contract | Eighteen of sixty-nine can emit a result the contract rejects. |
| Run the CI gate the way CI runs it (`--all-files`) | It cannot pass, and re-running does not help. |
| Run the suites from a checkout that is **not** a git worktree | 21 tests depend on an engine identity no test fixture establishes. |

Each was invisible to every prior phase for the same structural reason: the check
that would have caught it was scoped narrower than the thing it was protecting —
two services instead of six, forty-four policies instead of sixty-nine,
sixty-three files instead of all of them, one execution environment instead of
two.

## The production topology cannot run a scan

`tools/ci/production_overlay_smoke.py` starts `db` and `redis`, and says so in
its docstring: the other services *"need reviewed application secrets and, in the
PowerShell case, tenant certificates."* Tenant certificates are needed to
**scan**, not to **boot**. So Phase 11 generated a complete set of synthetic
material — a CA, per-host certificates carrying SANs, a Redis ACL whose password
the client knows, a real Fernet key, a well-formed 40-hex engine revision and a
`rediss://` URL with verification required — and started all six.

Four came up:

```
db                   running   healthy   restarts=0
redis                running   healthy   restarts=0
backend-api          running   healthy   restarts=0
dispatcher           running   healthy   restarts=0
powershell-service   restarting  unhealthy  restarts=10
worker               created   (never started)
```

`engine/powershell/service/main.py:63` is
`_EXECUTION_POOL: ThreadPoolExecutor | None = None` at module scope with no
`from __future__ import annotations`. The image's Python is **3.9.19**, where a
module-level annotated assignment evaluates its annotation at runtime, so PEP 604
`X | None` raises `TypeError` and uvicorn cannot import the app. The `worker`
declares `depends_on: powershell-service: {condition: service_healthy}`, so it
never starts. **No worker means no Celery consumer, and every scan a user creates
sits in the outbox for ever.**

Introduced by **Phase 9** with the `POWERSHELL_MAX_CONCURRENCY` execution pool —
absent from phases 1–8, from the base commit and from upstream, present in 9 and
10. It survived because nothing starts or imports that module:
`runtime_powershell_smoke.py` exercises the *local Docker transport* in
`collectors/powershell_client.py`, not the HTTP service, and no test in
`engine/tests`, `backend-api/tests` or `tools/tests` imports it.

One line fixes it, and that was verified rather than assumed: with the
future-import added, the module imports cleanly under the image's own 3.9.19.

The rest of the run is good news, and worth stating: only the API publishes a
host port; `db`, `redis`, `powershell-service` and `dispatcher` publish none; and
`/readiness` answered
`200 {"status":"ready","checks":{"database":{"ok":true,"detail":"ok"},"broker":{"ok":true,"detail":"ok"}}}`
against a production-configured PostgreSQL and a TLS-authenticated Redis. Phase
10's readiness endpoint works exactly as designed, in the topology it was written
for.

## Eighteen ready controls can emit a result the contract rejects

`OPAResult` requires `affected_resources`, with `strict=True`, `extra="forbid"`
and no default.

- **Nine** ready v6.0.0 policies never emit it at all, so **every** evaluation is
  rejected — 4.1, 5.1.2.3, 5.1.3.1, 5.1.3.2, 5.1.4.1, 5.1.4.3, 5.1.4.4, 5.1.4.5,
  5.1.4.6.
- **Nine more** emit it in their computed result and omit it from their
  `default result`, so they are rejected **exactly when the default fires** — on
  missing or malformed evidence — 1.2.2, 1.3.5, 2.1.9, 2.1.12, 2.1.13, 2.1.14,
  2.1.15, 6.5.2, 7.2.5.

Demonstrated with the pinned OPA 1.20.2 against 5.1.4.5, given valid **compliant**
evidence:

```
policy output: {"compliant": true, "message": "... LAPS ... is enabled", "details": {...}}
OPAResult:     ValidationError - affected_resources Field required
```

`opa_client.py:159` converts that to
`ValueError("OPA returned an invalid result contract")`, and `tasks.py:941`
records `EvaluationFailure("evaluation_error")` with
`provenance_status="incomplete"`. **The engine's handling is correct** — the
error is never flattened into a pass or an ordinary fail, which is exactly what
Phase 3 built it to do. The controls are simply unassessable whenever evaluation
is reached, while `metadata.json` advertises them as ready and the API lets a
user select them.

The second group is the harder one to reason about: those controls work on the
happy path and become contract-invalid precisely on the unknown-evidence path, so
the defect surfaces only once something else has already gone wrong.

The reason it shipped is a coverage boundary, and it is worth naming precisely.
The v6.0.0 surface is three nested circles:

| | controls |
|---|---:|
| marked `ready` in `metadata.json`, selectable in the product | **69** |
| with a Rego unit test referencing their package | **47** |
| with end-to-end crosswalk semantic **and** collector-contract coverage | **44** |

`test_crosswalk_semantic_coverage.py` exercises exactly the 44 the SOC 2
crosswalk references (47 points of focus). The **25** ready controls outside the
crosswalk have no end-to-end coverage, and **22** have no Rego unit test at all —
1.3.5, 2.1.8, 2.1.9, 2.1.10, 2.1.12–2.1.15, 3.1.1, 4.1, 5.1.2.3, 5.1.3.1,
5.1.3.2, 5.1.4.1, 5.1.4.3, 5.1.4.5, 5.1.4.6, 6.3.1, 6.5.2, 6.5.3, 7.2.5, 7.3.1.
`test_result_contract.py` validates `OPAResult` against hand-written
dictionaries, never against a policy's real output. `opa test` reporting 582
passing tests reads as dense coverage; the tests are concentrated in 47 policies.

And the scope is wider than the programme's. `benchmark_reader.list_benchmarks`
enumerates every version directory, so **v3.1.0 and v4.0.0** — two `ready`
controls each — and the `essential-eight` family are selectable through the API.
Eleven phases have verified v6.0.0 and nothing else.

## Unknown evidence reads as a pass, unknown status reads as a failure

CIS 1.2.2 does `object.get(input, "shared_mailboxes", [])` with no type check,
and its unknown-status branch resolves to `compliant: false`. Every case
evaluated with the pinned OPA and then validated against the engine's own
contract:

| input | compliant | contract | recorded as |
|---|---|---|---|
| valid list, all disabled | true | accepted | passed ✓ |
| `{"shared_mailboxes": "oops"}` | true | accepted | **passed** |
| `{}` — key absent | true | accepted | **passed** |
| `{"shared_mailboxes": null}` | false | rejected | evaluation_error |
| `[{"account_disabled": null}]` | false | accepted | **failed** |

A string produces **no bindings at all** for `some mailbox in shared_mailboxes` —
Rego does not iterate a string's characters — so both comprehensions are empty
and the guarded body succeeds. `count(shared_mailboxes)` then counts the string's
**length**, writing *"Sign-in is blocked for all 4 shared mailbox(es)"* into the
audit record for four mailboxes that do not exist. Separately, a mailbox whose
`account_disabled` the collector could not determine is recorded as an ordinary
tenant **failure**, not as indeterminate.

The explicit-`null` case is the only one that behaves correctly, and only by
accident: its `default result` omits `affected_resources`, so the contract
rejects it and it becomes an error rather than the tenant failure its own message
describes.

The crosswalk's own `residual_limitation` for point CC6.3-P11 already reads
*"Empty-evidence behavior must be corrected."* It is still uncorrected, and 1.2.2
is one of the 25 controls the crosswalk suite does not reach.

## A gate this programme added cannot pass

`ci.supply-chain.yml`'s `hooks` job runs
`pre-commit run --all-files --show-diff-on-failure`. Run that way on a pristine
committed copy of this stack:

- the **first pass modifies 221 files** (+2,812 / −1,547) through `ruff-format`,
  `trailing-whitespace` and `end-of-file-fixer`;
- a **second pass modifies nothing and still fails** — `ruff` reports **19
  errors with no *safe* auto-fix** (E402 ×9, E741 ×4, F841 ×4, E731, E712) in
  `security/` (11), `engine/` (7) and `backend-api/app/api/v1/platforms.py` (1).
  Six carry unsafe fixes that ruff will not apply without `--unsafe-fixes`.

`detect-secrets` and `detect-private-key` both pass. Most of the rest is
inherited repository debt rather than Phase 10's code — but the gate runs
`--all-files`, so it is red on the first pull request and stays red. Phase 10
verified it against only the 63 files it changed.

## The clean-checkout run, and what it found

Plan item 19.1.4 asks for the gates from a clean checkout. Every phase to date
ran them inside a git worktree carrying `.venv`, `__pycache__` and
`node_modules`. Phase 11 exported exactly the tracked plus untracked-non-ignored
source set — **1,006 files, digest-verified, no `.git`** — and ran everything
there from scratch.

`uv sync --frozen` resolved for both projects, `npm ci` succeeded, and the
frontend typecheck, 262 tests, build and lint all passed. The Python suites did
not: **19 engine failures, and 2 more across `backend-api/tests` and
`tools/tests`**, all from one cause.
`engine/worker/provenance.py:68 engine_identity()` falls back to
`git rev-parse HEAD` and raises when neither that nor `ENGINE_GIT_SHA` nor
`ENGINE_IMAGE_DIGEST` is available; `tasks.py:1001` turns that into
`EvaluationFailure("provenance_unavailable")`. Supplying `ENGINE_GIT_SHA`
restores the exact worktree result — 1,938 passed / 1 skipped / 11 xfailed — and
leaves one failure, `tools/tests/test_secret_scanning.py::test_tracked_examples_pass`,
which shells out to `git ls-files`.

The *runtime* does declare this: `engine/worker_entrypoint.sh:6` calls
`engine_identity()` before starting Celery, and Phase 3's handoff documents the
identity sources. The gap is narrower than it first looked, and is in the **test
environment**: no suite supplies an identity fixture or a preflight, so ten
phases of green runs all silently depended on being inside a git worktree. CI's
`actions/checkout` provides `.git`, so no CI job is affected today.

## Supply chain: the first image scan this programme has run

`ci.supply-chain.yml` builds the worker **and** the API image, generates a
CycloneDX SBOM for both, and passes only the worker to its vulnerability scan.
Its comment cites *"the pre-existing backlog recorded in earlier phases (0
critical, 51 high, 49 medium)"* — which is Phase 4's and Phase 5's source
**directory** scan. No phase has ever scanned an image.

Phase 11 did:

| image | Critical | High | Medium |
|---|---:|---:|---:|
| worker | 24 | 111 | 117 |
| **API (never scanned by CI)** | **35** | **199** | **179** |

Every worker Critical is a Debian base-image glibc or perl CVE marked `wont-fix`
upstream, so leaving that scan non-gating is the right call. But one API Critical
**is** fixable — `CVE-2026-40962 ffmpeg 5.1.6`, bundled inside `opencv-python`,
fixed in 8.1 — and so are Highs in `cryptography` (48.0.0 → 48.0.1), `urllib3`,
`pyjwt` and CPython itself. `cryptography` is the library that encrypts stored
M365 client secrets.

Two further gaps in the same area:

- `test_engine_base_images_are_digest_pinned` **skips any `FROM` line containing
  `python:3.11-slim`** — the one base image both services actually run on — and
  inspects only the engine Dockerfile. `backend-api/Dockerfile` is single-stage,
  uses the floating base, and installs uv with an unpinned `pip install uv`,
  which `engine/Dockerfile`'s own comment already calls out by name.
- `engine/powershell/Dockerfile` — the image that executes against a customer
  tenant — installs uv by **piping a remote script to a shell** and installs
  ExchangeOnlineManagement and MicrosoftTeams unpinned from PSGallery. It is
  built by no supply-chain gate, SBOM'd by nothing and scanned by nothing.

And one absence: **no IaC scanner is invoked by name in any of the 18 workflow
files** — no checkov, tfsec, kics, terrascan or hadolint — which plan item
19.1.13 requires. Phase 11 ran `trivy config` as the substitute and found only
six LOW `DS-0026` findings, so the gate could be turned on gating from day one.
(Super-Linter runs in `ci.backend-api.yml`, and what it bundles was not verified
from here, so this is an absence of an *explicit* IaC gate.)

SAST coverage is **better than it first appeared**, and this phase got it wrong
before Codex refuted it. `ci.security.yml` is path-filtered to `security/**`, but
it is not the repository's only CodeQL workflow: `ci.backend-api.yml:36-43`,
`ci.engine.yml:31-37` and `ci.frontend.yml:31-38` each run
`codeql-action/init` and `analyze` on every pull request to `main` **with no path
filter**. The finding was withdrawn in full. bandit does still cover only
`backend-api/app` and `backend-api/tests`, so Phase 11's sweep of `engine/` was
the first (0 High, 2 Medium — both verified false positives — 23 Low over 11,532
lines).

## Public claims: two that are false, and one class that is clean

Plan item 19.1.14. Two claims are live on the public site and are not true of the
product:

- `AboutUs.tsx:68`, under *"Industry Standards We Support"*, lists **NIST
  Framework** and **ISO 27001** beside CIS and the Essential Eight as if the four
  were equivalent. `engine/policies/` holds only
  `cis/microsoft-365-foundations` and `essential-eight`; there is no NIST or ISO
  27001 policy, collector, metadata record or benchmark, and `GET /v1/benchmarks`
  cannot return one. What *does* exist — and this phase missed it until Codex
  refuted the blanket claim — is `security/strategies/custom_benchmarks.py:83`
  and `:91`: keyword checkers over an uploaded document, **one rule each**
  (`NIST-IR`, `ISO-A.9`), inside the unmaintained TPRM module. Two of the four
  entries are a 140-control automated benchmark; the other two are a keyword
  search of a file the customer supplies.
- `FAQSection.tsx:43` promises *"comprehensive compliance reports in PDF, Excel,
  or CSV formats"* that are *"audit-ready"*. No PDF, spreadsheet or CSV
  generation exists in `backend-api/app`; the report surfaces are a JSON endpoint
  and a stored evidence object. Four further pages carry audit-readiness wording,
  including a hero promising *"Export audit-ready documentation instantly"*.

The class the plan actually warns about is clean. **No SOC 2 certification or
attestation claim exists anywhere outside the phase documents** — a search of
`README.md`, `SECURITY.md`, `docs/` and the whole frontend finds SOC 2 only as a
report contract and its types. Phase 10 corrected the infrastructure claims
(a `staging` branch, Docker Hub, GCP Cloud Build, Helm/AKS) and those corrections
hold.

## The decision register is not in the deliverable

Phase 0's decisions **D01–D10** are cited **62 times across fourteen files** in
the Phase 1–10 handoffs — D03 for zero-resource results, D04 for retention, D05 for redaction,
D06 for crosswalk ownership, D08 for public SOC 2 wording. They exist in **no
branch that would be merged**: `docs/compliance/phase-0/`,
`SOC2_EXECUTION_PLAN.md` and `soc2-collision-safe-delivery-plan.md` are untracked
files in a *different* worktree.

A reviewer opening this branch reads "pending D04 approval" and finds no D04, and
no execution plan to measure the work against.

## What the adversarial pass added

Fourteen independent verifiers ran over the integrated stack and produced 93
candidate findings; each then faced three refuters with distinct lenses — code
truth, test-and-config truth, scenario reachability — every one defaulting to
REFUTED. **71 survived.** Eight duplicated a finding Phase 11 had already
verified directly and were folded into it. The full set is in
[risk-register.json](risk-register.json); the ones that changed the decision:

- **§3 is a pattern, not one bad policy.** CIS 3.1.1 stores missing audit-log
  evidence as a tenant **fail**; 2.1.12, 2.1.13 and 2.1.14 map their own explicit
  *unknown* branch onto `compliant: false`; 1.3.5, 7.2.5 and 7.3.1 store a null
  setting as an ordinary fail; 6.3.1, 6.5.3, 2.1.8 and 2.1.10 **pass** on an empty
  population their collectors fabricate from a null response; and v4.0.0's 1.3.1
  records a **pass** when the evidence key is absent. Every one is among the 25
  ready controls the crosswalk does not cover.
- **`pr.preview-deploy.yml` has been dead since Phase 5.** It sets
  `APP_ENV=preview`, and `config.py:125` returns early only for `dev`, so the
  validator runs: `autoaudit_dev_password` fails the strength check and
  `redis://redis:6379` fails the TLS requirement, `Settings()` raises at import,
  `alembic/env.py` fails, and the container exits under `set -e` before uvicorn.
  It is byte-identical across every phase snapshot since Phase 7 — and it is
  where the last known default credential lives.
- **Phase 10's alert-metric gate has a second bypass.**
  `check_alert_metrics.py` silently drops the expression of any rule whose
  `expr:` key precedes its `alert:` key, so those metric names are never checked.
- **Evidence is destructible in more ways than Phase 10 recorded.** Deleting an
  artifact leaves an encrypted excerpt of the same evidence in
  `evidence_validation`; an approved manual-evidence bundle's attachments can be
  destroyed unilaterally by the submitter; `delete_scan` severs evidence from the
  control it proves, unaudited; the hold endpoint's stated *"the owner cannot
  lift their own"* is not implemented; and Phase 10's own recorded bypass list is
  inaccurate about two of the three paths it names. Neither of Phase 10's two new
  evidence-lifecycle endpoints has a test anywhere.
- **`POST /v1/auth/login` has no rate limiting, throttling or lockout.**
- **More public copy that is not true:** a 99.9% uptime commitment, "real-time"
  and "continuous" monitoring on six surfaces for a product with no scheduler, a
  14-day free trial and Premium/Enterprise support plans with no billing system,
  and customer counts for a product with no production deployment.

The refuters also did the opposite job, which is the half that makes the number
mean something. They rejected the claims that the absence of GRC approval and the
absence of risk owners are *defects* — correctly, since both are externally
blocked and repeatedly recorded as such — and rejected "no evidence-pack
generator exists" and "no scan is re-derivable from provenance" as overstated.
Those are carried as unmet criteria and as a documented break in the traceability
chain, not as defects. They also disagreed with each other on how many policies
break the `affected_resources` contract, offering 20 and 12; Phase 11 counted it
directly and Codex reproduced the count.

## What is genuinely ready

Every gate is green, and this deserves to be said plainly rather than buried
under the findings.

Engine 1,938 passed / 1 skipped / 11 xfailed. Backend and tools 803 passed.
`opa test` 582/582, `opa check --strict` clean. promtool: 17 rules, unit tests
SUCCESS. The alert-metric, organizational-register, control-status, promotion and
API-type gates all clean. Frontend typecheck, 262 tests, build and lint clean.
`git diff --check` clean. Bandit clean on `backend-api/app`.

Both suites were re-run in full against a **second PostgreSQL cluster at
`Australia/Melbourne`** and are identical to the UTC results.

`container_smoke.py` PASS. `production_overlay_smoke.py` PASS.
`runtime_tls_smoke.py` PASS — anonymous, wrong-password, untrusted-CA and
plaintext Redis connections all rejected. `runtime_powershell_smoke.py` PASS —
real PowerShell, clean JSON, containers removed, no tokens in argv.

Exactly one Alembic head. A clean-database `upgrade head` applies the full chain
and is idempotent; prior-head upgrades are tested. Downgrades deliberately refuse
with *"forward-only; restore from a verified backup instead"* — coherent for an
audit-evidence schema, and Phase 10's restore is tested.

**Immutability is enforced by the database, not by application code**: Phase 3
terminal-result and scan-input triggers, Phase 7 append-only audit and manual
revision triggers, Phase 8 append-only drift triggers.

**The crosswalk is clean.** An independent check of `mapping.json` against
Appendix A and Appendix B raised no finding across 24 verified assertions.

**Traceability holds for five of its six links** — see
[traceability-trace.md](traceability-trace.md). Report → mapping → result →
policy → collector → provenance all resolve unaided, and `policy_source` stores
the evaluated Rego verbatim so a reviewer can re-run the exact policy. The break
is the sixth: only the input **digest** is stored, so what a judgement was made on
cannot be recovered without re-collecting from the live tenant — a different
point in time, and therefore a different fact.

## Acceptance criteria

[acceptance-criteria.json](acceptance-criteria.json) evaluates all thirteen of
section 19.3 individually, with evidence for each. **Six are not met** — 2
(enforced checks), 6 (a known credential remains), 7 (unknown results appear as
pass and as ordinary noncompliance), 11 (evidence ownership and retention), 12
(GRC approval) and 13 (owned risks) — and five of those block. Two more are met
only conditionally: criterion 3 (one Alembic head) holds for this stack alone and
fails on integration, and criterion 5 asks only about the 44 crosswalked policies
and cannot see the other 25.

## Independent review

**Codex was available for the first time in five phases.** Phases 7, 8, 9 and 10
each recorded it rate-limited and substituted Gemini; Phase 10's handoff said
outright that four consecutive phases was not an accident and that this stack
should get an independent human or Codex review before merge. It got one.

Codex was given fourteen of Phase 11's own claims across three rounds, prompted
to refute by default. It **confirmed eight, refuted five as written, and one of
those was withdrawn outright.** The refutations are the valuable half:

- **Refuted:** *"nothing declares or asserts"* the engine-identity precondition.
  It does — `engine/worker_entrypoint.sh:6` calls `engine_identity()` before
  starting Celery, and Phase 3's handoff documents the identity sources. The
  accurate finding is narrower and lives in the test environment; severity
  reduced from high to medium.
- **Refuted:** *"no phase has verified"* the older CIS versions and the Essential
  Eight. `test_wiring.py:66` enumerates all metadata structurally, the Essential
  Eight family has semantic Rego tests, and `test_phase7_soc2.py:386` exercises
  v3.1.0 scan behaviour. The accurate finding is incomplete semantic coverage,
  not zero verification; severity reduced from high to medium.
- **Corrected:** the CIS 1.2.2 mechanism. Rego produces **no bindings** for
  string membership rather than iterating four characters; the fabricated "4"
  comes from `count()` over the string's length on a different line. The observed
  false pass is unchanged, and Codex reproduced it — including under the worker's
  `--strict-builtin-errors`.
- **Corrected:** *"on any input"* for the contract-broken controls. A collection
  failure or non-object evidence fails those controls earlier, for a different
  reason, without reaching the policy. The accurate statement is *whenever
  evaluation is reached*.
- **Withdrawn outright:** *"CodeQL is not a pull-request gate for anything
  outside `security/`"*. `ci.backend-api.yml`, `ci.engine.yml` and
  `ci.frontend.yml` each run `codeql-action/init` and `analyze` on every pull
  request to `main` with no path filter. The finding was wrong and is recorded as
  withdrawn in the register rather than deleted.
- **Refuted:** *"the product implements neither NIST nor ISO 27001"*.
  `custom_benchmarks.py:83` and `:91` register keyword checkers for both,
  reachable through the evidence strategy resolver — one rule each, in the
  unmaintained TPRM module. Restated to say exactly that; severity high → medium.
- **Corrected:** *"merged, Alembic refuses to load the versions directory"*.
  `alembic/script/revision.py:212` warns on a duplicate revision id and loads
  anyway; the failure is at **head resolution** on the combined graph, which
  Codex reproduced in memory. `alembic upgrade head` still fails, and with it
  `entrypoint.sh:5`.

It confirmed the rest, reproducing all nine always-invalid contract failures
under OPA 1.20.2 and the 19 ruff errors under ruff 0.8.0 independently, and added
one finding of its own: `tools/tests/test_phase10_supply_chain.py:27` declares
`POWERSHELL_DOCKERFILE` as a constant and no test in the file ever uses it. It
also declined to over-claim on my behalf — noting that keyword absence cannot
prove no IaC scanner runs, since Super-Linter's bundled linters were not
verifiable from here, and that it could not check plan item 19.1.13's exact
wording **because the execution plan is not in this branch**, which is the
decision-register finding demonstrating itself.

Gemini reviewed the same headline claims in parallel and confirmed the PEP 604
mechanism, the `OPAResult` contract path (finding no normalisation between the
OPA output and `model_validate`), and both supply-chain gaps.

Full record in [review.json](review.json).

## Standard handoff

- **Phase:** 11 — final verification complete; **release refused**. Six of the
  thirteen section-19.3 criteria are not met, five of them blocking, and
  [risk-register.json](risk-register.json) carries **85 open risks — 7 blocking,
  27 high — none with an owner, a due date or a documented acceptance**, plus one
  finding this phase withdrew after review refuted it.
- **Baseline:** `8736fcb9` plus the exact 1,004-file Phase 10 prerequisite
  snapshot. `upstream/main` has moved to `75b919d0`, 96 commits ahead, and this
  branch is not based on it.
- **Branch/commit/PR:** `fix/soc2-phase-11-final-verification`;
  uncommitted/unpushed; no PR.
- **Files changed:** no repository source. Phase 11 adds only
  `docs/compliance/phase-11/`.
- **Decisions:** verify and record rather than repair, per section 19.5; run the
  full production overlay with synthetic material rather than accept the shipped
  smoke's two-service scope; keep the full-overlay harness as a phase artifact
  rather than add it to `tools/ci/`; leave every risk-register row unowned rather
  than assign an owner no one has agreed to be.
- **Security/GRC review required:** everything in
  [release-decision.md](release-decision.md) §6, plus the eight conditions for
  reconsidering.
- **Next unblocked work:** [remediation-plan.md](remediation-plan.md) is the
  execution plan. Conditions 1–7 of the release decision are engineering
  or documentation and can start immediately — the first is a one-line fix.
  Conditions 8 and 9 need a repository administrator and a GRC owner and cannot.
  Phase 11 is re-runnable once 1–7 land.
- **Since executed.** [remediation-report.md](remediation-report.md) records what
  happened to conditions 1–7 on `fix/soc2-phase-11-conditions`: all four blockers
  closed, three of the six unmet criteria now met, and what remains reduced to
  two decisions and two permissions.
