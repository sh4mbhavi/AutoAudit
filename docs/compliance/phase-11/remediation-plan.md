# Phase 11 — remediation plan for conditions 1–7

Companion to [release-decision.md](release-decision.md). That document says
**DO NOT RELEASE** and lists ten conditions. This one is the execution plan for
the seven that need no permission we do not have.

**This file is the source of truth for the remediation work.** It is written to
be executed without the conversation that produced it: every target is named by
file and control id, every step says how it is proven, and every step says which
register row it closes.

- Conditions **8** (branch protection) and **9** (GRC approval, D01–D10, risk
  ownership) are **out of scope here** — 8 needs GitHub admin, 9 needs a named
  human authority. Neither is an engineering task.
- Condition **10** is re-running Phase 11 once 1–7 land.

## Where the work happens

**Not in `AutoAudit-phase-11`.** That worktree is the evidence for the release
decision and its defining property is that it changed no repository source. It
stays pristine.

```
git worktree add -b fix/soc2-phase-11-conditions \
    /Users/clupa/Documents/projects/autoaudit/AutoAudit-remediation 8736fcb9
```

Then overlay the Phase 11 working source exactly as each phase has done, using
the tracked + untracked-non-ignored file set, and **remove any empty directory
the overlay leaves behind** (git does not track directories; this bit Phase 10
and Phase 11 identically — `engine/collectors/_pending/compliance/` is the one
that matters, and `test_phase8_compliance_collectors.py::test_registered_ids`
will tell you if you miss it).

Reproduce the baseline before changing anything:

| gate | expected |
|---|---|
| `engine/tests` | 1938 passed, 1 skipped, 11 xfailed |
| `backend-api/tests tools/tests` | 803 passed |
| `opa test engine/policies engine/tests` | 582/582 |
| `opa check --strict engine/policies` | clean |
| frontend typecheck / test / build | clean / 262 passed / built |

Environment (see [verification.json](verification.json) for the full record):
`OPA_BINARY` = OPA 1.20.2 from `tools/ci/install_opa.py`; `PROMTOOL` = 3.7.3 from
`tools/ci/install_promtool.py`; `AUTOAUDIT_REQUIRE_INTEGRATION=1`;
`MIGRATION_TEST_ADMIN_URL` pointing at a disposable loopback PostgreSQL 16
cluster. macOS caps unix socket paths at 103 bytes, so that cluster's
`unix_socket_directories` must be a short path outside the scratchpad.

## Two decisions needed before W3 and W8

Neither is mine to make and both change the work:

1. **Which `/readiness` survives the merge.** `upstream/main` shipped its own in
   PR #302; this stack has a different one. Keeping both silently shadows one
   (§6 of the decision). This gates W8.
2. **Who integrates `metadata.json` and `registry.py`.** The delivery plan has
   asked for a nominated integrator since Phase 0. Nine open PRs touch the first
   and seven touch the second. This gates W8, and W3 edits `metadata.json`'s
   neighbourhood heavily.

A third is desirable but not blocking: **D03** (zero-resource results) would let
W3 finish the empty-population case rather than leaving it flagged.

## Order, and why

Two orderings are defensible for the upstream merge. **Recommended: integrate
early (W2), not last.** The stack is 96 commits behind and every day of work
widens the gap; upstream's `/readiness` and its new Alembic revision change what
W5 and W6 should be built on; and a 96-commit merge is easier before a large new
diff than after it. The cost is that W2 needs both decisions above up front.

If those decisions are not available, move W8 to the end and accept the rebase.

```
W0  setup + baseline
W1  formatting sweep          ← isolated 221-file mechanical commit, first
W2  upstream integration      ← needs decisions 1 and 2  (or defer to last)
W3  policy correctness        ← the largest workstream
W4  gates and CI
W5  evidence lifecycle + residual security
W6  product surface
W7  documentation and register
W9  re-run Phase 11
```

---

## W1 — Formatting sweep (condition 4a)

**Do this first and commit it alone.** `pre-commit run --all-files` rewrites 221
files; mixing that into semantic commits makes every later diff unreadable.

1. `uvx pre-commit run --all-files` — expect ruff-format, trailing-whitespace and
   end-of-file-fixer to modify ~221 files (+2,812 / −1,547).
2. Fix the **19 ruff errors that have no safe auto-fix**. Bare `ruff check`
   reports 35; 16 carry `[*]` safe fixes that `--fix` applies, leaving:

   | file | rule | n |
   |---|---|---:|
   | `security/evidence_backend/scanner.py` | E402 | 4 |
   | `security/evidence_backend/reportgenerator.py` | E402 | 3 |
   | `engine/legacy/rules-azure/main.py` | E402 | 2 |
   | `engine/GCP/Collector/GCP_IAM_Security_Controls_Collector.py` | E741 | 4 |
   | `security/strategies/application_control.py` | F841 | 2 |
   | `security/strategies/patch_applications.py` | F841 | 1 |
   | `engine/scripts/test_collector.py` | F841 | 1 |
   | `security/strategies/configure_macro_settings.py` | E731 | 1 |
   | `backend-api/app/api/v1/platforms.py` | E712 | 1 |

   **Fix them; do not scope the hook.** Narrowing a hook that also carries
   `detect-secrets` and `detect-private-key` is how coverage is lost later. The
   E402s are deliberate `sys.path` manipulation before imports — `# noqa: E402`
   with a one-line reason is honest there. `platforms.py:26` E712 is live code
   and should be a real fix (`if Platform.is_active:`).
3. The repository has **no `[tool.ruff]` section and no `ruff.toml`**, so the
   rule set is ruff 0.8.0's default. Consider pinning it explicitly — a gate
   whose scope is "whatever the tool defaults to this year" will move under you.
4. Re-run both suites; nothing should change.

**Proves:** `uvx pre-commit run --all-files` exits 0 with no file modified, twice
in a row. **Closes:** P11-OWN-01 (blocking).

## W2 — Upstream integration (condition 6)

Needs both decisions above. `upstream/main` was `75b919d0` at Phase 11, 96
commits ahead of `8736fcb9`.

1. **The duplicate Alembic revision.** Both trees carry revision `2899a0e678b6`
   under different filenames with identical `down_revision`. Alembic *warns and
   loads*, then cannot resolve `head`; `backend-api/entrypoint.sh:5` runs
   `alembic upgrade head` on every container start and fails. Delete one file.
2. **Then author a merge revision** over `b9d4e17c6a52` (this stack) and
   `8a7b91ea95d9` (upstream's control-verification-template revision, whose
   `down_revision` is the same `2899a0e678b6` as this stack's `c4e91a73b620`).
   Without it there are two heads.
3. **Resolve `/readiness`** per decision 1. If upstream's wins, the production
   compose healthcheck at `docker-compose.production.yml:115` loses its per-check
   timeout and its broker check — say so explicitly rather than letting it happen.
4. **`metadata.json` and `registry.py`** per decision 2.
   [collisions.json](collisions.json) has the full per-PR overlap.

**Proves:** `cd backend-api && uv run alembic heads` returns exactly one; clean
database `upgrade head` applies the full chain; both suites green; `git diff` of
`main.py` shows one `/readiness`. **Closes:** P11-OWN-03, P11-OWN-04 (both
blocking), P11-OWN-12, and the integration half of P11-ADV-…-P11-01.

## W3 — Policy correctness (conditions 2 and 3)

The largest workstream. **Do the contract fix and the unknown-evidence fix
together, file by file** — the two lists overlap in eight policies and editing
them twice invites churn.

All paths below are under
`engine/policies/cis/microsoft-365-foundations/v6.0.0/`.

### 3a. `affected_resources` (18 controls)

`OPAResult` (`engine/worker/result_contract.py:21-28`) is
`strict=True, extra="forbid"` with a required `affected_resources: list[Any]` and
no default.

- **Never emit it — every evaluation is rejected (9):**
  `4.1`, `5.1.2.3`, `5.1.3.1`, `5.1.3.2`, `5.1.4.1`, `5.1.4.3`, `5.1.4.4`,
  `5.1.4.5`, `5.1.4.6`.
- **Omit it only from `default result` — rejected exactly when evidence is
  missing or malformed (9):**
  `1.2.2`, `1.3.5`, `2.1.9`, `2.1.12`, `2.1.13`, `2.1.14`, `2.1.15`, `6.5.2`,
  `7.2.5`.

Add the real affected-resource list where the policy computes one, `[]` where it
genuinely has none. **Both the computed result and the `default result` need it.**

### 3b. Unknown evidence must not read as pass or as ordinary fail

| control | defect |
|---|---|
| `1.2.2` | passes on a string (counts its **length** as mailboxes) and on an absent key; records a mailbox of unknown status as an ordinary **fail** |
| `3.1.1` | schema-complete `default result` with `compliant:false` — missing audit-log evidence stored as a tenant fail |
| `2.1.12`, `2.1.13`, `2.1.14` | map their own explicit *unknown* branch onto `compliant:false` |
| `1.3.5`, `7.2.5`, `7.3.1` | store a null (unknown) setting as an ordinary fail |
| `6.3.1`, `6.5.3`, `2.1.8`, `2.1.10` | **pass** on an empty population their collectors fabricate from a null response |
| `v4.0.0/1.3.1` | passes when the domains evidence key is absent entirely |

Pattern for each: type-guard the evidence (`is_array`, `is_boolean`,
`is_object`), and return `compliant: null` (indeterminate) rather than `false`
for anything the tenant did not actually assert. The Phase 2 policies —
`2.1.5`, `2.4.4`, `1.1.1` — are the worked examples already in the tree.

**The genuinely-empty-population case needs D03** and cannot be finished here.
Implement the unambiguous half (type confusion, absent key, null status) and
leave the real-zero case explicitly flagged, the way Phase 2 left `6.1.2`.

### 3c. The two gates that would have caught all of it

1. **A contract gate over every `ready` control**, not only the 44 crosswalked
   ones: evaluate each policy with representative inputs and assert
   `OPAResult.model_validate` accepts the output.
   `engine/tests/test_result_contract.py` today validates hand-written
   dictionaries and never a policy's real output — that is the hole.
2. **Extend semantic coverage from 44 to 69.** `test_crosswalk_semantic_coverage.py`
   is pinned to the Appendix B population by design; the other 25 need their own
   suite rather than a widened crosswalk. 22 of the 69 have no Rego unit test at
   all: `1.3.5`, `2.1.8`, `2.1.9`, `2.1.10`, `2.1.12`–`2.1.15`, `3.1.1`, `4.1`,
   `5.1.2.3`, `5.1.3.1`, `5.1.3.2`, `5.1.4.1`, `5.1.4.3`, `5.1.4.5`, `5.1.4.6`,
   `6.3.1`, `6.5.2`, `6.5.3`, `7.2.5`, `7.3.1`.

Also decide what to do about **v3.1.0 and v4.0.0**, which
`benchmark_reader.list_benchmarks` makes selectable (two `ready` controls each)
and which no phase has verified. Either bring them into scope or stop marking
them ready.

**Proves:** `opa check --strict` clean; `opa test` green with the new cases; the
new contract gate green over all 69; engine suite green. Re-run the exact
demonstrations in [release-decision.md](release-decision.md) §2 and §3 — 5.1.4.5
with `{laps_enabled: true}` must now validate, and the 1.2.2 table must show
`passed / indeterminate / indeterminate / indeterminate / indeterminate`.
**Closes:** P11-OWN-14, P11-OWN-16 (both blocking), P11-OWN-15, and the
adversarial rows F2, F3, F4, F5, F7.

## W4 — Gates and CI (conditions 1b, 4b)

1. **Promote the full-overlay smoke.** [full_overlay_smoke.py](full_overlay_smoke.py)
   starts all six production services with synthetic material — a CA, per-host
   certs with SANs, a Redis ACL whose password the client knows, a real Fernet
   key, a 40-hex `ENGINE_GIT_SHA`, and a `rediss://` URL with verification
   required. Move it into `tools/ci/`, wire it into CI, and let it replace or
   extend `production_overlay_smoke.py`'s two-service scope. **This is what makes
   W2's fix un-regressable.**
2. **`tools/ci/check_alert_metrics.py`** silently drops the expression of any rule
   whose `expr:` key precedes its `alert:` key. Second bypass found in the same
   gate; fix the key-order assumption and add a case for it.
3. **`.github/workflows/pr.preview-deploy.yml`** — dead since Phase 5 and still
   carrying `autoaudit_dev_password`. It sets `APP_ENV=preview`, and
   `config.py:125` returns early only for `dev`, so the validator rejects both
   the password and the plaintext `redis://` and the container exits before
   uvicorn. **Repair or delete it.** Deleting is defensible; leaving a dead
   workflow that publishes a known credential is not.
4. **Scan the API image.** `ci.supply-chain.yml` builds and SBOMs both images and
   scans only the worker. The API image carries 35 Critical / 199 High, one of
   them fixable (`CVE-2026-40962` ffmpeg 5.1.6 via `opencv-python`, fixed in 8.1).
5. **Pin the bases.** `tools/tests/test_phase10_supply_chain.py:71` skips any
   `FROM` containing `python:3.11-slim` — the one base both services run on — and
   inspects only the engine Dockerfile. Remove the exemption, digest-pin both
   bases, extend the gate to `backend-api/Dockerfile`, and replace its
   `pip install uv` (line 18) with the digest-pinned uv image the engine uses.
6. **The PowerShell image** (`engine/powershell/Dockerfile`) installs uv by piping
   a remote script to a shell and installs ExchangeOnlineManagement and
   MicrosoftTeams unpinned. It is the image that runs against a customer tenant
   and no supply-chain gate, SBOM step or scan covers it.
   `test_phase10_supply_chain.py:27` even declares `POWERSHELL_DOCKERFILE` and
   never uses it.
7. **Add an explicit IaC gate.** None exists by name in any of the 18 workflows.
   Current backlog is six LOW `DS-0026` findings, so it can be gating from day
   one.

**Closes:** the second half of P11-OWN-00, P11-OWN-05, P11-OWN-06, P11-OWN-07,
P11-OWN-09, P11-OWN-17, and adversarial rows CI-01, SEC-R1, CD-01, CD-02.

## W5 — Evidence lifecycle and residual security

**Not in the original conditions list, and it should have been:** criteria 6 and
11 are both NOT MET and 11 is blocking. Treat this as condition 3b.

1. **The legal-hold race.** `set_legal_hold` (`evidence.py:1698`) takes
   `SELECT … FOR UPDATE`; `delete_artifact` reads through `_owned_artifact`
   (`evidence.py:437`), a plain `SELECT` that the lock cannot block. Take the
   lock **on the delete side** — that is the side performing the irreversible
   act.
2. **Separation of duties.** The hold endpoint's docstring claims *"the owner
   cannot lift their own"*. Nothing implements it.
3. **Orphaned evidence.** Deleting an artifact leaves an encrypted excerpt in
   `evidence_validation`; `delete_scan` severs evidence from the control it
   proves, unaudited and without consulting `legal_hold`; an approved
   manual-evidence bundle's attachments can be destroyed by the submitter.
   Phase 10's own recorded bypass list is wrong about two of the three paths.
4. **Test the two Phase 10 endpoints.** Setting a legal hold and reading the
   access log have no test anywhere.
5. **`POST /v1/auth/login` has no rate limiting, throttling or lockout.**
6. **`tools/ops/backup.py`** passes the database password in subprocess argv,
   readable from `ps` and `/proc/<pid>/cmdline`. Use `PGPASSWORD` or a passfile.
7. **`docs/GETTING_STARTED.md:163`** publishes `autoaudit_dev_password` as the
   password of a stack the reader has just started — false since
   `docker-compose.yml:39` began requiring an operator-generated value.

**Closes:** P11-OWN-20, and adversarial rows P11-04, F-02, F-03, F-04, F-05,
F-06, F-09, SEC-R2, SEC-R3, SEC-R4.

## W6 — Product surface (condition 5)

1. **Wire the SOC 2 report.** `GET /v1/scans/{scan_id}/soc2-report` exists, is
   covered by 34 backend tests, and **nothing calls it**:
   `frontend/src/types/soc2.ts` types the whole response and
   `frontend/src/api/client.ts` has no `soc2` function. Add the client call and a
   surface a reviewer can reach. Two register rows travel with it: the report is
   **owner-scoped only** (the auditor role that gates cross-owner review
   elsewhere does not apply), and it **carries no identifier for the tenant it
   describes**.
2. **Correct the public copy.** Remove or qualify; do not invent replacements —
   new claims are a product decision, removing untrue ones is not.

   | file | claim |
   |---|---|
   | `Landing/AboutUs.tsx:68` | NIST and ISO 27001 listed as supported standards beside CIS. What exists is `security/strategies/custom_benchmarks.py:83`/`:91` — keyword checkers over an uploaded document, one rule each, in the unmaintained TPRM module |
   | `Contact/components/FAQSection.tsx:43` | "export … in PDF, Excel, or CSV formats", "audit-ready" — no such export exists |
   | `Landing/components/HeroSection.tsx:14` | 99.9% uptime commitment |
   | `Landing/featuresData.ts:27` + five more | "real-time" / "continuous" monitoring — there is no scheduler anywhere in the product |
   | `Contact/components/FAQSection.tsx:33` | 14-day free trial, Premium/Enterprise support plans — no billing, plan or trial system |
   | About page | customer counts; "cut audit preparation time by 80%" |
   | `Evidence.tsx:444` | "Download PDF" downloads a `text/plain` `.txt` |

   The class the plan actually warns about is **clean** and should stay clean: no
   SOC 2 certification or attestation claim exists anywhere outside the phase
   documents. Do not introduce one.

**Closes:** P11-OWN-19, P11-OWN-22, and adversarial rows T-02, T-03, DOC-03,
DOC-04, DOC-05, DOC-06, DOC-11, DOC-12, DOC-13.

## W7 — Documentation and the decision register (condition 7)

1. **Bring `docs/compliance/phase-0/`, `SOC2_EXECUTION_PLAN.md` and
   `soc2-collision-safe-delivery-plan.md` into the branch.** They are cited 62
   times across fourteen files in the Phase 1–10 handoffs and exist in no branch
   that would be merged — they are untracked files in the separate `AutoAudit`
   worktree on `docs/soc2-phase-0-rebaseline`. Every "pending D04 approval" in
   the deliverable currently points at nothing.
2. Correct the documentation rows the adversarial pass found: `README.md`'s
   "rapid automated deployments to the cloud" and its GCP contact routing;
   `workflow-documentation.md`'s CI inventory, which omits the test job and two
   of the seven workflows; the collector README's GraphClient-only contract,
   false for 24 of 50 registered collectors; and the 13 controls whose `service`
   differs between their Rego `METADATA` and `metadata.json`.

**Closes:** P11-OWN-08 and the `19.1.1-F*`, `DOC-07`–`DOC-10`, `CI-02`,
`CI-04`, `CI-05` rows.

## W9 — Re-run Phase 11 (condition 10)

Phase 11 is designed to be repeatable. Re-run it against the remediated stack:
the four checks that found the blockers are the ones that matter —

1. start **all six** production services and require six healthy;
2. evaluate every **ready** policy against `OPAResult`;
3. run `pre-commit run --all-files` the way CI runs it;
4. run the suites from a checkout with no `.git`, with `ENGINE_GIT_SHA` supplied.

Then re-evaluate all thirteen section-19.3 criteria. Criteria 2, 12 and 13 will
still fail without conditions 8 and 9 — that is the point at which the decision
stops being an engineering one.

## Exit criteria for conditions 1–7

- All six production overlay services reach healthy; the worker starts.
- Every `ready` control's output validates against `OPAResult`.
- No policy returns `pass` or ordinary `fail` for evidence the tenant did not
  assert.
- `pre-commit run --all-files` exits 0 twice in a row.
- Exactly one Alembic head after integration with `upstream/main`.
- The SOC 2 report is reachable; no public claim is untrue.
- `docs/compliance/phase-0/` is in the branch.
- Both suites, `opa check --strict`, `opa test`, promtool, all CI gates, and the
  frontend build green — under UTC **and** `Australia/Melbourne`.
- The register's 7 blocking and 27 high rows are closed or explicitly accepted by
  a named owner.
