# Phase 11 — coordination and integration review

Date: 2026-09-07 (Australia/Melbourne). Read-only: no PR, branch, label, review
or repository setting was created or changed. The GitHub account available to
this phase (`sh4mbhavi`) holds `pull`, `push` and `triage`, and neither `admin`
nor `maintain`.

## Upstream has moved a third time

| Recorded at | `upstream/main` |
|---|---|
| Phase 9 | `bfb8edd4` |
| Phase 10 | `0a074cc9` |
| **Phase 11** | **`75b919d0`** |

`upstream/main` is now **96 commits** ahead of the stack base `8736fcb9`. Merged
since Phase 10 recorded `0a074cc9`: PRs **#331** (full-history gitleaks CI),
**#329** (baseline security audit), **#302** (readiness endpoint), **#358**
(import sorting in `main.py`) and **#229** (control verification templates).

Two of those land directly on top of this stack.

### PR #302 merged a competing `/readiness`, and PR #361 is now conflicting

Phase 10 recorded that **PR #361** creates the same `health.py` and the same
`/readiness` endpoint it had created independently, and asked for a decision.
The decision has been overtaken: **a different pull request got there first.**
`c0cbd2fd` (PR #302, `yifeng/add-readiness-endpoint`) is merged, and
`upstream/main` now carries `/liveness` and `/readiness` in `backend-api/app/main.py`
with a `ReadinessResponse` model in `backend-api/app/schemas/health.py`. PR #361
is now `CONFLICTING`.

The two implementations are not equivalent, and the difference is the reason
Phase 10 wrote its version:

| | upstream/main (PR #302) | this stack (Phase 10) |
|---|---|---|
| Checks | database only | database **and** broker |
| Timeout | none | 3 s per check, bounded independently |
| Failure detail | `{"status": "not_ready"}` | per-check `{ok, detail}` |
| Detail content | — | exception **type** only, never its text |
| Schema | `response_model=ReadinessResponse` | `include_in_schema=False` |

An unbounded probe is the specific failure the Phase 10 docstring says the
timeout exists to prevent: a hung database makes the readiness probe itself hang,
and a probe that never answers is indistinguishable from one that never ran.
`docker-compose.production.yml` health-checks the API on `/readiness`, so which
implementation wins is a runtime decision, not a cosmetic one.

Both register `@app.get("/readiness")` in the same file. A merge that keeps both
decorators leaves FastAPI matching whichever was registered first and silently
drops the other. `backend-api/app/main.py` is contended by **five** open pull
requests plus this stack.

### PR #352's Alembic merge revision has landed, and it collides

Phase 10 recorded the risk. It is now real, and characterised exactly:

- this stack: `2899a0e678b6_merge_migration_heads.py`
- `upstream/main`: `2899a0e678b6_merge_ccf7645372fc_and_d87c3bb49953_.py`

Same revision id `2899a0e678b6`, same `down_revision` tuple
`("ccf7645372fc", "d87c3bb49953")`, **different filenames**. Git keeps both, and
Alembic then finds one revision id twice and refuses to load the versions
directory at all — so `alembic upgrade head`, `alembic heads` and
`backend-api/entrypoint.sh` all fail before any container starts.

Deleting one file is not the whole fix. Upstream's new `8a7b91ea95d9`
(control verification templates) has `down_revision = "2899a0e678b6"`, and this
stack's `c4e91a73b620` (Phase 3 result semantics) has the same `down_revision`.
Once the duplicate is removed the graph has **two heads** — `b9d4e17c6a52` and
`8a7b91ea95d9` — and a new merge revision is required before the acceptance
criterion "exactly one Alembic head" can hold again.

## Collision surface

`collisions.json` records the computation. **28 of the 38 open pull requests
touch files this stack changes.** The two files the collision-safe delivery plan
singles out are the two most contended in the repository:

| File | Open PRs touching it |
|---|---:|
| `engine/policies/cis/microsoft-365-foundations/v6.0.0/metadata.json` | 9 |
| `engine/collectors/registry.py` | 7 |
| `backend-api/app/main.py` | 5 |
| `backend-api/app/api/v1/auth.py` | 3 |
| `.github/workflows/ci.backend-api.yml` | 3 |
| `backend-api/pyproject.toml` | 3 |
| `frontend/src/pages/Auth/components/SignupFormPanel.tsx` | 3 |

`soc2-collision-safe-delivery-plan.md` §4 states: *"Do not edit `metadata.json`
or `registry.py` concurrently without one nominated integrator."* No integrator
has been nominated in eleven phases. This stack edits both, and so do sixteen
open pull requests between them.

Largest individual overlaps: **#350** (Google SSO) at 28 files and `CONFLICTING`;
**#266** (HPA/KEDA, draft) at 13 — the deployment-platform decision Phase 10
declined to make, still in draft; **#296** at 7; **#313** at 5, which adds a
top-level `permissions:` block to five workflow files this stack rewrites.

## Branch protection could not be verified

| Query | Answer |
|---|---|
| `GET /repos/.../branches/main` | `"protected": true` |
| `GET /repos/.../branches/main/protection` | `404` |
| `GET /repos/.../rulesets` | `[]` |
| `GET /repos/.../rules/branches/main` | `[]` |
| account permissions | `{admin: false, maintain: false, push: true}` |

The branch reports itself protected and the detail endpoint requires
administrator rights this account does not have, so **which status checks are
required — if any — is unknowable from here.** Every phase since Phase 4 has
recorded that the proposed required-check set was never applied. Phase 11 can
neither confirm nor refute that; it needs a repository administrator to export
the protection settings.

Until then every gate in this programme is a green local run and not an enforced
one, which is why acceptance criterion 2 is recorded as not met rather than as
blocked.

## What this means for integration order

The integration is now a prerequisite with a known, ordered shape:

1. Resolve the duplicate `2899a0e678b6` file, then author a merge revision over
   `b9d4e17c6a52` and `8a7b91ea95d9`.
2. Decide the `/readiness` implementation before merging `main.py`, with #266,
   #300, #318 and #361 all queued on the same file.
3. Nominate the `metadata.json` / `registry.py` integrator the delivery plan has
   asked for since Phase 0, before nine and seven pull requests respectively are
   resolved by whoever merges last.
4. Only then re-run Phase 11.
