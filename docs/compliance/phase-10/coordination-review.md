# Phase 10 coordination review

Date: 2026-09-07 (Australia/Melbourne).

Read-only. No public PR was opened, merged, closed or commented on, and no
repository setting was changed. This records what must be resolved *before* the
Phase 10 branch can be merged, per plan section 4.2.

## Baseline movement

Phase 9 recorded upstream `main` at `bfb8edd44414683ac4adcde3ab79d4520a0a00a3`.
It has moved: **`0a074cc9255029e3c337c6fba6db5964ba89e7c9`**, twenty-two commits
across sixteen files, merging PRs #294, #330 and #352.

This branch is still based on Phase 1 `8736fcb9` overlaid with the Phase 9
working source, exactly as Phase 9 was. It is **not** represented as based on
current upstream, and integration remains unreviewed work that Phase 7's handoff
first flagged and every phase since has carried forward.

Three of those merges land on Phase 10 files:

### PR #352 — the Alembic merge revision collides by identity, not by text

Upstream now carries
`backend-api/alembic/versions/2899a0e678b6_merge_ccf7645372fc_and_d87c3bb49953_.py`.
Phase 1 added
`backend-api/alembic/versions/2899a0e678b6_merge_migration_heads.py`.

**Same revision id. Same `down_revision` tuple. Different filename.** Both are
no-op merges of `ccf7645372fc` and `d87c3bb49953`, so they agree in substance --
but Alembic refuses to load two files declaring the same revision id, and a
rebase that keeps both breaks migrations outright rather than conflicting
visibly.

Phase 1's handoff anticipated this precisely: "Coordinate with that PR's owner
before either implementation merges; do not add two distinct merge revisions for
the same heads." The resolution is to **delete one file**, keeping upstream's,
since it has landed. Nothing else in the migration graph changes.

### PR #330 — externalised compose secrets

Touches `docker-compose.yml` and `env.example`, both of which Phase 10 also
edits. The intents are compatible: #330 moves hard-coded values to `${VAR:?}`
indirection, which is the convention Phase 10's additions already follow. A
mechanical rebase.

### PR #294 — backend test fixtures

Touches `backend-api/app/api/v1/evidence.py` and `backend-api/tests/conftest.py`.
Phase 10 appends two endpoints to the end of `evidence.py` and does not touch
the regions #294 changes.

## Open pull requests

43 open at the time of writing; the full listing with per-PR file lists is in
[pull-requests-2026-09-07.json](pull-requests-2026-09-07.json) and the computed
overlap is in [collisions.json](collisions.json). Eleven touch a file Phase 10
changes. Two are conflicts of intent rather than adjacent edits.

### PR #361 — database readiness health check (`feature/backend-readiness-check`)

**Hard conflict, and Phase 10 owns the awkwardness.** #361 creates
`backend-api/app/core/health.py` containing `database_ready()`, and adds
`GET /readiness` to `main.py`. Phase 10 independently created **the same file
path, the same endpoint path, and the same concept**, without seeing it first.

The two are not textually mergeable and must not both land. On substance,
Phase 10's is a superset:

| | #361 | Phase 10 |
|---|---|---|
| Checks | database | database and broker |
| Timeout per check | none | 3s, so a hung dependency reports not-ready rather than hanging the probe |
| Response | boolean-derived | per-check outcomes, 200/503 |
| Failure detail | none | exception **type** only -- a connection error's message routinely carries the DSN, and `/readiness` is unauthenticated |
| Registered on | the app | the app (both correctly outside the `/v1` prefix, so a probe needs no session cookie) |

Recommended resolution: land Phase 10's `health.py` and close #361 as
superseded, **crediting its author** -- it identified the gap independently and
its `SELECT 1` choice is the same one Phase 10 made. If #361 lands first,
Phase 10's version replaces it wholesale rather than being merged into it, since
a partial merge would produce a readiness endpoint that checks the broker without
a timeout.

Whoever merges second owns this. It should be a deliberate decision by someone
who has read both, not a conflict resolution.

### PR #266 — HPA/KEDA scaling proof of concept (`feature/proof-of-concept-deployment-26t1-imp-dha-003`)

**Conflict of intent on the phase's first plan item.** 81 files, +6,841/-50,
marked "PR in progress, not ready to review yet", last updated 2026-09-03. It is
a complete AKS Helm chart -- HPAs, KEDA queue-depth autoscaling on three
per-queue worker deployments, PodDisruptionBudgets, topology spread, graceful
shutdown -- plus an in-cluster Prometheus/Grafana/celery-exporter stack, a
Grafana dashboard, and a k6 load harness.

Phase 10's first plan item is "select and document the production deployment
platform". **Phase 10 deliberately did not author a competing chart.** Writing a
second Kubernetes deployment definition without reading #266's AKS testing log
would recreate exactly the collision Phase 9 recorded on PR #351. The decision
surface is recorded in
[deployment-platform-decision.md](deployment-platform-decision.md) instead, and
#266 is named there as the starting point if the platform decision lands on
Kubernetes.

Four things in #266 need review alongside it rather than after it:

1. **It adds a production surface.** `POST /v1/test/synthetic-scan` and a
   `synthetic_evaluate` Celery task exist to generate load. They are double-gated
   by a Helm flag and `APP_ENV != prod` and return 404 when disabled, which is
   the right shape -- but a load-generation lever inside the product is a
   security surface that has to be assessed, not assumed benign.
2. **Its k6 harness logs in as `admin@example.com`** — the bootstrap account
   Phase 1 removed, and whose reintroduction Phase 1's handoff explicitly warns
   against.
3. **It adds `prometheus-fastapi-instrumentator` and a `/metrics` endpoint** to
   `backend-api/app/main.py`, and `prometheus_client` to the PowerShell service.
   Phase 10 adds a `/metrics` endpoint to the same file. The two are compatible
   in substance -- #266's is generic RED-style HTTP instrumentation, Phase 10's
   is the named series its alert rules read -- but they cannot both define the
   route. Its PodMonitors scrape a path that, before Phase 10, nothing served.
4. **`backend-api/entrypoint.sh` runs `alembic upgrade head` on every container
   start.** With one replica that is merely unusual; with an autoscaler it is a
   concurrent-migration race with no advisory lock and no separate migration job.
   Pre-existing, but #266 makes it immediately live.

Phase 10 also edits `docker-compose.yml`, `engine/pyproject.toml`,
`engine/uv.lock`, `backend-api/pyproject.toml` and `backend-api/uv.lock`, all of
which #266 touches. The lockfile edits will conflict textually and must be
re-resolved by regenerating, never by hand-merging.

### The other nine

Adjacent edits with no shared function:

| PR | Shared file(s) | Nature |
|---|---|---|
| #358, #318, #302, #300 | `backend-api/app/main.py` | four PRs queued on one file. #302 and #300 add health/version endpoints; Phase 10 adds `/metrics` and `/readiness`. **Five contenders on one file** — see the note below. |
| #318 | `backend-api/app/core/middleware.py` | adds response headers; Phase 10 adds a metrics call. Different regions of `dispatch`, but read both: middleware ordering is load-bearing for the Phase 9 conditional poll. |
| #355, #350 | `pyproject.toml`, `uv.lock`, `evidence.py`, `config.py` | lockfile conflicts; regenerate rather than merge |
| #313 | `ci.engine.yml`, `ci.validate-alerts.yml`, `ops.short-test.yml` | adds top-level `permissions:` blocks. Wanted, and compatible: Phase 10 rewrote `ci.validate-alerts.yml` and should adopt #313's permissions block on the new version. |
| #296, #299 | `evidence.py`, `README.md` | unrelated regions |

**On `/version`, deliberately.** Phase 10's plan item 8 requires release
traceability, and PR #300 already adds a `/version` endpoint to `main.py` — a
file with four other PRs queued on it. Phase 10 therefore did **not** add a
fifth competing endpoint. Release traceability is delivered through
`tools/ops/release_manifest.py` and the existing `ENGINE_GIT_SHA` provenance
chain instead, and #300 remains the right place for the runtime endpoint. This
is a coordination decision, not an omission.

## What this review did not do

- It did not open, merge, close, rebase or comment on any pull request.
- It did not read the full diff of every one of the 43 open PRs. The overlap
  above is computed from the GitHub file lists; #361 and #266 were read because
  they collide semantically, and #352, #330 and #294 were read because they have
  already landed on Phase 10 files.
- It did not integrate this branch with current upstream. That work is still
  outstanding from Phase 7 and is a prerequisite for merging any of this stack.
- It did not resolve PR #351, the hard conflict Phase 9 recorded. It is still
  open and still unresolved.
