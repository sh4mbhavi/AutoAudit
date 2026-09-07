# GitHub Actions Workflow Documentation

Reference for anyone picking up the project who wants to understand what runs in `.github/workflows/`, when it runs, and why.

---

## Naming Convention

Workflow files use a prefix to group them by purpose:

| Prefix | Purpose |
|---|---|
| `ci.` | Code quality checks on PRs and pushes to main |
| `ops.` | Scheduled or operational jobs not tied to code review |
| `pr.` | PR metadata management |

---

## CI Workflows

| Workflow | Path filter |
|---|---|
| `ci.backend-api.yml` | **None** — runs on every PR and push to `main` |
| `ci.frontend.yml` | **None** |
| `ci.engine.yml` | **None** |
| `ci.validate-alerts.yml` | **None** |
| `ci.supply-chain.yml` | **None** |
| `ci.grype.yml` | **None** — scans the whole repository (`path: "."`) |
| `ci.runtime.yml` | **None** — builds and starts the containers |
| `ci.secret-examples.yml` | **None** |
| `ci.security.yml` | `security/**` (the unmaintained TPRM module) |

### When they run

Every workflow above except `ci.security.yml` triggers on **all** pull requests
and pushes to `main`, regardless of which files changed.

The table above previously listed seven workflows and generalised over them as
if it were complete, while `.github/workflows/` held nine `ci.` files.
`ci.runtime.yml` and `ci.secret-examples.yml` were missing from it and described
nowhere else on this page -- and `ci.runtime.yml` is the only job that starts the
API, the worker and the PowerShell service, exercises the production Compose
overlay, and proves Redis enforces TLS. Both supply a required-check context in
`docs/compliance/phase-4/branch-protection-proposal.json`.

This corrects a previous version of this page, which said each workflow watched
its own directory and "never starts" otherwise. Phase 4 deliberately removed
those path filters (`docs/compliance/phase-4/change-control.md`): a gate that
only runs when its own directory changes cannot catch a change in one component
that breaks another, which is precisely the failure a cross-cutting gate exists
for. `ci.validate-alerts.yml` lost its filter in Phase 10 for the same reason —
deleting a metric emitter in the application is what actually breaks an alert.

### Jobs

When triggered, two jobs run in parallel:

**`analyze`** runs CodeQL static analysis and reports findings to the GitHub Security tab. The backend-api workflow also runs Bandit inside the same job as a Python-specific check.

**`run-lint`** runs Super Linter across changed files. Several linters are disabled to keep it focused on the languages used in each area.

### PR status comment

After both jobs finish, a `report` job posts a table on the PR showing which jobs passed or failed with a link to the run logs. On subsequent pushes the comment updates in place.

```
analyze  ─┐
           ├─→  report
run-lint ─┘
```

The report job only runs on PR events, not on push or schedule.

### `ci.security.yml`

The `security/` directory contains the TPRM Scanner from T2 2025 and is no longer actively maintained. The workflow is kept so changes to that directory are still scanned but is not expected to trigger under normal development.

---

## Grype Dependency Scan

**`ci.grype.yml`** triggers on every PR and push to `main`, and weekly. It has no path filter and scans the whole repository (`path: "."`).

Grype walks the repo and checks dependency files (`pyproject.toml`, `requirements.txt`, `package-lock.json`) against public vulnerability databases without needing a Docker build. Results upload to the GitHub Security tab as a SARIF report.

**`fail-build` is `true`, with `severity-cutoff: critical`** — a critical finding
blocks the merge. A previous version of this page said the opposite; Phase 4
turned the gate on and the page was never updated. Findings at `high` and below
do not block: Phase 4 and Phase 5 both recorded 0 critical, 51 high, 49 medium
and 12 low passing this gate, and that backlog has not been triaged since.

Note that a **directory** scan cannot see a base image or an apt layer.
`ci.supply-chain.yml` (Phase 10) scans the built worker image itself, generates a
CycloneDX SBOM for the worker and the API, and verifies that the built worker
image matches `engine/uv.lock`. Its image scan reports rather than gates, for the
same untriaged-backlog reason.

Note: the Security tab upload requires GitHub Advanced Security, which is free for public repos and requires a paid plan for private ones.

---

## Ops Workflows

**`ops.collector.yml`** is **hard-disabled** (`if: false`) and runs nothing. Its
header records why: it used a long-lived `GCP_CREDENTIALS` service-account key
and auto-committed live GCP infrastructure data into the repository on every
push. Do not re-enable the trigger before both conditions in that header are met.

**`ops.workflow-cleanup.yml`** runs weekly as a **dry run only**: it reports which runs are older than `RETENTION_DAYS` and deletes nothing. Deletion requires a manual `workflow_dispatch` with `dry_run=false` and `confirm=DELETE`. So workflow-run history is **not** currently being retained to any period by an automated process, and must not be cited as retained evidence on the strength of this workflow alone.

**`ops.branch-cleanup.yml`** deletes merged branches. It was absent from this
page entirely.

**`ops.short-test.yml`** is the canary used to verify the cleanup workflow. It
triggers only when its own file changes — and until Phase 10 its path filter
named `short-test.yml` while the file is `ops.short-test.yml`, so it could never
trigger at all. That is worth stating plainly: the cleanup behaviour had never
been exercised by its own test.

---

## Other CI Workflows

**`ci.opa-eval.yml`** evaluates legacy OPA policies under `engine/legacy/`. It
triggers on pushes to `engine-development` and on **every** pull request with no
branch filter, unlike every other CI workflow. It uploads a PDF and a JSON report
(retained 30 days since Phase 10; previously with no stated retention) and gates
nothing.

**`ci.validate-alerts.yml`** validates the Prometheus alerting rules under
`infrastructure/monitoring/alerts/`. Phase 10 rebuilt it, so the previous
description ("does not do anything meaningful") no longer applies. It now:

- installs a **pinned, checksum-verified** promtool via
  `tools/ci/install_promtool.py`, instead of an unpinned `apt-get install -y prometheus`;
- runs `promtool check rules` on every rule file (syntax);
- runs `promtool test rules` against `tests/rule_tests.yaml` (semantics — does a
  threshold fire when it should, and stay quiet when it should not);
- runs `tools/ci/check_alert_metrics.py`, which fails the build if any alert
  reads a metric that is neither emitted by the application nor declared in
  `tools/ci/external_metrics.json` with the exporter that provides it.

It is no longer path-filtered.

**`ci.runtime.yml`** builds the API and worker images with
`tools/ci/container_smoke.py`, then starts **every** service in
`docker-compose.production.yml` with `tools/ci/production_overlay_smoke.py` and
asserts the boundaries hold: only `backend-api` publishes a host port, Redis
refuses a plaintext connection and completes a TLS handshake under its ACL,
`/readiness` answers, and the worker replies to a Celery ping over the TLS
broker. It also runs the Redis transport and PowerShell transport smokes.

**`ci.secret-examples.yml`** proves the `detect-secrets` canary is still
rejected, so the secret gate cannot be silently disarmed.

---

## PR Workflows

**`pr.size-warning.yml`** comments on unusually large pull requests.

The three `pr.preview-*` workflows that used to live here -- deploy, teardown and
instructions -- were removed. The deploy job had been unable to start a backend
since Phase 5 made `POSTGRES_PASSWORD` mandatory and the runtime validator began
rejecting `APP_ENV=preview` with a development password and a plaintext
`redis://` broker, and it carried that published default credential in a tracked
file. `git log --diff-filter=D -- .github/workflows/pr.preview-deploy.yml` has
the original, and README.md records what reviving previews would take.

---

## Weekly Scheduled Scans

| Workflow | Schedule | Purpose |
|---|---|---|
| `ci.backend-api.yml` | Saturdays 23:32 UTC | CodeQL and lint scan of backend-api |
| `ci.frontend.yml` | Saturdays 23:32 UTC | CodeQL and lint scan of frontend |
| `ci.engine.yml` | Saturdays 23:32 UTC | CodeQL and lint scan of engine |
| `ci.security.yml` | Saturdays 23:32 UTC | CodeQL and lint scan of security |
| `ci.grype.yml` | Thursdays 20:37 UTC | Dependency vulnerability scan |
| `ci.supply-chain.yml` | Mondays 04:17 UTC | Image build, SBOM, image vulnerability scan |
| `ops.workflow-cleanup.yml` | **Sundays 00:00 UTC** | **Dry run only** — reports runs older than `RETENTION_DAYS`, deletes nothing |

Scheduled runs do not post PR comments.
