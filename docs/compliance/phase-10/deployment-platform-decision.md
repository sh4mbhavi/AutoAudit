# The production deployment platform — a decision proposal

Date: 2026-09-07 (Australia/Melbourne). Status: **awaiting a named platform owner.**

Phase 10's first plan item is "Select and document the production deployment
platform". Phase 10 has **not** selected one, and this document explains why that
is the right outcome rather than an omission: selecting a platform commits an
organisation to a cost, an operating model and a set of vendor controls it will
have to evidence in a SOC 2 examination. Engineering can lay out the options and
the constraints; it cannot make that commitment, and no owner has been appointed
to make it (Phase 0 decisions D01–D10 remain unapproved with no named owners,
recorded identically in the Phase 7, 8 and 9 handoffs).

What Phase 10 did instead was make the question answerable: it removed three
false claims that a reader would otherwise have taken for a decision already
made, and it recorded exactly what each candidate would require.

## The three contradictory claims this repository used to make

All three were simultaneously present and mutually incompatible. None had a
supporting artifact.

| Claim | Where | Status |
|---|---|---|
| Google Cloud Platform: "Production deployments to GCP will be triggered from this branch", Cloud Build, Artifact Registry, Docker Hub pushes | `README.md` lines 27–39 | **False.** No workflow references `gcloud`, `google-github-actions`, `artifactregistry`, `cloudbuild`, Docker Hub or any registry except GHCR preview tags. Corrected by Phase 10. |
| Azure Kubernetes Service: "Alerting rules are deployed via Helm charts to the AKS cluster" | `infrastructure/monitoring/alerts/README.md` line 9 | **False.** There is no Helm chart, no Kubernetes manifest and no IaC of any kind in the tree. Corrected by Phase 10. |
| Owner-operated Docker Compose host with a self-managed HTTPS ingress proxy | `docs/compliance/phase-5/deployment.md` | **The only one with an artifact behind it** — `docker-compose.production.yml`. Phase 5's own document says it "does not provision or verify a production deployment". |

A fourth position exists outside the repository: **draft PR #266**
(`feature/proof-of-concept-deployment-26t1-imp-dha-003`, 81 files, +6,841) is a
complete AKS Helm chart with HPAs, KEDA queue-depth autoscaling, PodDisruptionBudgets,
topology spread, an in-cluster Prometheus/Grafana/celery-exporter stack and a k6
load harness. It is marked "PR in progress, not ready to review yet" and is a
*scaling* proof of concept — its own values file is named `values-poc.yaml`.

**Phase 10 deliberately did not author a competing chart.** A second Kubernetes
deployment definition, written without reading #266's AKS testing log, would
create exactly the collision Phase 9's coordination review warned about on
PR #351. If the platform decision lands on Kubernetes, #266 is the starting
point and its author is the person who has actually run it.

## What each candidate would require

Assessed against the Phase 10 verification checklist, not against preference.

### Owner-operated Docker Compose (the status quo)

*Already satisfies:* private internal network, no host publication for
PostgreSQL, Redis or the PowerShell service, TLS between services, secrets as
mounted files, and — after Phase 10 — healthchecks, resource limits, ordered
startup and bounded logs. `tools/tests/test_phase10_deployment.py` gates all of
it.

*Would still need:* an HTTPS ingress that the repository does not contain (the
template publishes `127.0.0.1:8000` for "a local TLS ingress proxy" that exists
nowhere), a frontend service (the production file has none, and
`frontend/Dockerfile` runs the Vite **dev** server), a backup schedule, and a
host to run on with its own patching and access controls to evidence.

*Cost of the choice:* every platform control — physical security, host patching,
network segmentation, availability — is the organisation's own to operate and
evidence. Nothing is inherited.

### Kubernetes, via PR #266's chart

*Would satisfy:* horizontal scaling, disruption budgets, rolling updates, and
the two alert rules in `platform.yaml` labelled `platform: kubernetes`
(`PodRestartsHigh`, reading kube-state-metrics, and
`ClusterStorageCapacityWarning`, reading the kubelet) which are unfireable
anywhere else. The other five read node_exporter and cAdvisor series, which any
platform can provide. It also brings a real
Prometheus and Grafana, which is what the whole monitoring directory presumes.

*Would still need:* review of the two application changes it carries — a
`POST /v1/test/synthetic-scan` load lever and a `synthetic_evaluate` Celery
task, double-gated by a Helm flag and `APP_ENV != prod`, which are a production
surface that has to be assessed rather than assumed benign. Its k6 harness also
logs in as `admin@example.com`, which is the bootstrap account Phase 1 removed;
that must not be reintroduced. And `backend-api/entrypoint.sh` runs
`alembic upgrade head` on every container start, which races itself the moment
there is more than one replica — a pre-existing defect that Kubernetes makes
immediately live.

*Cost of the choice:* a managed control plane's controls are inherited and must
be evidenced from the provider's own SOC 2 report, with the responsibility
boundary documented. That is a CC9 vendor-management obligation, not a free win.

### A managed platform (Cloud Run, App Service, ECS)

*Would satisfy:* most host-level controls by inheritance, and removes the
ingress and patching gaps outright.

*Would still need:* a rethink of the PowerShell execution service, which spawns
`pwsh` child processes and holds Exchange sessions for up to 300 seconds — a
poor fit for a request-scoped serverless runtime, and the component with the
tightest trust boundary in the product (Phase 5). The dispatcher is also a
long-lived polling process with no HTTP surface, which several managed platforms
cannot host at all.

## What the decision has to record

Whoever makes it should record, in a form GRC can cite:

1. The platform, and the environments it provides (production, staging — note
   `APP_ENV` already accepts `staging` and `preview` and no manifest implements
   either).
2. Which controls are **inherited** from the provider, with the report and
   validity period they are evidenced by, and where the responsibility boundary
   sits. The Phase 10 anti-pattern guard is explicit: do not claim an inherited
   control without reviewing the applicable provider report.
3. Where secrets live. Every production secret is currently a file on the deploy
   host; no Vault, SOPS, sealed-secrets or cloud secret manager is referenced
   anywhere. `ENCRYPTION_KEY` in particular must be **preserved** across any
   migration — an IaC that generates it fresh silently orphans every stored
   tenant credential.
4. Where backups go, and who can read them. `tools/ops/backup.py` produces an
   **unencrypted** archive containing every scan result and evidence object;
   see `backup-and-recovery.md`.
5. Whether the object store moves off the local volume. `EVIDENCE_STORAGE_BACKEND`
   accepts only `local` today, and S3/MinIO is blocked on Phase 0 decision D04
   *and* on the frozen dependency locks.

## What this document does not do

It does not select a platform, does not endorse PR #266, and does not authorise
any deployment. It records the options, the constraints each carries, and the
fact that the repository no longer asserts a platform it does not have.
