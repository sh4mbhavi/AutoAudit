# AutoAudit Monorepo - Main/Deployment Branch

## Project Overview
AutoAudit is a M365 compliance automation platform built by several specialist teams. This monorepo centralizes all codebases—including backend services, APIs, compliance scanners, and frontends—enabling unified CI/CD, streamlined development, and rapid automated deployments to the cloud.

## Documentation

- [Getting Started](docs/GETTING_STARTED.md) - Set up your development environment
- [Contributing Guide](docs/CONTRIBUTING.md) - Find where to contribute based on your skills

## Repository Structure
The repo follows the established modular structure:
- `/backend-api`
- `/security`
- `/frontend`
- `/engine`
- `/infrastructure`
- `/tools`
- `/docs`
- `/.github/workflows`

Full commit history and traceability from team forks are preserved.

## Branching Strategy
- Work merges into `main` through reviewed pull requests.
- **Branch protection is not currently enforced.** Phase 4 produced a proposed
  set of required status checks
  (`docs/compliance/phase-4/branch-protection-proposal.json`) and recorded that
  it was never applied to the repository. Until an owner applies it, a green CI
  run is advisory: nothing prevents a merge with a failing or absent check.

## CI/CD Pipeline Overview
- Code scanning (CodeQL, Bandit, Grype) and the policy, migration, container and
  supply-chain gates run on every push or pull request to `main`.
  `docs/DevSecOps/workflow-documentation.md` lists each workflow and what it
  actually does.
- `ci.supply-chain.yml` builds the worker and API images, generates a CycloneDX
  SBOM for each, verifies that the built worker image matches `engine/uv.lock`,
  and records a release manifest. Artifacts are retained for 90 days.

## Docker Builds and Deployment

**There is no automated deployment, and no production environment.** This
section previously described a `staging` branch, Docker Hub pushes and a GCP
Cloud Build trigger; none of them exists in this repository. Phase 10 corrected
it rather than leaving a reader to plan against a pipeline that was never built.

What actually exists:

- **Images are built from source on the deployment host** using
  `docker-compose.production.yml`. That template is the reviewed production
  topology: a private internal network, TLS between every service, secrets
  mounted as files, and no host port on PostgreSQL, Redis or the PowerShell
  service.
- **The only registry push in the repository** is `pr.preview-deploy.yml`, which
  pushes mutable `pr-<number>` tags to GHCR for pull-request previews. Those tags
  are overwritten on each run and are not release artifacts.
- **Release traceability** comes from `ENGINE_GIT_SHA`, which the worker image
  refuses to build without and which is written into every scan's provenance
  record, plus `tools/ops/release_manifest.py`, which records the source
  revision, every lockfile digest, the policy-corpus and mapping digests, and
  the built image ids.
- **The production platform has not been selected.** The decision, and the three
  contradictory claims this repository used to make about it, are recorded in
  `docs/compliance/phase-10/deployment-platform-decision.md`.

## Contribution Guidelines
- Work merges into `main` through reviewed pull requests. There is no `staging` branch.
- Emergency fixes require expedited team approval and follow strict policies.
- All merges are subject to passing full CI/CD and security gating.

## Contact & Support
For production deployment queries:
- Contact the DevOps lead managing GCP integration.
- Report critical issues with `main` branch deployments on GitHub with relevant tags.
