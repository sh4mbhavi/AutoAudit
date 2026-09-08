# Phase 8 — open-PR coordination review

Inventory refreshed 2026-09-06 against `Hardhat-Enterprises/AutoAudit`:
**43 open PRs**, 188 merged. Full snapshot: [pull-requests-2026-09-06.json](pull-requests-2026-09-06.json).
`upstream/main` is `bba14810f558190ee5221017c11864d300f8078a`, unchanged since the Phase 5, 6 and 7
handoffs. This stack is still based on Phase 1 `8736fcb9` plus the Phase 7 working source and has not
been rebased onto current upstream.

An open PR contributes no current coverage. Nothing below was merged, reviewed for correctness, or
adopted; this is a routing aid for the integrator.

## Direct collisions with Phase 8 files

| PR | Title | Collision | Required disposition |
|---|---|---|---|
| [#352](https://github.com/Hardhat-Enterprises/AutoAudit/pull/352) | Merge Alembic migration heads | **Highest risk.** Phase 8 adds revision `a3f5c1d90b47` with `down_revision = f7d2c48b1a03`. Any PR that also adds a head, or rewrites the chain, reintroduces the multi-head condition Phase 1 closed (DB-01) and breaks `test_migration_graph_has_one_head`. | Sequence explicitly. Whichever lands second must rebase its `down_revision`, not merge heads a second time. |
| [#229](https://github.com/Hardhat-Enterprises/AutoAudit/pull/229) | ControlVerificationTemplate table + CRUD | Adds a migration (same head risk) and touches manual-verification surfaces Phase 7 rebuilt. Flagged in the Phase 7 handoff and still open. | Resolve against Phase 7 before Phase 8 is integrated; confirm it does not fork the revision chain. |
| [#351](https://github.com/Hardhat-Enterprises/AutoAudit/pull/351) | Multi-client collector support | Changes how a collector obtains clients. Phase 8 adds `compliance.*` collectors that take a certificate-authenticated Compliance client with its own alias namespace. | Reconcile with `PowerShellClient`'s separate `compliance_certificate_alias` kwarg before either lands. |
| [#362](https://github.com/Hardhat-Enterprises/AutoAudit/pull/362) | Ingestion service for file validation and hashing | Overlaps Phase 7 evidence ingestion, which Phase 8 does not modify but depends on. | Review against Phase 7's bounded, fail-closed ingest; do not adopt a second ingest path. |
| [#302](https://github.com/Hardhat-Enterprises/AutoAudit/pull/302), [#361](https://github.com/Hardhat-Enterprises/AutoAudit/pull/361) | readiness & health endpoints | Phase 8 edits `scan_readiness.py` (adds `NON_GRAPH_PERMISSIONS` and latent Purview checks). These PRs add *different* readiness/health surfaces. | Confirm they are distinct concerns (service liveness vs pre-scan tenant readiness) and do not collide on naming or routing. |
| [#332](https://github.com/Hardhat-Enterprises/AutoAudit/pull/332) | compose policy checks | Phase 8 adds `docker-compose.compliance.yml` and a deployment test. | Check the policy checks accept the new overlay. |
| [#330](https://github.com/Hardhat-Enterprises/AutoAudit/pull/330) | externalize hardcoded secrets in docker-compose | Phase 8 adds `COMPLIANCE_CERT_ALIASES` as a compose secret pair. | Merge order matters; both edit compose secret wiring. |

## Adjacent, no file collision

- **Section 7 SharePoint work** — [#325](https://github.com/Hardhat-Enterprises/AutoAudit/pull/325),
  [#336](https://github.com/Hardhat-Enterprises/AutoAudit/pull/336),
  [#344](https://github.com/Hardhat-Enterprises/AutoAudit/pull/344),
  [#348](https://github.com/Hardhat-Enterprises/AutoAudit/pull/348),
  [#357](https://github.com/Hardhat-Enterprises/AutoAudit/pull/357),
  [#359](https://github.com/Hardhat-Enterprises/AutoAudit/pull/359).
  These are plan section 16.3's "optional later waves" and were deliberately not attempted here.
  Phase 7 pinned 11 v6 controls as xfail because they reference `sharepoint.spo_tenant` and
  `sharepoint.spo_sync_client_restriction`, which exist on disk but are unregistered. Any of these PRs
  that registers those collectors must remove the matching xfail in `engine/tests/test_wiring.py`.
- **Overlapping CIS 2.4.1/2.4.2** — [#320](https://github.com/Hardhat-Enterprises/AutoAudit/pull/320)
  and [#342](https://github.com/Hardhat-Enterprises/AutoAudit/pull/342) still both open, still
  unresolved since Phase 0. One must be selected or superseded.
- **Essential Eight controls** — [#346](https://github.com/Hardhat-Enterprises/AutoAudit/pull/346),
  [#347](https://github.com/Hardhat-Enterprises/AutoAudit/pull/347),
  [#349](https://github.com/Hardhat-Enterprises/AutoAudit/pull/349),
  [#354](https://github.com/Hardhat-Enterprises/AutoAudit/pull/354).
  These add controls to a different benchmark. Each changes a `metadata.json`, so each must regenerate
  its `controls.md` or the Phase 7 documentation gate fails. That gate is new to them.
- **CI** — [#313](https://github.com/Hardhat-Enterprises/AutoAudit/pull/313),
  [#331](https://github.com/Hardhat-Enterprises/AutoAudit/pull/331),
  [#353](https://github.com/Hardhat-Enterprises/AutoAudit/pull/353),
  [#355](https://github.com/Hardhat-Enterprises/AutoAudit/pull/355).
  Phase 8 adds no workflow file and edits none.

## Standing coordination debt carried from earlier phases

- Phase 4's required status checks were never applied to branch protection, so a green local run is
  not an enforced gate for any of the above (CI-02, still open).
- No PR in this inventory touches Purview, DLP, sensitivity labels, or configuration drift, so Phase 8's
  substantive work has no competing implementation. The collisions are structural (migrations,
  collector plumbing, compose secrets), not semantic.
