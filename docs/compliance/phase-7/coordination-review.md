# Phase 7 coordination review

Read-only upstream fetch on 2026-09-06 observed `upstream/main` at
`bba14810f558190ee5221017c11864d300f8078a`, unchanged from the Phase 5 and Phase 6
handoffs. The refreshed open-PR inventory (43 PRs) is
[coordination-snapshot.json](coordination-snapshot.json). Candidate diffs were
retrieved read-only. Nothing was merged, closed, pushed or commented on, and no
message was sent to any maintainer or PR author.

## Overlapping work

- [#229 ControlVerificationTemplate table and CRUD](https://github.com/Hardhat-Enterprises/AutoAudit/pull/229)
  is the closest overlap with this phase. It adds a `control_verification_template`
  table keyed on `(framework, benchmark, version, control_id)` plus admin-only CRUD,
  and describes later phases that would add confidence scoring, evidence linkage and
  status propagation from a verdict into `scan_result.status`.

  Two things must be resolved before it lands alongside Phase 7.

  First, **its migration reintroduces a second Alembic head.** `8a7b91ea95d9` sets
  `down_revision = 'j1k2l3m4n567'`, which branches beside the Phase 1 merge
  `2899a0e678b6` that closed finding DB-01. Rebasing it onto the current head
  (`f7d2c48b1a03` after this phase) is required; merging as-is re-opens DB-01.

  Second, its stated Phase 3 goal — propagating a manual verdict into
  `scan_result.status` — directly contradicts execution-plan rule 5 and this
  phase's residual-evidence separation. Phase 7 deliberately reports approved
  manual and inherited evidence as a separate stream and never lets it change a
  scan result, a state count, or the automated compliance/coverage scores. That
  design difference needs an explicit owner decision, not a silent merge.

  The template content itself is complementary: Phase 7 consumes the existing
  `docs/compliance/templates/manual_controls_v6.0.0.json` as read-only auditor
  instructions rather than duplicating it, so the two can converge on one source.

- [#292 RBAC on scan and M365 connection mutations](https://github.com/Hardhat-Enterprises/AutoAudit/pull/292)
  owns role policy. Its only change to `security/evidence_ui/app.py` is a type
  annotation on `SCAN_MEM`, so it does not collide with the AUTH-02 hardening here.
  The new Phase 7 evidence and manual-evidence routes must be included when that
  role policy is integrated; this phase preserves object ownership and adds
  reviewer authorization on top of the existing `permissions.py` roles rather than
  inventing a second role system.

- [#230 report service and template rewrite](https://github.com/Hardhat-Enterprises/AutoAudit/pull/230)
  rewrites `security/reports/report_service.py` and the DOCX template. Phase 7 does
  not modify the report renderer, but it does change how generated reports are
  stored and authorized: by opaque object id against an owned `evidence_artifact`
  row, never by filename. That PR must adopt the storage/authorization seam rather
  than writing into the shared `security/results/reports` directory.

- [#355 backend test coverage](https://github.com/Hardhat-Enterprises/AutoAudit/pull/355)
  and [#294 backend test suite](https://github.com/Hardhat-Enterprises/AutoAudit/pull/294)
  overlap the backend test tree. Phase 7 adds `test_phase7_*` modules following the
  established per-module fixture convention; there is no shared conftest to conflict
  over beyond the existing CI integration guard.

- A new upstream branch `feature/audit-readiness-summary` appeared during this
  session with no open PR. It was not inspected beyond its name and must be checked
  for overlap with the SOC 2 projection before either lands.

No open PR provided the crosswalk artifact, the validator, evidence ownership,
evidence bounds, the approval lifecycle, or metadata-driven documentation. The
residual Phase 7 work is genuinely unclaimed.

## What this review is not

Engineering review is not maintainer coordination and is not GRC approval. Phase 0
decisions D01–D10 remain unapproved drafts with no named owners, and the mapping
artifact records `approved: false` for exactly that reason. Phase 4's required
status checks were never applied to branch protection (HTTP 401 when read), so
"CI is green locally" does not mean an enforced gate exists upstream.
