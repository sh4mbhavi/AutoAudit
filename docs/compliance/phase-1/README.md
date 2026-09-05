# Phase 1 — Credential, bootstrap, migration and public-copy containment

Engineering implementation on `fix/soc2-phase-1-containment`, in the separate
`AutoAudit-phase-1` worktree. Baseline and fetched upstream/main are both
`be241f52beb5ffec10904771bf7cfa4b98233ab0` (checked 2026-09-05, Australia/Melbourne).
The original Phase 0 branch and its untracked plans/handoff were preserved.

**Acceptance remains externally blocked:** Google credential revocation and the
state of administrator accounts in existing deployments require owner evidence.
No production system, identity provider, GitHub protection, shared history or
SOC 2 rating was changed. The user's explicit Phase 1 instruction authorized
this engineering work; it does not constitute GRC approval of Phase 0 decisions.

## Delivered changes

| Finding | Repository change | Remaining acceptance dependency |
| --- | --- | --- |
| SEC-01 | Replaced the Google OAuth values in `env.example` with placeholders; removed the embedded Fernet key from the backend example; examples and tests are no longer blanket-excluded from secret scanning; added Google-format detection and a blocking example/canary CI job | Google identity owner must confirm revocation/replacement; repository owner must coordinate historical exposure handling |
| SEC-03 | Container startup only migrates and starts the API; manual seeding requires development environment, an explicit opt-in and caller-supplied credentials; existing users are neither reset nor promoted; bootstrap output carries no credentials | Environment owners must inventory and disable or rotate legacy bootstrap accounts already created by older releases |
| SEC-04 | Registration/reset/verification events use logging with user ID only; reset and verification tokens are never included | No token-delivery implementation added; approved delivery remains separate work |
| DB-01 | Added forward-only no-op merge revision `2899a0e678b6` joining the existing heads; verified four PostgreSQL upgrade paths with data preservation | Deployment owner must check deployed revision stamps and schema drift before rollout |
| DOC-01 | Removed unsupported bank-level encryption, zero-knowledge and independent-audit assertions from landing/signup/contact copy; FAQ explicitly qualifies framework coverage and disclaims certification | Any future certification or independent-audit claim needs substantiation and approved wording |

The backend environment example now requires a database URL and a freshly generated
Fernet key. Existing Docker development defaults elsewhere are not proof of a
production credential policy. They remain separate configuration-hardening work
(including candidate PR #330). No actual provider credential was validated against
a provider, and no secret values are reproduced in this handoff.

## Credential incident and history handoff

Status: **revocation unconfirmed, externally blocked**. The Google identity owner
has not been identified or contacted by this session. Repository access is not
authority to rotate an external identity credential.

The owner must perform and record these actions through the organization's incident
process, without pasting credentials into tickets, logs or this repository:

1. Identify the OAuth application associated with the former `env.example` value.
2. Revoke the exposed secret, create a replacement if the integration is retained,
   and update the deployment secret store. Record actor, UTC time and provider
   confirmation/reference, without recording the replacement value.
3. Verify expected sign-in operation and review relevant access/authorization logs
   for the exposure interval. Decide whether related grants/sessions need action.
4. Record affected environments and deployment verification with the incident owner.

Read-only Git history assessment across locally fetched refs found the
Google-shaped value introduced by `f275a2787c1e017d66751338a67a37ebc183b77e`
(author timestamp `2026-01-04T17:13:28+05:30`). All three revisions returned by
`git rev-list --all -- env.example` contained it, including
`f798130222ca69fe0e69f0cd1284993f9f251822` and PR #330 head
`aeb83a4b8b449d0d7ebf109a8f935842b08d2bab`. These are file-history revisions,
not an exhaustive inventory of every descendant commit, fork, clone, PR cache,
artifact or external copy. Removing the current value does not invalidate it.

**Separate history proposal for repository-owner review:** revoke first; identify
all copies and affected refs; coordinate a maintenance window, replacement rules,
force-push permissions and clone/fork recovery instructions; then perform a
reviewed history cleanup if the owner decides it is appropriate. Coordinate hosted
PR/cache cleanup with the hosting provider where needed. No history rewrite,
force push, remote branch change or external message was performed here.

## PR coordination

PR #352 was read in full at `1cb1399f05f032c6d214429407c16f8c66a3ea09`.
Its merge revision and parents are reproduced, with regression and real PostgreSQL
tests added. The existing migration bodies are byte-for-byte unchanged. Coordinate
with that PR's owner before either implementation merges; do not add two distinct
merge revisions for the same heads.

The refreshed open-PR inventory and relevant diff sections also identified overlap
with #350 (head `596b920d6ed55793e17f7d54378474bdb816a3e1`, token logs and bootstrap),
#355/#294/#292/#296 (bootstrap changes), #266 (configuration/bootstrap), #330
(environment secrets), #331 (history scanning), and #326 (dependency gating).
These broader PRs were not adopted or declared merge-ready. In particular their
bootstrap candidates retain fallback credentials or account reset behavior;
Phase 1 reproduces neither. #331's history baseline is not adopted as evidence of
revocation. Cookie authentication, RBAC and full-history/dependency CI remain in
their planned later phases. No PR was merged, closed, commented on or pushed.

## Verification

Regression tests were added before the security fixes: 15 bootstrap/logging cases
failed against the old behavior and passed after the change. The initial two
scanner checks failed because both hook and baseline excluded examples. The
canary also exposed detect-secrets 1.5.0's failure to recognize unquoted Google
client secrets in `.example` files; `tools/google_oauth_secret_detector.py` adds a
narrow provider-format rule. Scanning is offline (`--no-verify`). Existing
synthetic test inputs now have line-specific annotations rather than a blanket
test-file exclusion. Documentation and deployed migrations retain their existing
exclusions; this is not a complete repository/history scanner rollout.

Run from repository root, with the disposable PostgreSQL cluster described in
[migrations.md](migrations.md) running:

```sh
MIGRATION_TEST_ADMIN_URL=postgresql://autoaudit_migration@127.0.0.1:55432/postgres uv run --project backend-api --with pytest python -m pytest backend-api/tests/test_migrations.py backend-api/tests/test_phase1_security.py tools/tests/test_secret_scanning.py -q
uv run --directory backend-api alembic heads
npm exec --yes --package=node@20 -- npm --prefix frontend ci --no-audit --no-fund
npm exec --yes --package=node@20 -- npm --prefix frontend run build
npm exec --yes --package=node@20 -- npm --prefix frontend run lint
git diff --check
```

Final results are recorded below. The migration test fixture contains
synthetic linked application rows, not a production dump. Container-entrypoint
checks execute the shell script with a recording `uv` executable to verify exactly
which commands run for development, preview and production; they do not claim a
container or production rollout was performed.

## Standard handoff

```text
Phase: 1 — Immediate credential, bootstrap and migration containment.
Baseline commit: be241f52beb5ffec10904771bf7cfa4b98233ab0; upstream/main identical.
Branch/commit/PR: fix/soc2-phase-1-containment; separate AutoAudit-phase-1 worktree;
  local commit titled "fix: contain phase 1 credential and bootstrap risks";
  no remote PR/push/merge.
Findings closed: Repository fixes for SEC-03, SEC-04, DB-01 and DOC-01;
  SEC-01 repository containment done, revocation still externally blocked.
Files changed: Bootstrap/settings/logging/entrypoint and setup documentation;
  environment examples, secret-scanner configuration/plugin/tests/workflow;
  synthetic fixture annotations; public landing/signup/contact copy;
  new Alembic merge and regression tests; this handoff and migrations.md.
Decisions made: Opt-in local bootstrap; no existing-account mutation; offline
  scanner canary; preserve deployed migration history and supplied SOC 2 ratings;
  remove unsupported claims instead of asserting new security guarantees.
Tests run and exact results: See final verification record below and migrations.md.
Security/GRC review required: Google identity owner confirms revocation;
  environment owners audit existing privileged accounts; repository owner
  coordinates history/overlapping PRs; GRC Phase 0 decisions remain pending.
Known gaps or follow-up work: No live revocation/account/deployment verification;
  no comprehensive history cleanup; no new token delivery; later security,
  authentication, evidence and CI findings remain open.
Next unblocked phase: Phase 2 is technically independent of Phase 1 changes,
  but its Phase 0/GRC/licensed-source dependencies remain as documented.
```

## Final verification record

- Focused suite after final formatting: **27 passed, 1 warning** (19 bootstrap/logging/
  entrypoint tests, 5 migration tests, 3 scanner tests). The warning is the existing
  Pydantic class-based settings configuration deprecation.
- All **8 pre-commit hooks passed** on all 25 changed/new files: secret detection,
  Ruff, formatting, whitespace, final newlines, YAML, merge conflicts and private keys.
- Alembic: **exactly one head**, `2899a0e678b6 (head)`.
- Frontend dependencies installed from lockfile with Node **20.20.2**; production
  build passed. Frontend lint exited 0 with **10 existing warnings**. No claim is
  made that the unrelated frontend unit suite or typecheck baseline is fixed.
- New scanner CI commands also passed locally with pinned `pytest==8.4.2` and
  `uv==0.8.22`: **3 passed**. The GitHub workflow has not run remotely.
- Targeted searches found no bootstrap password or reset/verification token logging
  in backend runtime code, and no unsupported target security claims in frontend
  source. The remaining `admin@example.com` in an existing manual-verification
  integration fixture is not a production bootstrap path.
- `git diff --check` and the staged whitespace check passed. Existing migration
  files were not edited; the merge is a new revision only.
- Independent specification and code-quality reviews found no actionable defects.
  Final scanner annotations and formatting preserve the reviewed behavior.
- Final disposable-database cleanup found **0 test databases**; PostgreSQL was stopped.
- Original worktree remains on `docs/soc2-phase-0-rebaseline`, with only the same
  pre-existing untracked plans and Phase 0 files. The Phase 1 branch/worktree is kept.

These local checks establish the repository remediation and reproducible migration
paths. Phase 1 acceptance remains externally blocked as stated above.
