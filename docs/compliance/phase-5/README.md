# Phase 5 — Runtime trust boundaries and secret handling

Date: 2026-09-06 (Australia/Melbourne).

**Local engineering implemented; deployment, upstream integration and external
acceptance remain pending.** No production service, tenant, credential,
repository setting or public PR was changed.

## Workspace and baseline

- Worktree: `/Users/clupa/Documents/projects/autoaudit/AutoAudit-phase-5`.
- Branch: `fix/soc2-phase-5-runtime-trust`; uncommitted and unpushed.
- Base commit: Phase 1 `8736fcb9`, with the complete uncommitted Phase 4 source
  copied before implementation. [phase-4-snapshot.json](phase-4-snapshot.json)
  records SHA-256 hashes for all 171 prerequisite changed/new files.
- All earlier worktrees are preserved. The prerequisite stack still needs
  reviewed integration with current upstream; this branch is not represented
  as already based on current main.
- Initial upstream observed: `bba14810f558190ee5221017c11864d300f8078a`.
  [Coordination review](coordination-review.md) records the five required PR
  dispositions and newly merged CORS/Bookings work.

## Implemented

PowerShell now accepts 25 fixed operation identifiers for all 22 registered
PowerShell collectors. The shared immutable registry fixes the module,
read-only command or sequence, permitted collector IDs and typed parameters.
The generic cmdlet/script API and client bypass are removed. Unknown operations,
modules, parameters, collector IDs, shell syntax, certificate paths and malformed
configuration fail before execution. HTTP calls require constant-time service
authentication. Access tokens travel in authenticated HTTPS or process
environment, never subprocess arguments. Service validation/error responses are
redacted. Local Docker uses the real interpreter's file-input mode and removes
its uniquely named container on success, failure and timeout.

Graph collection rejects every method except GET, and rejects request bodies
before token acquisition. Pagination still enforces the requested Graph origin
and version and fails closed on truncation or malformed evidence.

Celery control messages now contain only scan, result and connection IDs. The
executing worker loads frozen metadata, checks result membership and connection
ownership, and decrypts the selected connection just in time. Completed or
unselected results never decrypt credentials. Retries and terminal errors are
redacted, including transient failures while loading execution context; local
credential dictionaries are cleared after execution. No raw secret is copied
into task retries, result records, provenance or broker events.

Browser authentication uses revocable opaque cookie sessions with SHA-256 token
hashes in PostgreSQL. Password and Google sign-in share HttpOnly/Secure/SameSite
behavior. Signed session-bound CSRF and an exact frontend Origin are required
for every unsafe request, including login, registration, refresh and logout.
Refresh rotates atomically within idle and absolute lifetime limits, and logout
revokes the database session. Browser storage tokens, bearer headers, callback
tokens and token-dependent UI gates are removed. Refresh races across tabs or
in-flight requests recheck the current cookie before expiring authentication;
logout failures remain visible. The nonfunctional Remember me option is removed.

Forward migration `d5f02b84c731` creates session storage and purges unused Google
provider access/refresh credentials while preserving identity links. New links
discard provider credentials; a database constraint prevents reintroducing them.
The API access log is disabled so OAuth callback authorization codes are not
printed in query-string access logs; existing path-only request logging remains.

Production settings reject missing/default secrets, unsafe origins, unauthenticated
Redis, disabled TLS checks and insecure failover URLs. Startup validation hides
secret inputs. The standalone production Compose template has no PowerShell,
Redis or database host ports. Redis requires mounted TLS and ACL material and
has no disk persistence/result backend. An optional SharePoint overlay supplies
PnP configuration and mounts certificate material only into the service.

See the [authentication contract](authentication.md),
[deployment contract](deployment.md), and [PowerShell operation contract](../../../engine/powershell/README.md)
for compatibility, provisioning and runtime details.

## Verification

Tests use synthetic credentials and evidence. PostgreSQL fixtures create/drop
unique databases on a disposable loopback server. Container and TLS smoke tests
create their own temporary resources and remove them afterward.

```sh
export OPA_BINARY=/tmp/autoaudit-phase5-tools/opa
export MIGRATION_TEST_ADMIN_URL=postgresql://postgres@127.0.0.1:55435/postgres
export AUTOAUDIT_REQUIRE_INTEGRATION=1
uv run --frozen --project engine --extra dev python -m pytest engine/tests -q
uv run --frozen --project backend-api --extra dev --extra evidence python -m pytest backend-api/tests tools/tests -q
"$OPA_BINARY" check --strict engine/policies
"$OPA_BINARY" test engine/policies engine/tests
npm exec --yes --package=node@24 -- npm --prefix frontend test
npm exec --yes --package=node@24 -- npm --prefix frontend run typecheck
npm exec --yes --package=node@24 -- npm --prefix frontend run lint
npm exec --yes --package=node@24 -- npm --prefix frontend run build
python3 tools/ci/container_smoke.py
uv run --frozen --project backend-api python tools/ci/runtime_tls_smoke.py
uv run --frozen --project engine --extra dev python tools/ci/runtime_powershell_smoke.py
git diff --check
```

- Engine: **1,196 passed, 1 existing structural skip**. Real PostgreSQL/OPA
  integration ran. Dedicated PowerShell adversarial tests: **101 passed**.
- Backend/tools: **151 passed**, including **50 cookie/CSRF/session tests**,
  upgrade/purge preservation, real DB session lifecycle and API-to-worker
  serialized credential-free messages.
- Strict OPA check passed; **550/550 Rego tests passed**.
- Frontend Node 24: **232 passed across 25 files**; typecheck, lint and build
  passed. Nine lint warnings and the existing large-chunk advisory remain.
- Real Chromium with a migrated disposable PostgreSQL database passed UI login,
  HttpOnly/storage/header boundaries, CSRF rejection, refresh rotation without
  false UI sign-out, old-session replay rejection and logout revocation.
- Actual API/worker images rebuilt and entrypoints verified: migration/startup,
  liveness and Celery broker ping passed on disposable internal networks.
- Real Redis verified TLS/authentication passed; anonymous, wrong-password,
  untrusted-CA and plaintext connections were rejected, and persistence was off.
- Real PowerShell 7.5 interpreter returned clean JSON through the local Docker
  client, and both successful and timed-out containers were removed. Microsoft
  cmdlets were stubbed; this is interpreter/transport proof, not a live M365 scan.
- All eight pre-commit hooks passed on Phase 5 changed/new files. Secret-scanner
  false positives are narrowly recorded for synthetic fixtures, migration IDs
  and rejected development values. No historical baseline entries or file-wide
  scanner coverage were removed. A temporary Git index kept the real index unstaged.
- Bandit 1.8.6 passed application code and tests; only ordinary test assertions
  are excluded in the test command. The deliberate empty provider credential
  has a narrow reviewed annotation. Synthetic SQL queries use parameters.
- Actionlint passed the updated runtime workflow. Grype's critical gate passed:
  **0 critical, 51 high, 49 medium, 12 low** on a clean source snapshot. Existing
  lower-severity dependency findings remain; no Grype suppression was added.

Detailed results and browser verification are recorded in [verification.json](verification.json).
Local code and security reviews passed after fixing Redis TLS edge cases,
startup error redaction, transient context retries, PowerShell stdin/timeout
behavior, CSRF malformed-input errors and browser refresh races.

## Remaining acceptance and compatibility

Before production release, a maintainer must integrate the complete reviewed
Phase 1–5 stack with current upstream, publish and verify hosted checks, and
complete the Phase 4 enforced-check proof. Deployment owners must provision and
verify actual TLS material, Redis ACL contents, internal networks, same-site
HTTPS frontend/API domains, Google redirect registration and service credentials.
Live Microsoft/SharePoint module and tenant acceptance remain pending.

Drain and handle old credential-bearing Celery messages/backups under the prior
incident process before switching task contracts. Existing bearer browser/API
clients must sign in/use the new cookie/CSRF contract; the disabled legacy
Streamlit prototype remains unsupported and is not re-enabled. The provider
credential purge is intentional and cannot recover those old tokens. Existing
M365 encryption keys and database volumes must be preserved during deployment.

Pending Phase 0 GRC decisions, historical credential actions and organization-level
SOC 2 evidence are unchanged. No supplied rating, certification or production
acceptance is inferred from these tests. Phase 6 still owns transactional
queueing/reconciliation and complete selected-tenant SharePoint binding.

## Standard handoff

- **Phase:** 5 — local engineering implemented; external acceptance pending.
- **Baseline:** `8736fcb9` plus exact 171-file Phase 4 snapshot; upstream integration pending.
- **Branch/commit/PR:** `fix/soc2-phase-5-runtime-trust`; uncommitted/unpushed; no PR.
- **Findings addressed locally:** SEC-02, SEC-05, SEC-06, SEC-07 and insecure
  non-development configuration defaults.
- **Files changed:** [phase-5-changes.json](phase-5-changes.json) distinguishes
  Phase 5 changes from prerequisite files.
- **Decisions:** exact read-only operations; identifier-only tasks; owner-bound
  JIT decryption; revocable opaque sessions; signed bound CSRF; discard unused
  Google credentials; verified private TLS and ephemeral identifier broker.
- **Tests:** exact commands/results above and the verification record.
- **Security/GRC review:** local reviews passed; deployment owner, maintainer
  hosted enforcement, incident follow-up and GRC acceptance remain pending.
- **Known gaps:** current-main integration, real M365 acceptance, lower-severity
  dependencies, legacy bearer incompatibility and Phase 6 lifecycle/tenant work.
- **Next unblocked phase:** Phase 6 can be implemented locally from this snapshot.
