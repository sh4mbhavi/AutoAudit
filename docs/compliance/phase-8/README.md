# Phase 8 — Highest-value coverage expansion

Date: 2026-09-06 (Australia/Melbourne).

Local engineering implemented. Upstream integration, hosted checks, live-tenant
validation and GRC approval remain pending. No public PR, production service,
external tenant, credential or repository setting was changed.

## Baseline and workspace

- Worktree: `/Users/clupa/Documents/projects/autoaudit/AutoAudit-phase-8`.
- Branch: `fix/soc2-phase-8-coverage-expansion`; uncommitted and unpushed.
- Git base: Phase 1 `8736fcb9`, overlaid with the complete Phase 7 working source.
  [phase-7-snapshot.json](phase-7-snapshot.json) records SHA-256 for all 895
  prerequisite files; the overlay was verified byte-identical before any Phase 8
  change. Every earlier worktree is preserved and untouched.
- Read-only upstream refresh: `bba14810f558190ee5221017c11864d300f8078a`,
  unchanged since the Phase 5, 6 and 7 handoffs. This stack still needs reviewed
  integration with current upstream and is not represented as based on it.
- [Coordination review](coordination-review.md) records the 43 open PRs and the
  collisions that must be resolved before merge.
- Phase 8 changes only: [phase-8-changes.json](phase-8-changes.json).
- Phase 7's recorded results were reproduced here before any change was made:
  engine 1,375 passed / 1 skipped / 11 xfailed; backend and tools 453 passed;
  `opa check --strict` clean; `opa test` 550/550.

## Wave A — Purview DLP and information protection

**The three controls are still `blocked` and still evaluate in no scan.** That is
the deliverable, not a shortfall: plan section 16.6 forbids promoting a `_pending`
collector without live-tenant validation, and no tenant exists here.

What now exists is everything required to *perform* that validation.

Microsoft's app-only page is explicit that Security & Compliance PowerShell
supports certificate authentication only, and that `-CertificateThumbPrint` is
Windows-only, so the Linux service has exactly one viable form. The executor's
previous `Connect-IPPSSession -AccessToken` branch — an auth mode Microsoft does
not document for app-only, and the exact thing `_pending/README.md` said does not
work — was deleted rather than extended. Two closed `OPERATIONS` entries carry a
`Select-Object` projection so evidence minimisation happens at the trust boundary
itself, and `resolve_certificate_alias(module, alias)` picks the environment
namespace **server-side from the operation's module**, so a Compliance request
cannot resolve a SharePoint certificate.

`-Organization` takes the tenant's primary `.onmicrosoft.com` domain, which a
tenant GUID is not, so the binding is its own domain-validated column that
rejects a GUID by name rather than overloading `tenant_id`.

### Candidate policies, and why no invariant was amended

`engine/tests/test_wiring.py` enforces a closed loop: a non-`ready` control must
have `policy_file: null`, and every `.rego` in a version directory must be
referenced by some control. A policy for a blocked control therefore cannot live
in the benchmark tree.

It does not have to. `_all_rego_files()` globs `*.rego` **non-recursively** from
the metadata's own directory, and `crosswalk.policy_corpus_digest` does the same,
so `engine/policies/candidate/` — a sibling of `cis/` — is invisible to both.
`find engine/policies/cis/.../v6.0.0 -name '*.rego'` still counts exactly 69.
No test was weakened, no `automation_status` value was added, and every pinned
census number holds unchanged.

Two hardenings make that isolation structural rather than test-only:
`capture_policy` now rejects any `policy_file` containing a path separator
(verified a no-op today — all 69 are flat filenames), and a test asserts no
candidate filename reaches the policy corpus digest.

The candidate policies still get `opa check --strict` and full semantic tests,
because those walk the whole `engine/policies` tree.

### What the policies decide, and what they refuse to

The licensed v6.0.0 procedure was not obtained; the only text available
self-declares `v6.0.1 – 2-26-2026`. That is recorded per candidate in
`candidates.json` and asserted by a test that reads the edition **from the
extract** rather than from a retyped literal — a provenance field that is only as
good as someone's transcription is not provenance.

- **3.2.2** has a real PowerShell procedure. Zero DLP policies is `indeterminate`
  — an empty tenant cannot be distinguished from an unentitled or unauthorized
  one. A tenant with DLP policies but none covering Teams is **not** a determinate
  violation either: 3.2.2's profile is **E5 Level 1 only**, an E3 tenant cannot
  create a Teams-workload policy at all, and calling an absent capability a
  violation would represent missing entitlement as noncompliance. `true` requires
  **every** returned Teams policy to have `Mode Enable` with `TeamsLocation All`,
  because audit steps 4 and 5 are applied to each returned policy; a partially
  enforcing tenant is reported and not decided.
- **3.2.1** and **3.3.1** can never return `true`. 3.2.1's audit is UI-only with
  an explicitly organizational criterion, and 3.3.1 states verbatim that the pass
  decision "is open to interpretation by the auditor". They decide the objective
  half only and express the rest as `compliant: null`, which Phase 3 already
  designed for: it stays in the coverage denominator and can never become a pass.

`deferred` was considered as the promotion target and rejected — `deferred`
controls are never dispatched and also cannot carry a `policy_file`, so the work
would have been permanently unreachable.

### Promotion is a mechanism, not a instruction

`tools/policies/promote_candidate.py --apply` refuses unless **every** blocking
gate in `candidates.json` is resolved **and** `--live-validation-evidence` names
an existing file. Six gates are recorded, all unresolved. Both refusals were
exercised and exit 1.

The promotion edit is **surgical**: only the two fields of the promoted control
change and every other byte of `metadata.json` is preserved, verified by
comparing the parsed documents. The full three-candidate sequence was exercised in
a throwaway copy with the gates forced resolved: ready 69→72, blocked 31→28, rego
69→72 — exactly the recorded `promotion_delta` — with `--check` clean at every
intermediate stage and `metadata.json` changing exactly four lines.

## Wave B — Real configuration drift

Five tables, not seven. The drift algorithm exists in exactly one place —
`engine/worker/drift.py` — and the backend only reads, governs baselines and
enqueues; there is no second comparison implementation to diverge.

**Normalized facts are never persisted.** `FACT_PROJECTIONS` declares, per
collector, named scalar fields whose names must already be pinned by that
collector's Phase 4 contract fixture, so no persisted field name is guessed, and
digesting whole top-level keys is forbidden — collectors return raw objects
alongside their scalars, and a top-level digest would fire on unrelated churn.

Member identity is `HMAC-SHA256`, never a bare digest: an unkeyed digest of a
boolean, a small enum, a policy name or a domain is a lookup table, not a
pseudonym. **Every digest is produced under a per-tenant subkey**, so two tenants
holding identical configuration do not produce identical digests — without that,
a holder of the store could bucket tenants by configuration and, controlling one
tenant, confirm another's values.

The feature gate is the key itself, not a boolean: with no key configured, zero
factprint rows are written and drift reports `fingerprints_unavailable`, while the
evaluation axis stays fully live. A weak or malformed key writes nothing and never
falls back to something unkeyed. Every row is bound to `phase8-draft-1`, exactly
as Phase 7 bound evidence to `phase7-draft-1`.

`drift_notification` carries `summary_counts` and nothing else — no control id,
no fact name, no member ref, no digest — so "notifications do not expose sensitive
evidence" is true by schema construction. (One qualification is recorded under
known gaps.)

## Defects this phase found and fixed in its own work

An adversarial six-dimension review of the code that actually landed found
defects a fully green suite walked straight past. The three most serious:

- **`verify_remediation` accepted a run that never looked.** It proved "the
  finding is gone" from the absence of an event key in any later `completed` run,
  but a run is `completed` when *either* axis is comparable, and the check
  consulted neither `configuration_comparable` nor `controls_skipped`. A run in
  which the control was never compared — collector errored, control deselected,
  fingerprint key unset — was accepted as proof of remediation. In an
  audit-evidence product that turns "we could not look" into "it is fixed", the
  same class of error as a failed collection becoming a pass. It now requires the
  finding's own axis to have been comparable and its control not to appear in
  `controls_skipped`.
- **`POST /v1/drift/runs` was a no-op.** It enqueued `worker.tasks.evaluate_drift`,
  which no worker registered; the endpoint answered 202 and the task was
  discarded. Its test asserted only the string being sent, so it was
  self-referential and passed while the feature was broken. The task is now
  registered, and a contract test reads the literal name out of the backend source
  and asserts the worker registers it.
- **The Purview binding could never be written.** Phase 8 added the columns, the
  schemas, the `connection_snapshot` tuple, the worker identity fields, the client
  kwargs and the executor branch — and neither `create_connection` nor
  `update_connection` persisted them, so the whole Wave A chain was unreachable
  from the API. The worker also never passed the binding to `PowerShellClient`.

Also fixed: drift never fired on the retry-exhausted finalisation path, so whether
a scan was compared depended on which control happened to finish last;
`member_digests` and `member_tokens` were sorted independently and so were not
parallel arrays, making set-member events name the wrong value; rotating the
fingerprint key manufactured a full set of false configuration events against an
untouched tenant, and is now an honest comparability break; `coverage_gained`
carried `severity_basis: "coverage_loss"`; `canonical_sorted` was documented as
the defence against ordering-induced false drift and was **never called** on the
digest path; and `drift_baseline.key_id` existed on the model but not in the
migration, so the column did not exist in the database at all.

## Defects found in existing code

- **`executor.py` leaked the service secret into every pwsh child.**
  `env = os.environ.copy()` handed `POWERSHELL_SERVICE_SECRET` and the entire
  SharePoint certificate path map to every subprocess of every module, with no
  test asserting what the child environment excludes. Replaced with an explicit
  allowlist plus only that module's own secrets.
- **`provenance.canonical_digest` sorts dict keys but preserves list order**, so
  a non-deterministic collection order would read as drift. Phase 8's
  canonicalisation sorts lists at every depth and states the ordering-semantics
  loss as a collector-contract obligation.
- **The Phase 6 timezone defect is fixed.** Reproduced here both ways before any
  change: `test_phase4_worker_contract` failed on an `Australia/Melbourne` cluster
  with `IndexError: pop from empty list` (the dispatcher published nothing) and
  passed on UTC. Phase 7 left it to Phase 6, but Phase 8 computes drift on scan
  finalisation, so on a non-UTC server this phase's own feature never fires at
  all. Eleven comparison sites now pin to `(now() AT TIME ZONE 'UTC')` — and,
  because correcting the comparisons alone is insufficient, the two naive columns
  those comparisons read (`scan_dispatch.available_at`, `scan.last_progress_at`)
  now default to UTC as well. **Both suites are now byte-identical on a Melbourne
  cluster and on UTC.** Converting the schema to `timestamptz` remains a
  Phase 6-owned decision; correcting the defaults did not require it.
- **`alembic/env.py` does not enable `compare_server_default`**, so autogenerate
  cannot see a server-default change at all. The `ALTER` statements are
  authoritative here. This blindness is why `drift_baseline.key_id` could exist on
  a model and not in the database without any gate noticing.

## Verification

Exact commands and results are in [verification.json](verification.json).

## Known gaps

Two review findings are recorded rather than fixed, with the fix specified:

- **`drift_notification.thread_key` is reversible.** It is the unkeyed
  `event_key` over `(drift_version, baseline_id, control_id, event_class,
  change_type, fact_name, member_ref)`, and `baseline_id` is a column on the same
  row, so a holder of only `drift_notification` can brute-force which control and
  fact a thread concerns from a small candidate space. What leaks is *which
  benchmark control* has a finding — never a tenant configuration value, and
  `summary_code` already discloses class and severity — but it weakens the
  "notifications carry no evidence" property, which is stated as structural. Fix:
  salt the preimage per baseline (a column on `drift_baseline`, absent from the
  notification row) and resolve the originating event through
  `drift_notification.drift_event_id` instead of by key equality. Not attempted
  here because it threads through roughly ten call sites and their tests, and a
  half-applied change would be worse than a documented one.
- **`SKIP_PROJECTION_CHANGED` can never fire.** `projection_id` is derived only
  from `collector_id` (`f"{collector_id}/v1"`) with no mechanism to bump the
  version, so changing a `FieldSpec`'s kind or vocabulary would silently compare
  incompatible shapes instead of skipping the control. Fix: derive the projection
  id from the declared field set, so any change to it changes the id.

Inherited and unchanged from earlier phases:

- **No enum/enum_set projection ships.** Both kinds are implemented,
  CHECK-constrained and tested, but every shipped field is `bool` or `int`,
  because those are the only scalar keys the existing Phase 4 contract fixtures
  pin and a persisted field name is never guessed. Member-level added/removed
  events therefore cannot fire in a default deployment; field-level ones can.
- **No egress channel.** One `inapp` channel, CHECK-enforced. SMTP or webhook
  delivery needs a lock regeneration and D05 approval of what may leave the
  system; recorded as a pending decision, not silently omitted.
- **No scheduler.** Drift fires on scan finalisation and on explicit request.
  Two scans that are never compared produce no run, and the API answers
  `not_run` rather than implying stability.
- **No frontend UI.** Types only, matching the Phase 7 precedent.
- **Phase 0 decisions D01–D10 remain unapproved** with no named owners, so
  retention is labelled `phase8-draft-1` and the mapping stays `approved: false`.
- **Phase 4's required status checks were still never applied to branch
  protection**, so a green local run is not an enforced gate.
- **The Compose overlay was not exercised against a running container**;
  `container_smoke.py` was not re-run.
- **`alembic/env.py` does not enable `compare_server_default`**, so no gate can
  see a server-default divergence between a model and the database.

## Independent review

**Codex was unavailable for this phase** — rate-limited until 2026-09-07 12:38,
the same limit Phase 7 recorded. No Codex review was performed for any Phase 8
stream. Gemini (Antigravity CLI, gemini-3.5-flash) substituted on the two
highest-risk new modules and returned five candidate defects: two were confirmed
and fixed (cross-tenant digest comparability; `canonical_sorted` never called),
one was a documentation issue, and two were adjudicated as not defects with the
reasoning recorded — plaintext `observed_value` is a deliberate, D05-permitted
decision, and the empty-collection path yields `indeterminate` rather than a
false verdict.

A six-dimension adversarial review of the landed code, with independent refuters
per finding, produced 34 findings; the three criticals and most highs are fixed
above. **That substitution is weaker than the standing Codex instruction, and
this phase should get an independent human or Codex review before merge.** Phase
7's integration work also went un-reviewed for the same reason; that has now
happened twice and should not be allowed to become routine.

## Standard handoff

- **Phase:** 8 — local engineering implemented; external acceptance pending.
- **Baseline:** `8736fcb9` plus the exact 895-file Phase 7 prerequisite snapshot.
- **Branch/commit/PR:** `fix/soc2-phase-8-coverage-expansion`; uncommitted/unpushed; no PR.
- **Findings addressed locally:** none of the numbered plan findings close here.
  Phase 8 is coverage expansion, not remediation. It does fix a confirmed Phase 6
  lifecycle defect and a live secret-inheritance defect in the Phase 5 executor.
- **Files changed:** [phase-8-changes.json](phase-8-changes.json).
- **Decisions:** candidate policies outside the benchmark tree so no invariant is
  amended; promotion as a refusing tool rather than an instruction; the fingerprint
  key as the feature gate; per-tenant subkeys; drift computed in exactly one place;
  notifications that carry counts and codes only; `compliant: null` wherever the
  benchmark assigns the decision to a human.
- **Tests:** see [verification.json](verification.json).
- **Security/GRC review required:** [grc-review-request.md](grc-review-request.md)
  asks a named GRC approver about CC6.1-P06, CC6.7-P20, CC7.1-P28 and the CC4
  coverage line, and changes nothing. `approval.approved` is still `false`.
- **Next unblocked phase:** Phase 9 may proceed. Phase 8's own promotion remains
  gated on live-tenant validation and the licensed v6.0.0 procedure.
