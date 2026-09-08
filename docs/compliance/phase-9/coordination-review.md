# Phase 9 coordination review

Date: 2026-09-06 (Australia/Melbourne).

Read-only. No public PR was opened, merged, closed or commented on, and no
repository setting was changed. This records what must be resolved *before* the
Phase 9 branch can be merged, per plan section 4.2.

## Baseline movement

Phase 8 recorded upstream `main` at `bba14810f558190ee5221017c11864d300f8078a`.
It has moved: **`bfb8edd44414683ac4adcde3ab79d4520a0a00a3`** (PR #292,
"26T2-BE-PG-001", merged 2026-09-06 18:24 +1000). Eighteen files changed.

One of them is a Phase 9 file. PR #292 put `require_auditor_or_above` on
`create_scan` and `delete_scan` in `backend-api/app/api/v1/scans.py`. Phase 9
changes `get_scan`, `get_scan_summary` and `get_scan_results` in the same file.
The two edits are textually adjacent and semantically independent — Phase 9 adds
no dependency to those two handlers and removes none — so this is a mechanical
rebase, not a conflict of intent.

This branch is still based on Phase 1 `8736fcb9` overlaid with the Phase 8
working source, exactly as Phase 8 was. It is **not** represented as based on
current upstream, and integration with upstream remains unreviewed work that
Phase 7's handoff first flagged.

## Open pull requests

46 open at the time of writing; the full listing with per-PR file lists is in
[pull-requests-2026-09-06.json](pull-requests-2026-09-06.json) and the computed
overlap is in [collisions.json](collisions.json). Twelve touch a file Phase 9
changes. Two of those are real conflicts of intent rather than adjacent edits.

### PR #351 — multi-client collector support (`feature/26T2-SEC-EG-005-multi-api`)

**Hard conflict.** It rewrites the client-construction block inside
`worker/tasks.py:_evaluate_control_async` so a collector can declare
`required_clients = ("graph", "dvm")` and receive a dict of clients. Phase 9
rewrote that same function into `_evaluate_collection_async`, which now builds
**one** client for a whole collection group rather than one per control.

The two are compatible in substance and cannot both be applied textually. The
resolution is to land #351's `BaseMultiClientCollector` and its
`required_clients` dispatch **inside** Phase 9's single client-construction site,
next to `collectors/routing.py:uses_powershell` — which is exactly the "one place
that decides which client a collector needs" that Phase 9 created because the
rule had been written three times. Sharing one client set per group is strictly
better for a multi-client collector than building two clients per control.

Whoever merges second owns this. It should be a deliberate rebase by someone who
has read both, not a conflict resolution.

### PR #364 — E8 UAH Settings Catalog support (`feature/e8-uah-configuration-policies`)

**Textual conflict, compatible intent.** It edits the exact serial per-policy
loop in `entra/devices/configuration_policies.py` that Phase 9 replaced with
`gather_bounded`, and adds `params={"$expand": "assignments"}` to the list call
plus four E8-UAH controls to the Essential Eight metadata.

Both changes are wanted. `$expand=assignments` applies cleanly to the bounded
version — it is on the list request, not the per-policy loop — and the metadata
additions do not touch Phase 9 at all. Rebase, do not re-litigate.

### The other ten

Adjacent edits with no shared function:

| PR | Shared file(s) | Nature |
|---|---|---|
| #350 Google SSO | `ci.backend-api.yml`, `main.py`, `asr_rules.py`, `client.ts` | four files, four unrelated regions |
| #266 HPA/KEDA scaling | `main.py`, `powershell/service/{executor,main}.py`, `worker/tasks.py` | worth a second look: it also changes how the PowerShell service scales, which interacts with Phase 9's `POWERSHELL_MAX_CONCURRENCY` bound |
| #361, #358, #318, #302, #300 | `backend-api/app/main.py` | five PRs queued on one file; Phase 9 adds two CORS header entries |
| #355, #313, #294 | `ci.backend-api.yml` | Phase 9 adds one step |

**PR #266 deserves review alongside Phase 9 rather than after it.** Phase 9 gives
the PowerShell service its own bounded execution pool
(`POWERSHELL_MAX_CONCURRENCY`, default 4) in place of Starlette's shared 40-slot
threadpool. A horizontal autoscaler that scales that service on queue depth needs
to know the per-replica bound exists, or it will scale on a signal the bound is
already controlling.

## What this review did not do

- It did not open, merge, close, rebase or comment on any pull request.
- It did not read the full diff of every one of the 46 open PRs. The overlap
  above is computed from the GitHub file lists; #351 and #364 were read in full
  because they collide semantically, and #292 was read because it has already
  landed on a Phase 9 file.
- It did not integrate this branch with current upstream. That work is still
  outstanding from Phase 7 and is a prerequisite for merging any of this stack.
