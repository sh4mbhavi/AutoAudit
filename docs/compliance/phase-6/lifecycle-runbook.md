# Scan lifecycle operations

## State and transaction contract

| From | Allowed destination | Meaning |
|---|---|---|
| pending | running | Durable child dispatch intents have been created. |
| pending/running | completed | All selected results have terminal assessment/capability outcomes. |
| pending/running | failed | Context, deadline or exhausted dispatch prevents completion; unresolved rows are errors. |
| pending/running | cancelled | Owner stopped the scan; unresolved rows are indeterminate. |
| completed/failed/cancelled | none | Terminal evidence and lifecycle cannot be reopened by tasks. |

A scan may complete with errors or indeterminate controls; `completed` never
means all controls passed. Compliance and coverage remain separate. New API scans
have a positive explicit selection; old scans retain unknown attribution.

Lock order is parent scan, then result/outbox children. Result writes use a
conditional pending predicate. Finalization takes the parent lock before reading
pending rows and aggregates. Do not add delivery-driven result counter increments.

Deletion is owner-authorized hard deletion under the same parent lock. Queued or
running messages for deleted IDs safely no-op. Cancellation retains evidence and
is preferable when a record of interrupted assessment is needed.

## Running recovery

Run migrations before rollout, start the worker and the **dispatcher**. Both
Compose templates include it. Without the dispatcher new scans remain durably
pending until it resumes; there is no HTTP retry workaround.

```sh
# One operator recovery pass (from engine/, with normal validated runtime env)
python -m worker.dispatcher --once
# Supervised service, or use the Compose dispatcher service
python -m worker.dispatcher
```

The dispatcher stores publication/retry state in PostgreSQL. A broker outage
backs off; restoring Redis allows due work to publish. A crash after sending but
before committing may duplicate a task with its same ID; SQL result transitions
provide idempotency. Multiple dispatchers are supported via parent locking and
rechecks. A busy parent does not block unrelated candidate scans.

| Setting | Default | Purpose |
|---|---:|---|
| SCAN_DEADLINE_SECONDS | 3600 | Absolute new-scan deadline; set consistently on API/worker/dispatcher. |
| DISPATCH_POLL_SECONDS | 5 | Delay between independent database recovery passes. |
| DISPATCH_RETRY_SECONDS | 15 | Initial broker-failure backoff; doubles to a 300-second cap. |
| DISPATCH_STALL_SECONDS | 1200 | Delay before a sent, unresolved task becomes eligible for replay. |
| DISPATCH_MAX_ATTEMPTS | 8 | Bounded publication/replay attempts before visible failure. |
| DISPATCH_BATCH_SIZE | 100 | Maximum due publication candidates in a pass. |

Deadlines are enforced when the reconciler next obtains the scan lock. They are
not an immediate process kill or a guarantee that a slow in-flight remote read
ends at that exact second. Broker connection/socket timeouts bound normal network
outage waits; the dispatcher must be supervised and its fixed error events monitored.

The scan read/list/summary API exposes `dispatch_id`, `dispatch_count`,
`last_progress_at`, `deadline_at` and `lifecycle_version`. `dispatch_count` records
committed successful sends, including replay, not completed controls. Inspect
`scan_dispatch.attempts`, `available_at`, `dispatched_at`, `last_error` alongside
result reason codes for diagnosis. Never copy broker credentials into an incident
log. Failed/cancelled scans require a new scan rather than reopening old evidence.

## SharePoint provisioning

Save `sharepoint_admin_url`, `sharepoint_tenant_id` and
`sharepoint_certificate_alias` together on the selected M365 connection. The
frontend derives the SharePoint tenant field from the M365 tenant. The API requires
a matching GUID, commercial-cloud HTTPS admin URL, and an alias of 1–64 characters,
starting with a letter/digit and continuing with letters, digits, `_` or `-`.
Clearing all three fields disables that binding.

The deployment owner provisions the corresponding service-side certificate alias
mapping and mounted certificate/password material. A database alias is a reference,
never a certificate path. Preserve existing encryption keys and database volumes.

The selected Graph application needs `Sites.Read.All` in addition to existing
control-specific permissions. The worker requests the tenant root site and requires
its returned SharePoint tenant ID and hostname to agree with the selected connection.
No proof, including an unavailable tenant facet or a 403, means indeterminate. A
configured GUID alone is not tenant proof. Changes to tenant/client/SharePoint
identity after scan creation require a new scan; new credentials for unchanged
identity can be rotated without changing frozen attribution.

API sources: [Microsoft Graph root-site retrieval](https://learn.microsoft.com/en-us/graph/api/site-get?view=graph-rest-1.0)
and [SharePoint tenant identifiers](https://learn.microsoft.com/en-us/graph/api/resources/sharepointids?view=graph-rest-1.0).
Locking follows [PostgreSQL SELECT locking semantics](https://www.postgresql.org/docs/current/sql-select.html)
and [Read Committed transaction behavior](https://www.postgresql.org/docs/current/transaction-iso.html).

## Rollout and rollback

Integrate and review the complete prerequisite stack first. Deploy migration,
API, worker, frontend and dispatcher together with the Phase 5 identifier-only
message contract. Do not reintroduce old credential-bearing tasks or global
SharePoint configuration. Handle historical broker material under the existing
incident process.

Migration is forward-only. Operational rollback must preserve the outbox and
cancelled-state contract; running an older worker that can mutate terminal scans
is not a compatible rollback. Pause execution services while preparing a corrected
build if needed, retaining PostgreSQL data for recovery. No owner infrastructure,
credential, or upstream branch setting is changed by this local implementation.
