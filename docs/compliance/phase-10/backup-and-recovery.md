# Backup and recovery

Date: 2026-09-07 (Australia/Melbourne).

This describes what `tools/ops/backup.py` does, what it deliberately does not do,
and which numbers below are proposals rather than commitments.

Before Phase 10 there was nothing to describe. No `pg_dump`, no snapshot step,
no restore script, no stated RPO or RTO, and no backup service in any compose
file. The only strings in the repository matching "backup" belonged to
`security/strategies/regular_backups.py`, which is a **scanner** that grades a
*customer's* backup evidence against ACSC Essential Eight ML1/ML2. AutoAudit
shipped a tool that would have failed AutoAudit on every one of those controls.

## What is durable, and therefore what is backed up

| State | Where | Backed up | Why |
|---|---|---|---|
| Scans, results, provenance, factprints, drift rows, the evidence audit trail | `postgres_data` volume | Yes, `pg_dump --format=custom` | This is the audit record. |
| Uploaded evidence objects and generated reports | `evidence_store` volume | Yes, as a tar archive | The `evidence_artifact` rows are pointers; a database-only backup restores an audit trail whose objects are all missing. |
| Broker state (queued and in-flight tasks) | Redis | **No, deliberately** | `infrastructure/runtime/redis.conf` sets `save ""` and `appendonly no`, and the production compose mounts `/data` as tmpfs. Phase 6 made PostgreSQL the owner of retry state precisely so broker loss is recoverable without a broker backup: the outbox rows survive and the dispatcher republishes. |
| Policy corpus, crosswalk mapping, container images | The source revision | **No** | Rebuilt from source. `tools/ops/release_manifest.py` records the digests that make a rebuild verifiable. |

## The manifest

Every backup writes `manifest.json` recording, for each artifact, its SHA-256 and
byte size; plus the Alembic revision the database was at, the server's version,
and the retention policy version in force.

`restore` verifies every digest **before** it writes anything, and refuses a
cross-major-version restore rather than letting `pg_restore` fail halfway. That
refusal is not hypothetical: until Phase 10, `docker-compose.yml` ran PostgreSQL
17 while CI, `tools/ci/container_smoke.py` and `docker-compose.production.yml`
all ran 16, so a dump taken from a developer's volume would not have restored
into production. Phase 10 aligned the versions and
`tools/tests/test_phase10_deployment.py` now fails if they diverge again.

Recording the Alembic revision matters for a reason worth stating: restoring a
dump into a deployment running different code is where a backup is least useful
and most dangerous, because the row shapes would not match what the application
expects. The revision is in the manifest so that mismatch is visible before the
restore rather than after it.

## Proposed objectives — **not commitments**

These are engineering proposals for the platform owner and GRC to accept, amend
or reject. Nothing enforces them, nothing schedules a backup, and no deployment
has ever taken one.

| | Proposal | Basis |
|---|---|---|
| RPO | 24 hours | A daily dump. Scans are user-initiated and re-runnable: a re-run produces new evidence with its own provenance rather than reconstructing the old, so the irreplaceable loss is *uploaded* evidence and the *historical* audit record, not the ability to assess a tenant again. |
| RTO | 4 hours | Restore is a `pg_restore` plus a tar extraction, both bounded by volume size. The dominant term is human: noticing, deciding, and provisioning a target. |
| Backup retention | 35 days | Follows D04's proposal for "backups containing evidence": a maximum 35-day expiry after primary deletion. **D04 is unapproved.** |
| Restore test cadence | Quarterly | More frequent than CC9's annual cadence in the organizational register, deliberately: a restore is the one control whose failure is invisible until it is needed. |

**Every number here is unapproved.** Phase 0 decision D04 governs evidence
retention, has no named owners, and states in terms that it is "not a legal
minimum or an existing product commitment". An RPO is a promise to a customer;
engineering can propose one and cannot make one.

## Gaps, stated plainly

**The archive is not encrypted.** It contains every scan result, provenance
record and uploaded evidence object in plaintext. `ENCRYPTION_KEY` protects
stored M365 client secrets *inside* the database and does not protect a dump of
it. Encrypting the archive properly needs a backup key that is **not** the
application's key — restoring with the application key would make a stolen
backup and a stolen application secret the same compromise — and deciding where
that key lives is a deployment decision this repository cannot make. Until then
the archive must be stored on an encrypted volume with access control, and the
manifest says so in its `encryption` block rather than leaving a reader to
assume.

**Nothing schedules a backup.** There is no scheduler anywhere in the product:
no Celery beat, no cron, no periodic task. Phase 8 recorded the same absence for
drift. `backup.py` is an operator entry point, and a backup that is never run is
worth exactly what one that does not exist is worth.

**D04's deletion tombstones are not re-applied on restore.** D04 proposes that a
restore must reapply deletion tombstones before serving data, so a restore does
not resurrect evidence a customer asked to be deleted. `restore` does not do
this. It cannot be built correctly against an unapproved policy — what counts as
a tombstone, and how long one is retained, are exactly what D04 decides — and
building it against a guess would produce a mechanism that looks like compliance
with a policy nobody approved. Recorded as a gap.

**The restore has been tested here, not in production.**
`tools/tests/test_phase10_backup_restore.py` takes a real dump of a real migrated
database with real rows and evidence bytes, destroys the source, restores into a
fresh database, and asserts the rows and bytes came back. That is a tested
restore procedure. It is not a tested *production* restore, because there is no
production environment — recorded as risk R-07 in the Risk and Impact
Prioritisation Matrix and unchanged by this phase.

## Running one

```sh
# Take a backup. --taken-at is supplied by the caller so the manifest is
# reproducible rather than dependent on when the tool happened to run.
python tools/ops/backup.py create \
  --into /backups/$(date -u +%Y-%m-%dT%H%M%SZ) \
  --database-url "$DATABASE_URL" \
  --evidence-dir /var/lib/autoaudit/evidence-store \
  --taken-at "$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Verify one without restoring it. Run this on a schedule: an unverified backup
# is an assumption.
python tools/ops/backup.py verify --from /backups/2026-09-07T000000Z

# Restore into a target. Verifies every digest first and refuses a cross-major
# restore.
python tools/ops/backup.py restore \
  --from /backups/2026-09-07T000000Z \
  --target-url "$RECOVERY_DATABASE_URL" \
  --evidence-dir /var/lib/autoaudit/evidence-store
```

`--evidence-dir` is the evidence store itself, and the archive's fixed root is
stripped on extraction so the objects land directly in it. `restore` refuses a
target database that already contains tables — restoring into a populated
database merges two datasets rather than replacing one, and the most likely
wrong `--target-url` an operator types is the production one. Override with
`--allow-nonempty` only deliberately.

After any restore, before serving traffic:

1. Confirm the restored Alembic revision matches the deployed code's expectation
   (`uv run --project backend-api alembic heads`).
2. Confirm the deployment carries an encryption key ring that can read the
   restored `m365_connection` rows: `python tools/ops/rotate_encryption_key.py
   --check`. A restore into a deployment whose key has since rotated is the
   likeliest way to end up with unreadable credentials, and it reports by
   connection id without printing key material.
3. Confirm `GET /readiness` reports ready before removing the maintenance page.
