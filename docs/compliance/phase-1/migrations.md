# DB-01: merge the Alembic heads

Validated locally on 2026-09-05 against baseline `be241f52`, on branch
`fix/soc2-phase-1-containment`. The prior graph had two heads:
`ccf7645372fc` (manual verification detail) and `d87c3bb49953` (user profile fields).
Normal `alembic upgrade head` failed with `Multiple head revisions are present`.

The new revision `2899a0e678b6` joins those two parents. Its upgrade and downgrade
perform no schema or data operations. This reproduces the merge approach reviewed
in PR #352 at `1cb1399f05f032c6d214429407c16f8c66a3ea09`. Existing migration files
are unchanged. No production database was accessed.

## Regression and PostgreSQL evidence

The regression was added before the merge migration. From `backend-api`:

```sh
uv sync --frozen
uv run --frozen --with pytest pytest -q tests/test_migrations.py
```

The initial graph-only test failed: `AssertionError: ['ccf7645372fc', 'd87c3bb49953']`
(`1 failed in 2.47s`). After adding integration coverage, the same suite with
`MIGRATION_TEST_ADMIN_URL` set failed all five cases before the fix
(`5 failed in 3.71s`): the graph assertion and all four real upgrade paths failed
because the graph had multiple heads.

A disposable PostgreSQL **16.14 (Homebrew)** cluster was created and bound only to
`127.0.0.1:55432`. The exact setup commands were:

```sh
mktemp -d /tmp/autoaudit-pg-phase1.XXXXXX
# Returned /tmp/autoaudit-pg-phase1.DFb8QX
/opt/homebrew/opt/postgresql@16/bin/initdb -D /tmp/autoaudit-pg-phase1.DFb8QX/data -U autoaudit_migration --auth-local=trust --auth-host=trust
/opt/homebrew/opt/postgresql@16/bin/pg_ctl -D /tmp/autoaudit-pg-phase1.DFb8QX/data -l /tmp/autoaudit-pg-phase1.DFb8QX/postgres.log -o '-h 127.0.0.1 -p 55432 -k /tmp/autoaudit-pg-phase1.DFb8QX' -w start
```

The cluster contains only synthetic fixtures. Each parameterized test creates a
randomly named `autoaudit_migration_test_*` database and drops it in teardown;
the admin database is never migrated. The URL guard requires a loopback IP.

After adding the merge, final verification from `backend-api` was:

```sh
uv tool run ruff check tests/test_migrations.py alembic/versions/2899a0e678b6_merge_migration_heads.py
MIGRATION_TEST_ADMIN_URL=postgresql://autoaudit_migration@127.0.0.1:55432/postgres uv run --frozen --with pytest pytest -q tests/test_migrations.py
uv run --frozen alembic heads
```

Results: **All checks passed; 5 passed in 5.66s; `2899a0e678b6 (head)`**.

| Starting database | Result |
| --- | --- |
| Empty database | Full migration history completes; both branch additions exist; one merged version marker |
| Populated `ccf7645372fc` | Profile branch applied; original rows and values preserved; one merged version marker |
| Populated `d87c3bb49953` | Manual verification branch applied; original rows and values preserved; one merged version marker |
| Populated database with both previous heads | Merge changes version markers only; complete application row snapshots unchanged |

Synthetic fixtures include a user, M365 connection, scan, JSONB scan evidence,
OAuth account with a token over 1,024 characters, evidence validation, user
settings, contact submission, note and history, plus manual verification and
profile values wherever their starting branch exists. All public application
tables are snapshotted; row counts and every pre-existing column value are
compared after upgrade, including timestamps and linked IDs. The suite checks
that both branch schema additions exist and that repeating `upgrade head`
preserves all application rows and the single version marker.

## Rollback boundary

On the populated both-heads fixture, the test also executed:

```sh
alembic downgrade ccf7645372fc
alembic upgrade head
```

The explicit downgrade restores **both** prior version markers, leaves all
application row snapshots unchanged, and permits successful re-upgrade. A trial
of `alembic downgrade -1` failed with `Ambiguous walk`; use the explicit tested
revision when reverting only this merge. Downgrading older schema revisions is
outside this validation and may remove their tables or columns.

## Cleanup and limitations

```sh
/opt/homebrew/opt/postgresql@16/bin/psql -h 127.0.0.1 -p 55432 -U autoaudit_migration -d postgres -Atc "SELECT count(*) FROM pg_database WHERE datname LIKE 'autoaudit_migration_test_%'"
/opt/homebrew/opt/postgresql@16/bin/pg_ctl -D /tmp/autoaudit-pg-phase1.DFb8QX/data -m fast -w stop
```

Results: `0` remaining test databases; `server stopped`. The temporary cluster
directory remains available for inspection or restarting these local checks.

The populated current-schema case is a synthetic representative database with
both known heads, not a copy of a deployed database. Unknown deployed schema
drift, legacy revision stamps, concurrent migration processes, production data
volume and lock timing were not tested. Integration cases skip when
`MIGRATION_TEST_ADMIN_URL` is absent; a passing graph-only run is not evidence
that the four PostgreSQL cases ran. This document records local migration
validation, not a production rollout or a SOC 2 compliance conclusion.
