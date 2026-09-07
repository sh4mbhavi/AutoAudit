"""Database access for the Celery worker.

Uses synchronous SQLAlchemy since Celery tasks are synchronous.
For async operations within tasks, use asyncio.run().

---
Extending for other cloud providers
---

Right now this module only handles M365 connections. The backend schema already
has tables for azure_connection, gcp_connection, and aws_connection - we just
haven't built the credential storage for those yet.

When you add a new provider, you'll need to:

1. Add a get_<provider>_credentials() function that queries the relevant table
   and decrypts any secrets. Look at how get_scan() joins to m365_connection
   for the pattern.

2. Update get_scan() to also pull from the new connection table. The scan table
   has nullable FKs for each provider (azure_connection_id, gcp_connection_id,
   aws_connection_id) - only one will be non-null per scan.

3. Add a collector in /engine/collectors/<provider>/ that knows how to use
   those credentials to call the provider's APIs.

4. The task in tasks.py will need a branch to pick the right collector based on
   which connection ID is populated on the scan.

The encryption approach is the same across all providers - Fernet symmetric
encryption with the key from ENCRYPTION_KEY env var. See decrypt() below.
"""

import json
from contextlib import contextmanager
from datetime import datetime
from typing import Generator

from cryptography.fernet import Fernet, MultiFernet
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from worker.config import settings
from worker.result_contract import TERMINAL_STATES, calculate_scores

# Convert async URL to sync URL for worker
sync_database_url = settings.DATABASE_URL.replace(
    "postgresql+asyncpg://", "postgresql://"
)

# Create sync engine and session factory
engine = create_engine(sync_database_url, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)


@contextmanager
def get_db_session() -> Generator[Session, None, None]:
    """Get a database session context manager."""
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


# Fernet key ring for decryption. The worker never encrypts, so it only ever
# needs the read half: ENCRYPTION_KEY plus every retired key still listed in
# ENCRYPTION_KEY_DECRYPT_ONLY. During a rotation the API and the worker are
# updated at different times by construction, so the worker has to be able to
# read rows written under either key -- otherwise a partially rolled deployment
# fails at scan time, deep inside a collection, as an InvalidToken.
#
# The name stays `_fernet` because engine/tests/test_phase3_migrated_integration
# monkeypatches it with a plain Fernet; MultiFernet and Fernet share the
# decrypt() signature, so that substitution keeps working.
_fernet: MultiFernet | Fernet | None = None


def get_fernet() -> MultiFernet | Fernet:
    """Get or create the key ring used for credential decryption."""
    global _fernet
    if _fernet is None:
        if not settings.ENCRYPTION_KEY:
            raise ValueError("ENCRYPTION_KEY environment variable is required")
        keys = [Fernet(settings.ENCRYPTION_KEY.encode())]
        keys.extend(Fernet(key.encode()) for key in settings.decrypt_only_keys())
        _fernet = MultiFernet(keys)
    return _fernet


def reset_key_ring() -> None:
    """Drop the cached key ring so the next call re-reads configuration."""
    global _fernet
    _fernet = None


def decrypt(ciphertext: str) -> str:
    """Decrypt a ciphertext string under any key in the ring."""
    if not ciphertext:
        return ""
    return get_fernet().decrypt(ciphertext.encode()).decode()


def get_scan(session: Session, scan_id: int) -> dict | None:
    """Get scan details by ID.

    Returns scan context without loading or decrypting credentials.
    For other providers, you'd add similar joins here - see module docstring.
    """
    result = session.execute(
        text("""
            SELECT s.id, s.user_id,
                   s.m365_connection_id, s.azure_connection_id,
                   s.gcp_connection_id, s.aws_connection_id,
                   s.framework, s.benchmark, s.version,
                   s.status, s.started_at, s.finished_at,
                   s.compliance_score, s.total_controls, s.passed_count,
                   s.failed_count, s.skipped_count, s.error_count, s.notes,
                   s.selected_count, s.semantics_version, s.metadata_snapshot,
                   s.metadata_digest, s.correlation_id, s.connection_snapshot,
                   s.dispatch_id, s.dispatch_count, s.last_progress_at,
                   s.deadline_at, s.lifecycle_version
            FROM scan s
            WHERE s.id = :scan_id
        """),
        {"scan_id": scan_id},
    )
    row = result.fetchone()
    if not row:
        return None

    return {
        "id": row.id,
        "connection_snapshot": row.connection_snapshot,
        "dispatch_id": row.dispatch_id,
        "dispatch_count": row.dispatch_count,
        "last_progress_at": row.last_progress_at,
        "deadline_at": row.deadline_at,
        "lifecycle_version": row.lifecycle_version,
        "selected_count": row.selected_count,
        "semantics_version": row.semantics_version,
        "metadata_snapshot": row.metadata_snapshot,
        "metadata_digest": row.metadata_digest,
        "correlation_id": row.correlation_id,
        "user_id": row.user_id,
        # Connection IDs - only one of these should be set per scan
        "m365_connection_id": row.m365_connection_id,
        "azure_connection_id": row.azure_connection_id,
        "gcp_connection_id": row.gcp_connection_id,
        "aws_connection_id": row.aws_connection_id,
        # What we're scanning against
        "framework": row.framework,
        "benchmark": row.benchmark,
        "version": row.version,
        # Status and timing
        "status": row.status,
        "started_at": row.started_at,
        "finished_at": row.finished_at,
        # Results
        "compliance_score": row.compliance_score,
        "total_controls": row.total_controls,
        "passed_count": row.passed_count,
        "failed_count": row.failed_count,
        "skipped_count": row.skipped_count,
        "error_count": row.error_count,
        "notes": row.notes,
    }


def get_execution_result(session: Session, scan_id: int, result_id: int) -> dict | None:
    """Resolve the result through its parent scan before any credential access."""
    row = (
        session.execute(
            text("""
        SELECT id, control_id, status, selected FROM scan_result
        WHERE id=:result_id AND scan_id=:scan_id
    """),
            {"scan_id": scan_id, "result_id": result_id},
        )
        .mappings()
        .first()
    )
    return dict(row) if row else None


def get_execution_credentials(
    session: Session, scan_id: int, connection_id: int
) -> dict:
    """Decrypt only the connection owned by this scan's user, inside execution."""
    row = (
        session.execute(
            text("""
        SELECT c.tenant_id, c.client_id, c.encrypted_client_secret,
               c.is_active, c.sharepoint_admin_url, c.sharepoint_tenant_id,
               c.sharepoint_certificate_alias, c.compliance_certificate_alias,
               c.compliance_organization, s.connection_snapshot
        FROM scan s JOIN m365_connection c
          ON c.id=s.m365_connection_id AND c.user_id=s.user_id
        WHERE s.id=:scan_id AND c.id=:connection_id
    """),
            {"scan_id": scan_id, "connection_id": connection_id},
        )
        .mappings()
        .first()
    )
    if not row:
        raise ValueError("Scan connection unavailable")
    if not row["is_active"]:
        raise ValueError("Scan connection inactive")
    snapshot = row["connection_snapshot"]
    identity_fields = (
        "tenant_id",
        "client_id",
        "sharepoint_admin_url",
        "sharepoint_tenant_id",
        "sharepoint_certificate_alias",
        "compliance_certificate_alias",
        "compliance_organization",
    )
    if snapshot is not None and any(
        snapshot.get(key) != row[key] for key in identity_fields
    ):
        raise ValueError("Scan connection identity changed")
    if not row["encrypted_client_secret"]:
        raise ValueError("Scan credential unavailable")
    return {
        "tenant_id": row["tenant_id"],
        "client_id": row["client_id"],
        "client_secret": decrypt(row["encrypted_client_secret"]),
        **{
            key: row[key] if snapshot is not None else None
            for key in identity_fields[2:]
        },
    }


def get_pending_scan_results(session: Session, scan_id: int) -> list[dict]:
    """Get all scan results with status='pending' for a scan.

    Returns list of dicts with result details including control metadata.
    """
    result = session.execute(
        text("""
            SELECT id, scan_id, control_id, status, message, evidence
            FROM scan_result
            WHERE scan_id = :scan_id AND status = 'pending'
            ORDER BY control_id
        """),
        {"scan_id": scan_id},
    )
    rows = result.fetchall()
    return [
        {
            "id": row.id,
            "scan_id": row.scan_id,
            "control_id": row.control_id,
            "status": row.status,
            "message": row.message,
            "evidence": row.evidence,
        }
        for row in rows
    ]


def get_collection_results(
    session: Session, scan_id: int, control_ids: list[str]
) -> list[dict]:
    """Pending, selected results for the named controls, ordered by control id.

    The order is what makes a collection group's execution deterministic: the
    same scan always evaluates the same controls against the same shared
    collection in the same sequence.
    """
    if not control_ids:
        return []
    rows = (
        session.execute(
            text("""
        SELECT id, control_id, status, selected FROM scan_result
        WHERE scan_id=:scan_id AND status='pending' AND selected IS TRUE
          AND control_id = ANY(:control_ids)
        ORDER BY control_id
    """),
            {"scan_id": scan_id, "control_ids": list(control_ids)},
        )
        .mappings()
        .all()
    )
    return [dict(row) for row in rows]


def update_scan_status(
    session: Session,
    scan_id: int,
    status: str,
    finished_at: datetime | None = None,
    notes: str | None = None,
) -> None:
    """Change lifecycle fields; result-derived summaries are updated separately."""
    if status not in {"running", "completed", "failed", "cancelled"}:
        raise ValueError("Invalid scan transition")
    # SQL predicate applies after waiting for concurrent parent writers.
    # PostgreSQL now() is timestamptz; these columns are TIMESTAMP WITHOUT TIME ZONE.
    # AT TIME ZONE 'UTC' pins the comparison to UTC on any server timezone. Removing
    # it reintroduces the Phase 6 non-UTC dispatcher failure.
    updates = ["status=:status", "last_progress_at=(now() AT TIME ZONE 'UTC')"]
    params = {"scan_id": scan_id, "status": status}
    if finished_at is not None:
        updates.append("finished_at=:finished_at")
        params["finished_at"] = finished_at
    if notes is not None:
        updates.append("notes=:notes")
        params["notes"] = notes
    session.execute(
        text(
            "UPDATE scan SET "
            + ", ".join(updates)
            + " WHERE id=:scan_id AND status IN ('pending', 'running')"
            + (" AND status='pending'" if status == "running" else "")
        ),
        params,
    )


def lock_scan(session: Session, scan_id: int) -> dict | None:
    """Every writer locks the parent before touching result/outbox children."""
    row = (
        session.execute(
            text("SELECT id, status FROM scan WHERE id=:scan_id FOR UPDATE"),
            {"scan_id": scan_id},
        )
        .mappings()
        .first()
    )
    return dict(row) if row else None


def update_scan_result(
    session: Session,
    result_id: int,
    status: str,
    message: str | None = None,
    evidence: dict | None = None,
    reason_code: str | None = None,
    provenance: dict | None = None,
) -> bool:
    """First terminal write wins; subsequent deliveries cannot replace evidence."""
    if status not in TERMINAL_STATES or status == "skipped":
        raise ValueError("Selected control requires a terminal assessment outcome")
    parent_id = session.execute(
        text("SELECT scan_id FROM scan_result WHERE id=:result_id"),
        {"result_id": result_id},
    ).scalar_one_or_none()
    if parent_id is None:
        return False
    parent = lock_scan(session, parent_id)
    if not parent or parent["status"] not in {"pending", "running"}:
        return False
    result = session.execute(
        text("""
        UPDATE scan_result SET status=:status, message=:message,
            evidence=CAST(:evidence AS jsonb), reason_code=:reason_code,
            provenance=CAST(:provenance AS jsonb),
            updated_at=(now() AT TIME ZONE 'UTC')
        WHERE id=:result_id AND status='pending' AND selected IS TRUE
    """),
        {
            "result_id": result_id,
            "status": status,
            "message": message,
            "evidence": json.dumps(evidence) if evidence is not None else None,
            "reason_code": reason_code,
            "provenance": json.dumps(provenance) if provenance is not None else None,
        },
    )
    changed = result.rowcount == 1
    if changed:
        session.execute(
            text(
                "UPDATE scan SET last_progress_at=(now() AT TIME ZONE 'UTC') WHERE id=:id"
            ),
            {"id": parent_id},
        )
    return changed


def finalize_scan_if_complete(
    session: Session, scan_id: int, *, final_status: str = "completed"
) -> bool:
    """Serialize summary refresh before reading results, including pending work.

    Counts derive from immutable result rows, never task delivery increments.
    Locking first lets a waiting final task see the preceding writer's commit.
    """
    if final_status not in {"completed", "failed", "cancelled"}:
        raise ValueError("Invalid terminal scan status")
    row = (
        session.execute(
            text("""
        SELECT id, status, selected_count FROM scan WHERE id=:scan_id FOR UPDATE
    """),
            {"scan_id": scan_id},
        )
        .mappings()
        .first()
    )
    if not row or row["status"] in {"completed", "failed", "cancelled"}:
        return False
    counts = dict(
        session.execute(
            text("""
        SELECT status, count(*) FROM scan_result WHERE scan_id=:scan_id GROUP BY status
    """),
            {"scan_id": scan_id},
        ).all()
    )
    compliance, coverage = calculate_scores(counts, row["selected_count"])
    complete = counts.get("pending", 0) == 0
    params = {
        "scan_id": scan_id,
        "compliance_score": compliance,
        "coverage_score": coverage,
        "complete": complete,
        "final_status": final_status,
    }
    assignments = []
    for state in TERMINAL_STATES:
        column = state + "_count"
        assignments.append(f"{column}=:{column}")
        params[column] = counts.get(state, 0)
    session.execute(
        text(
            "UPDATE scan SET "
            + ", ".join(assignments)
            + """,
        compliance_score=:compliance_score, coverage_score=:coverage_score,
        status=CASE WHEN :complete THEN :final_status ELSE status END,
        finished_at=CASE WHEN :complete
        THEN (now() AT TIME ZONE 'UTC') ELSE finished_at END
        WHERE id=:scan_id
    """
        ),
        params,
    )
    return complete
