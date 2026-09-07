"""Report what evidence retention *would* expire. Delete nothing.

Phase 7 built the retention schema -- ``retention_policy_version``,
``retention_expires_at``, ``legal_hold``, an append-only audit trail, and two
indexes (``ix_evidence_artifact_retention_expires_at``,
``ix_manual_evidence_record_expires_at``) that exist purely to support a sweep.
Nothing ever read those columns: Phase 7's own handoff says "retention is
structural, not scheduled".

**This tool reports; it does not delete, and that is deliberate.**

Phase 0 decision D04 governs retention. It is an unapproved draft with no named
owners, it says in terms that it is "not a legal minimum or an existing product
commitment", and it states that "no automatic cleanup or retention change is
authorized by this draft". Four consecutive phases refused to decide and labelled
their rows ``phaseN-draft-1`` rather than assert a policy. A tool that deleted
evidence on the strength of ``EVIDENCE_RETENTION_DAYS`` -- an engineering default
bound to ``phase7-draft-1`` -- would manufacture a GRC approval nobody gave, and
would do it to the audit record.

So the mechanism is built and the arithmetic is proven, and the deletion half
waits for an approved policy version. When one exists, the deleting pass has to
add exactly three things this report already establishes: the ``legal_hold``
exclusion, the ``retention_expired`` audit event, and the storage-level proof
that the bytes are gone (the pattern already used by ``DELETE
/evidence/artifacts/{object_id}``).

**The timestamp arithmetic is the dangerous part, and it is why this exists.**
``retention_expires_at``, ``expires_at``, ``deleted_at`` and ``occurred_at`` are
all timezone-NAIVE columns holding UTC -- unlike ``auth_session.expires_at``,
which is ``DateTime(timezone=True)``. Phase 7 documented what a naive comparison
against ``now()`` does on a non-UTC server: on the dispatcher it judged every
scan instantly past its deadline. A retention sweep making the same mistake on an
Australia/Melbourne cluster would consider ten hours' more evidence expired than
actually is, and would delete it. Every comparison here is pinned with
``(now() AT TIME ZONE 'UTC')``, exactly as the Phase 6 dispatcher SQL is, and
``tools/tests/test_phase10_retention_report.py`` runs the arithmetic under three
server timezones.

Usage:
    python tools/ops/retention_report.py
    python tools/ops/retention_report.py --json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend-api"))

from sqlalchemy import text  # noqa: E402
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine  # noqa: E402

from app.core.config import get_settings  # noqa: E402

# Kept in one place so the reporting pass and any future deleting pass cannot
# drift apart on what "expired" means. `(now() AT TIME ZONE 'UTC')` is not
# decoration: see the module docstring.
_NOW_UTC = "(now() AT TIME ZONE 'UTC')"

# The two queries, hoisted so the only interpolation in the module is visible in
# one place. _NOW_UTC is a constant, not caller input; it is a constant precisely
# so the reporting pass and any future deleting pass cannot drift on what
# "expired" means.
_ARTIFACT_SQL = f"""
    SELECT
      COUNT(*) AS total,
      COUNT(*) FILTER (WHERE status <> 'deleted') AS live,
      COUNT(*) FILTER (WHERE legal_hold) AS under_legal_hold,
      COUNT(*) FILTER (
        WHERE status <> 'deleted'
          AND retention_expires_at IS NOT NULL
          AND retention_expires_at <= {_NOW_UTC}
      ) AS past_expiry,
      -- The number that matters: expired AND not held. A hold outranks expiry,
      -- so these two must never be conflated.
      COUNT(*) FILTER (
        WHERE status <> 'deleted'
          AND NOT legal_hold
          AND retention_expires_at IS NOT NULL
          AND retention_expires_at <= {_NOW_UTC}
      ) AS eligible,
      COUNT(*) FILTER (
        WHERE status <> 'deleted' AND retention_expires_at IS NULL
      ) AS no_expiry_recorded
    FROM evidence_artifact
"""  # nosec B608 - _NOW_UTC is a module constant, never caller input

_MANUAL_SQL = f"""
    SELECT
      COUNT(*) AS total,
      COUNT(*) FILTER (WHERE status = 'approved') AS approved,
      COUNT(*) FILTER (
        WHERE status = 'approved'
          AND expires_at IS NOT NULL
          AND expires_at <= {_NOW_UTC}
      ) AS approved_but_lapsed
    FROM manual_evidence_record
"""  # nosec B608 - _NOW_UTC is a module constant, never caller input


async def artifact_report(session: AsyncSession) -> dict:
    row = (
        (
            await session.execute(
                # The only interpolation is _NOW_UTC, a module constant. It is a
                # constant precisely so the reporting pass and any future
                # deleting pass cannot drift on what "expired" means.
                text(_ARTIFACT_SQL)
            )
        )
        .mappings()
        .first()
    )

    versions = [
        dict(entry)
        for entry in (
            await session.execute(
                text(
                    "SELECT retention_policy_version AS version, COUNT(*) AS count "
                    "FROM evidence_artifact GROUP BY retention_policy_version "
                    "ORDER BY retention_policy_version"
                )
            )
        ).mappings()
    ]
    return {"counts": dict(row), "policy_versions": versions}


async def manual_evidence_report(session: AsyncSession) -> dict:
    """Approved manual attestations whose cadence has lapsed.

    ``TRANSITIONS["expire"]`` exists in the service layer and ``expires_at`` is
    indexed, but ``expire`` belongs to no role in REVIEWER_TRANSITIONS or
    SUBMITTER_TRANSITIONS and no route or job invokes it. So an approved control
    attestation from a year ago still reads `approved` forever, and stale manual
    evidence keeps counting as assurance.
    """
    row = (
        (
            await session.execute(
                # See above; _NOW_UTC is the only interpolated value.
                text(_MANUAL_SQL)
            )
        )
        .mappings()
        .first()
    )
    return {"counts": dict(row)}


async def gather(settings) -> dict:
    url = settings.DATABASE_URL
    if not url.startswith("postgresql+asyncpg://"):
        url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
    engine = create_async_engine(url, pool_pre_ping=True)
    try:
        async with AsyncSession(engine) as session:
            server_timezone = (
                await session.execute(text("SHOW TimeZone"))
            ).scalar_one()
            artifacts = await artifact_report(session)
            manual = await manual_evidence_report(session)
    finally:
        await engine.dispose()

    return {
        "mode": "report-only",
        "deletes_anything": False,
        "why": (
            "Phase 0 decision D04 governs evidence retention. It is an unapproved "
            "draft with no named owners and states that no automatic cleanup is "
            "authorized by it. The configured EVIDENCE_RETENTION_DAYS is an "
            "engineering default bound to a draft policy version, not a commitment."
        ),
        "configured_policy_version": settings.EVIDENCE_RETENTION_POLICY_VERSION,
        "configured_retention_days": settings.EVIDENCE_RETENTION_DAYS,
        # Recorded because it is the variable that would silently change the
        # answer if the arithmetic were not UTC-pinned.
        "database_server_timezone": server_timezone,
        "evidence_artifacts": artifacts,
        "manual_evidence": manual,
    }


def render(report: dict) -> str:
    counts = report["evidence_artifacts"]["counts"]
    manual = report["manual_evidence"]["counts"]
    lines = [
        "Evidence retention report (report-only; nothing was deleted)",
        "",
        f"  configured policy version : {report['configured_policy_version']}",
        f"  configured retention days : {report['configured_retention_days']}",
        f"  database server timezone  : {report['database_server_timezone']}",
        "",
        "  evidence artifacts",
        f"    total                   : {counts['total']}",
        f"    live (not tombstoned)   : {counts['live']}",
        f"    under legal hold        : {counts['under_legal_hold']}",
        f"    past their expiry       : {counts['past_expiry']}",
        f"    expired and NOT held    : {counts['eligible']}",
        f"    no expiry recorded      : {counts['no_expiry_recorded']}",
        "",
        "  manual evidence",
        f"    total                   : {manual['total']}",
        f"    approved                : {manual['approved']}",
        f"    approved but lapsed     : {manual['approved_but_lapsed']}",
        "",
        "  policy versions in use:",
    ]
    for entry in report["evidence_artifacts"]["policy_versions"]:
        lines.append(f"    {entry['version']}: {entry['count']}")
    lines += ["", "  " + report["why"]]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--json", action="store_true", help="emit JSON")
    args = parser.parse_args(argv)

    report = asyncio.run(gather(get_settings()))
    print(json.dumps(report, indent=2, sort_keys=True) if args.json else render(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
