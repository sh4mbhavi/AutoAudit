"""Re-encrypt application ciphertext under a new primary key.

Rotation is a three-step operator procedure, not a single command:

1.  Deploy the new key as ``ENCRYPTION_KEY`` with the previous one listed in
    ``ENCRYPTION_KEY_DECRYPT_ONLY``. Both the API and the worker must carry the
    same ring. At this point nothing has been rewritten: every row is still
    readable, new writes use the new key.
2.  Run this tool. It rewrites each row that is not already under the primary
    key, one row at a time, under a row lock.
3.  Only once ``--check`` reports nothing outstanding, drop the retired key from
    ``ENCRYPTION_KEY_DECRYPT_ONLY``. Dropping it earlier makes every
    not-yet-rewritten row permanently unreadable.

The pass is resumable because ``encryption.needs_rewrite`` answers "is this row
already current" by trial decryption under the primary key alone -- interrupt it
and re-run it, and it picks up the rows it did not reach.

**Scope.** Two columns hold ciphertext under ``ENCRYPTION_KEY``:

``m365_connection.encrypted_client_secret``
    Rotated. This is the round-trip ciphertext: losing it costs a tenant its
    stored credential.

``evidence_validation.extracted_text_encrypted``
    **Deliberately not rotated, and deliberately not discarded.** No code path
    in the product reads this column -- it is written by ``_encrypt_excerpt``
    and never decrypted anywhere. Rewriting a column nothing reads would risk
    the audit record for no operational gain, and NULLing it would destroy
    retained evidence that a future reader may be entitled to. Rows written
    under a retired key therefore stay readable only for as long as that key is
    kept in the ring; ``--check`` counts them so the decision to drop a key is
    made with that number in view rather than by surprise. Whether these
    excerpts must survive a key retirement is a D04/D05 retention question this
    tool has no authority to answer.

No key material is printed, logged or accepted on the command line. The tool
reads exactly the same environment the application reads.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend-api"))

from sqlalchemy import text  # noqa: E402
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine  # noqa: E402

from app.core.config import get_settings  # noqa: E402
from app.services import encryption  # noqa: E402
from app.services.encryption import InvalidToken  # noqa: E402


def async_url(url: str) -> str:
    """The application's own driver; the tool adds no new dependency."""
    if url.startswith("postgresql+asyncpg://"):
        return url
    return url.replace("postgresql://", "postgresql+asyncpg://", 1)


async def _connection_ids(session: AsyncSession) -> list[int]:
    """Every connection id, oldest first, read outside the rewrite transaction.

    Read first and lock one row at a time: holding a lock over the whole table
    for the length of a rotation would block every tenant's connection updates.
    A row created after this read is already written under the new primary key,
    because the primary changed before the pass started.
    """
    result = await session.execute(text("SELECT id FROM m365_connection ORDER BY id"))
    return [row[0] for row in result]


async def rotate_connections(session: AsyncSession, *, dry_run: bool) -> dict:
    """Rewrite each connection secret that is not already under the primary key."""
    examined = rewritten = already_current = empty = unreadable = 0
    unreadable_ids: list[int] = []

    for connection_id in await _connection_ids(session):
        # Lock the row so the update route at
        # backend-api/app/api/v1/m365_connections.py cannot rewrite the same
        # secret between our read and our write. Without this a concurrent
        # tenant edit would be silently reverted to the value we decrypted.
        result = await session.execute(
            text(
                "SELECT id, encrypted_client_secret FROM m365_connection "
                "WHERE id = :id FOR UPDATE"
            ),
            {"id": connection_id},
        )
        row = result.mappings().first()
        if row is None:  # deleted between the id read and the lock
            await session.rollback()
            continue

        examined += 1
        ciphertext = row["encrypted_client_secret"]
        if not ciphertext:
            # The empty string means "no secret held". It is not a decryption
            # failure and there is nothing to rewrite.
            empty += 1
            await session.rollback()
            continue
        if not encryption.needs_rewrite(ciphertext):
            already_current += 1
            await session.rollback()
            continue

        try:
            plaintext = encryption.decrypt(ciphertext)
        except InvalidToken:
            # No key in the ring can read this row. Report the id -- never the
            # ciphertext, and never any key material.
            unreadable += 1
            unreadable_ids.append(connection_id)
            await session.rollback()
            continue

        if dry_run:
            rewritten += 1
            await session.rollback()
            continue

        await session.execute(
            text(
                "UPDATE m365_connection SET encrypted_client_secret = :value "
                "WHERE id = :id"
            ),
            {"value": encryption.encrypt(plaintext), "id": connection_id},
        )
        await session.commit()
        rewritten += 1

    return {
        "table": "m365_connection.encrypted_client_secret",
        "examined": examined,
        "rewritten": rewritten,
        "already_current": already_current,
        "empty": empty,
        "unreadable": unreadable,
        "unreadable_ids": unreadable_ids,
    }


async def survey_evidence_excerpts(session: AsyncSession) -> dict:
    """Count excerpt rows still written under a retired key, without touching them.

    See the module docstring: this column is out of scope for rewriting. The
    count exists so an operator retiring a key knows what that retirement costs.
    """
    outstanding = 0
    total = 0
    # Streamed in batches rather than buffered. Whether a ciphertext is current
    # can only be answered by trying to decrypt it, so this has to touch every
    # row -- but an excerpt is up to EVIDENCE_MAX_EXTRACTED_CHARS of text, and
    # materialising the whole column at once is how a survey of a large evidence
    # store becomes an out-of-memory kill.
    result = await session.stream(
        text(
            "SELECT extracted_text_encrypted FROM evidence_validation "
            "WHERE extracted_text_encrypted IS NOT NULL "
            "AND extracted_text_encrypted <> ''"
        )
    )
    async for row in result.mappings():
        total += 1
        if encryption.needs_rewrite(row["extracted_text_encrypted"]):
            outstanding += 1
    return {
        "table": "evidence_validation.extracted_text_encrypted",
        "rotated": False,
        "total": total,
        # "not under the primary key" is all a trial decryption can establish:
        # needs_rewrite is equally true for a row under a retired key and for one
        # no key in the ring can read. Naming it "retired" would claim knowledge
        # the check does not have.
        "not_under_the_primary_key": outstanding,
    }


async def _run_pass(settings, *, check: bool) -> tuple[dict, dict]:
    engine = create_async_engine(async_url(settings.DATABASE_URL), pool_pre_ping=True)
    try:
        async with AsyncSession(engine) as session:
            connections = await rotate_connections(session, dry_run=check)
            excerpts = await survey_evidence_excerpts(session)
    finally:
        await engine.dispose()
    return connections, excerpts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--check",
        action="store_true",
        help="report what would be rewritten and change nothing (exit 1 if any row is outstanding)",
    )
    args = parser.parse_args(argv)

    settings = get_settings()
    if not settings.ENCRYPTION_KEY:
        print("ENCRYPTION_KEY is required.", file=sys.stderr)
        return 2
    retired = settings.decrypt_only_keys()
    if not retired and args.check is False:
        print(
            "ENCRYPTION_KEY_DECRYPT_ONLY is empty: there is no retired key to "
            "rotate away from. Deploy the new primary with the previous key "
            "listed there first.",
            file=sys.stderr,
        )
        return 2

    connections, excerpts = asyncio.run(_run_pass(settings, check=args.check))

    print(f"retired keys accepted for reading: {len(retired)}")
    for report in (connections, excerpts):
        print()
        for key, value in report.items():
            print(f"  {key}: {value}")

    # The excerpt count is reported, never gated on. It cannot reach zero: the
    # column is deliberately out of scope for rewriting, so gating --check on it
    # would make the exit code permanently 1 the moment a single historical
    # evidence row exists -- and step 3 of the procedure in the module docstring
    # ("run --check, then drop the retired key") would become unreachable. The
    # count exists so the operator makes that decision with the number in view,
    # which is a judgement, not a gate.
    if excerpts["not_under_the_primary_key"]:
        print(
            f"\nNote: {excerpts['not_under_the_primary_key']} evidence excerpt(s) "
            "are written under a retired key. They are NOT rotated by design (see "
            "the module docstring); dropping that key makes them unreadable. This "
            "does not block the rotation.",
            file=sys.stderr,
        )

    if connections["unreadable"]:
        print(
            "\nRows no key in the ring can read. Restore the key that wrote them "
            "to ENCRYPTION_KEY_DECRYPT_ONLY, or re-enter those credentials.",
            file=sys.stderr,
        )
        return 1
    if args.check and connections["rewritten"]:
        print(
            f"\n{connections['rewritten']} connection secret(s) still need rewriting.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover - operator entry point
    os.environ.setdefault("APP_ENV", "dev")
    raise SystemExit(main())
