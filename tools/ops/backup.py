"""Back up and restore AutoAudit's durable state, with a verifiable manifest.

Before Phase 10 there was nothing: no ``pg_dump``, no snapshot step, no
documented RPO or RTO, and no restore procedure anywhere in the repository. The
only durable state is two volumes -- the PostgreSQL data directory and the
evidence object store -- and losing either was total, silent and unrecoverable.
(The one thing that grepped as "backup", ``security/strategies/regular_backups.py``,
is a *scanner* that grades a customer's backup evidence. AutoAudit ships a tool
that would have failed AutoAudit on every one of those controls.)

**What is backed up.** Two things, because two things are durable:

``database``
    ``pg_dump --format=custom``. Every scan, result, provenance record,
    factprint, drift row and evidence audit event lives here.

``evidence``
    The contents of ``EVIDENCE_STORAGE_DIR`` as a tar archive. The rows in
    ``evidence_artifact`` are only pointers; the bytes are on the volume, and a
    database-only backup restores an audit trail whose objects are all missing.

Redis is deliberately **not** backed up. ``infrastructure/runtime/redis.conf``
disables RDB and AOF and the production compose mounts ``/data`` as tmpfs, so
broker state is ephemeral by design -- Phase 6 made PostgreSQL the owner of retry
state precisely so a broker loss is recoverable without one.

**The manifest is the point.** Each backup writes ``manifest.json`` recording the
SHA-256 of every artifact, the Alembic revision the database was at, the server's
major version, and the retention policy version in force. ``restore`` verifies
every digest before it writes anything, and refuses a cross-major-version
restore rather than letting ``pg_restore`` fail halfway. A backup nobody has
verified is not evidence of anything, which is why ``verify`` exists as its own
command and why the restore test in ``tools/tests`` actually runs one.

**What this does not do.** It does not encrypt the archive. Doing that properly
means a key that is not the application's ``ENCRYPTION_KEY`` -- restoring with the
application key would mean a stolen backup and a stolen application secret are
the same compromise -- and choosing where that key lives is a deployment
decision this repository cannot make. The gap is named in the Phase 10 handoff
and in ``docs/compliance/phase-10/backup-and-recovery.md`` rather than papered
over with a passphrase prompt.

Usage:
    python tools/ops/backup.py create  --into /backups/2026-09-07
    python tools/ops/backup.py verify  --from /backups/2026-09-07
    python tools/ops/backup.py restore --from /backups/2026-09-07 --target-url ...
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess  # nosec B404 # controlled pg_dump/pg_restore invocations
import sys
import tarfile
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit, urlunsplit

MANIFEST_NAME = "manifest.json"
DATABASE_ARTIFACT = "database.dump"
EVIDENCE_ARTIFACT = "evidence.tar"
SCHEMA = "autoaudit.backup-manifest/v1"


class BackupError(RuntimeError):
    """Anything that should stop a backup or a restore, stated plainly."""


def libpq_url(url: str) -> str:
    """Strip the SQLAlchemy driver so libpq tools accept the URL.

    The password is stripped too. It travels in the environment instead; see
    libpq_invocation.
    """
    return _split_password(url)[0]


def _split_password(url: str) -> tuple[str, str | None]:
    """(connection URL with no password, password) for a SQLAlchemy or libpq URL.

    A connection URL passed as a command-line argument is readable by every
    other process on the host, through `ps` and through /proc/<pid>/cmdline,
    for as long as pg_dump runs -- which on a real database is minutes. The
    environment of another process is not: on Linux /proc/<pid>/environ is
    readable only by the owning user, and macOS does not expose it at all.
    """
    url = url.replace("postgresql+asyncpg://", "postgresql://", 1)
    parts = urlsplit(url)
    if not parts.password:
        return url, None
    userinfo = quote(unquote(parts.username or ""), safe="")
    host = parts.hostname or ""
    if parts.port:
        host = f"{host}:{parts.port}"
    netloc = f"{userinfo}@{host}" if userinfo else host
    return urlunsplit(parts._replace(netloc=netloc)), unquote(parts.password)


def libpq_invocation(url: str) -> tuple[str, dict[str, str]]:
    """The URL to pass on the command line, and the environment to pass with it."""
    sanitised, password = _split_password(url)
    environment = dict(os.environ)
    if password is not None:
        environment["PGPASSWORD"] = password
    else:
        # Inheriting a stale PGPASSWORD would silently authenticate as someone
        # else, which is worse than failing.
        environment.pop("PGPASSWORD", None)
    return sanitised, environment


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _run(command: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(  # nosec B603 # fixed argv, no shell
        command, capture_output=True, text=True, timeout=3600, check=False, **kwargs
    )


def server_version(url: str) -> str:
    connection, environment = libpq_invocation(url)
    result = _run(["psql", connection, "-tAc", "SHOW server_version"], env=environment)
    if result.returncode != 0:
        raise BackupError(f"could not read server version: {_redact(result.stderr)}")
    return result.stdout.strip()


def alembic_revision(url: str) -> str | None:
    """The schema revision the dump was taken at.

    Recorded because a restore into a deployment running different code is the
    situation where a backup is least useful and most dangerous: the row shapes
    would not match what the application expects.
    """
    connection, environment = libpq_invocation(url)
    result = _run(
        ["psql", connection, "-tAc", "SELECT version_num FROM alembic_version"],
        env=environment,
    )
    return result.stdout.strip() or None if result.returncode == 0 else None


def create(
    *,
    database_url: str,
    evidence_dir: Path | None,
    into: Path,
    retention_policy_version: str,
    taken_at: str | None,
) -> dict:
    into.mkdir(parents=True, exist_ok=True)

    dump_path = into / DATABASE_ARTIFACT
    # --format=custom so pg_restore can be selective, and so the dump is
    # compressed without a separate step.
    connection, environment = libpq_invocation(database_url)
    result = _run(
        [
            "pg_dump",
            connection,
            "--format=custom",
            "--no-owner",
            "--no-privileges",
            "--file",
            str(dump_path),
        ],
        env=environment,
    )
    if result.returncode != 0:
        raise BackupError(f"pg_dump failed: {_redact(result.stderr)}")

    artifacts = {
        DATABASE_ARTIFACT: {
            "sha256": file_digest(dump_path),
            "bytes": dump_path.stat().st_size,
            "kind": "postgresql-custom-dump",
        }
    }

    if evidence_dir is not None and evidence_dir.is_dir():
        evidence_path = into / EVIDENCE_ARTIFACT
        with tarfile.open(evidence_path, "w") as bundle:
            # arcname is fixed so the archive does not embed the host path, and
            # so a restore into a differently-mounted volume still works.
            bundle.add(evidence_dir, arcname="evidence-store")
        artifacts[EVIDENCE_ARTIFACT] = {
            "sha256": file_digest(evidence_path),
            "bytes": evidence_path.stat().st_size,
            "kind": "evidence-object-store",
        }
    else:
        # Recorded explicitly. A manifest that silently omits evidence would
        # restore an audit trail whose objects are all gone, with nothing saying so.
        artifacts[EVIDENCE_ARTIFACT] = {
            "sha256": None,
            "bytes": 0,
            "kind": "evidence-object-store",
            "skipped": "no evidence directory was supplied or it does not exist",
        }

    manifest = {
        "schema": SCHEMA,
        "taken_at": taken_at,
        "database": {
            "server_version": server_version(database_url),
            "alembic_revision": alembic_revision(database_url),
            "name": urlsplit(libpq_url(database_url)).path.lstrip("/"),
        },
        "retention_policy_version": retention_policy_version,
        "artifacts": artifacts,
        "encryption": {
            "at_rest": False,
            "note": (
                "The archive is NOT encrypted. It contains every scan result, "
                "provenance record and uploaded evidence object in plaintext, and "
                "must be stored on an encrypted volume with access control. "
                "Encrypting it here needs a backup key distinct from the "
                "application ENCRYPTION_KEY, which is a deployment decision."
            ),
        },
    }
    (into / MANIFEST_NAME).write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    )
    return manifest


def read_manifest(source: Path) -> dict:
    path = source / MANIFEST_NAME
    if not path.exists():
        raise BackupError(f"no {MANIFEST_NAME} in {source}")
    manifest = json.loads(path.read_text())
    if manifest.get("schema") != SCHEMA:
        raise BackupError(f"unsupported manifest schema {manifest.get('schema')!r}")
    return manifest


def verify(source: Path) -> dict:
    """Check every artifact against its recorded digest.

    Separate from restore on purpose: a backup that has never been verified is
    an assumption, and the whole point of a recurring restore test is to stop
    treating it as one.
    """
    manifest = read_manifest(source)
    problems = []
    for name, entry in sorted(manifest["artifacts"].items()):
        if entry.get("sha256") is None:
            continue
        path = source / name
        if not path.exists():
            problems.append(f"{name} is missing")
            continue
        actual = file_digest(path)
        if actual != entry["sha256"]:
            # Never print the expected digest next to the actual one as if the
            # difference were interesting; the fact of the mismatch is the point.
            problems.append(f"{name} does not match its recorded digest")
        elif path.stat().st_size != entry["bytes"]:
            problems.append(f"{name} has an unexpected size")
    if problems:
        raise BackupError("; ".join(problems))
    return manifest


def _redact(text: str) -> str:
    """Strip anything URL-shaped before an error message is printed or raised.

    libpq tools echo the connection string they were given, and that string
    carries the password. A BackupError propagates to stderr and, in CI, into a
    log nobody redacts afterwards.
    """
    import re

    return re.sub(
        r"postgres(?:ql)?://\S+", "postgresql://<redacted>", text or ""
    ).strip()[:2000]


def _target_is_empty(url: str) -> bool:
    connection, environment = libpq_invocation(url)
    result = _run(
        [
            "psql",
            connection,
            "-tAc",
            "SELECT count(*) FROM information_schema.tables "
            "WHERE table_schema NOT IN ('pg_catalog', 'information_schema')",
        ],
        env=environment,
    )
    if result.returncode != 0:
        raise BackupError(f"could not inspect the target: {_redact(result.stderr)}")
    return result.stdout.strip() in {"", "0"}


def restore(
    *,
    source: Path,
    target_url: str,
    evidence_dir: Path | None,
    allow_version_mismatch: bool = False,
    allow_nonempty: bool = False,
) -> dict:
    manifest = verify(source)

    target_version = server_version(target_url)
    recorded = manifest["database"]["server_version"]
    if _major(target_version) != _major(recorded) and not allow_version_mismatch:
        raise BackupError(
            f"backup was taken on PostgreSQL {recorded} and the target is "
            f"{target_version}; a custom-format dump is not guaranteed across "
            "major versions. Restore into a matching version, or pass "
            "--allow-version-mismatch deliberately."
        )

    # A restore into a populated database merges two datasets rather than
    # replacing one, and the most likely wrong `--target-url` an operator can
    # type is the production one.
    if not allow_nonempty and not _target_is_empty(target_url):
        raise BackupError(
            "the target database already contains tables. Restoring into it "
            "would merge two datasets rather than replace one. Restore into a "
            "fresh database, or pass --allow-nonempty deliberately."
        )

    connection, environment = libpq_invocation(target_url)
    result = _run(
        [
            "pg_restore",
            "--dbname",
            connection,
            "--no-owner",
            "--no-privileges",
            # Atomic. Without these, pg_restore continues past errors and exits
            # 0, leaving a database that is neither the old one nor the new one
            # while reporting success.
            "--single-transaction",
            "--exit-on-error",
            str(source / DATABASE_ARTIFACT),
        ],
        env=environment,
    )
    if result.returncode != 0:
        raise BackupError(f"pg_restore failed: {_redact(result.stderr)}")

    entry = manifest["artifacts"].get(EVIDENCE_ARTIFACT, {})
    if evidence_dir is not None and entry.get("sha256"):
        evidence_dir.mkdir(parents=True, exist_ok=True)
        with tarfile.open(source / EVIDENCE_ARTIFACT, "r") as bundle:
            _safe_extract(bundle, evidence_dir)

    return manifest


# The archive's single root member. `create` writes the store under a fixed
# arcname so the archive does not embed the host path; `restore` therefore has
# to strip that root, or extracting into a directory that is itself the evidence
# store produces <store>/evidence-store/... and every restored object is
# unreachable by the application. The documented --evidence-dir is exactly such
# a directory, so this was not a hypothetical.
ARCHIVE_ROOT = "evidence-store"


def _major(version: str) -> str:
    return version.split(".")[0]


def _safe_extract(bundle: tarfile.TarFile, destination: Path) -> None:
    """Extract without letting a member escape the destination.

    The archive is one we wrote, but ``extractall`` on a tar whose members can
    name ``../`` is a path-traversal primitive regardless of provenance, and a
    backup archive is exactly the kind of file that gets copied between hosts.
    """
    root = destination.resolve()
    members = []
    for member in bundle.getmembers():
        if member.issym() or member.islnk():
            raise BackupError(f"archive contains a link member: {member.name}")
        # Strip the fixed archive root so the store's CONTENTS land in the
        # destination rather than in a nested directory of the same name.
        name = member.name
        if name == ARCHIVE_ROOT:
            continue
        prefix = ARCHIVE_ROOT + "/"
        if name.startswith(prefix):
            member.name = name[len(prefix) :]
        target = (root / member.name).resolve()
        if not str(target).startswith(str(root) + os.sep) and target != root:
            raise BackupError(f"archive member escapes the destination: {name}")
        members.append(member)
    bundle.extractall(root, members=members)  # nosec B202 # every member validated above


def _require_tools() -> None:
    for tool in ("pg_dump", "pg_restore", "psql"):
        if shutil.which(tool) is None:
            raise BackupError(f"{tool} is not on PATH")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    make = sub.add_parser("create", help="take a backup")
    make.add_argument("--into", type=Path, required=True)
    make.add_argument("--database-url", default=os.environ.get("DATABASE_URL", ""))
    make.add_argument("--evidence-dir", type=Path, default=None)
    make.add_argument("--retention-policy-version", default="phase10-draft-1")
    make.add_argument(
        "--taken-at", default=None, help="ISO timestamp, supplied by the caller"
    )

    check = sub.add_parser("verify", help="check artifacts against the manifest")
    check.add_argument("--from", dest="source", type=Path, required=True)

    put = sub.add_parser("restore", help="restore into a target database")
    put.add_argument("--from", dest="source", type=Path, required=True)
    put.add_argument("--target-url", required=True)
    put.add_argument("--evidence-dir", type=Path, default=None)
    put.add_argument("--allow-version-mismatch", action="store_true")
    put.add_argument(
        "--allow-nonempty",
        action="store_true",
        help="restore into a database that already has tables (merges datasets)",
    )
    put.add_argument(
        "--allow-nonempty",
        action="store_true",
        help="restore into a database that already contains tables (merges datasets)",
    )

    args = parser.parse_args(argv)

    try:
        _require_tools()
        if args.command == "create":
            if not args.database_url:
                raise BackupError("--database-url or DATABASE_URL is required")
            manifest = create(
                database_url=args.database_url,
                evidence_dir=args.evidence_dir,
                into=args.into,
                retention_policy_version=args.retention_policy_version,
                taken_at=args.taken_at,
            )
            print(json.dumps(manifest, indent=2, sort_keys=True))
        elif args.command == "verify":
            verify(args.source)
            print(f"{args.source}: every artifact matches its recorded digest")
        else:
            restore(
                source=args.source,
                target_url=args.target_url,
                evidence_dir=args.evidence_dir,
                allow_version_mismatch=args.allow_version_mismatch,
                allow_nonempty=args.allow_nonempty,
            )
            print(f"restored {args.source} into the target database")
    except BackupError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
