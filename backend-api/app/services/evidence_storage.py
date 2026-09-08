"""Tenant-scoped, bounded object storage for evidence artifacts and reports.

Phase 7 replaces the flat, world-readable ``security/results/`` directory whose
names were guessable (``{user_id}-{strategy}-{stem}-{unix_seconds}``) with keys
derived only from an artifact's random ``object_id`` and its owning user id. A
key therefore carries no display filename, no strategy name and no timestamp,
and knowing one key tells an attacker nothing about any other.

Two rules hold for every backend:

* **Bounded writes.** ``put`` streams and stops the moment the byte ceiling is
  crossed, so an oversized body is refused instead of buffered. A partial file
  is always removed.
* **Contained paths.** Every key is validated segment by segment and the final
  path is resolved and asserted to stay inside the configured root before any
  read, write or delete, which defends both ``..`` traversal and a symlink that
  points out of the store.

**No external object store is implemented here on purpose.** Approved object
storage (S3/MinIO and its encryption, replication and retention configuration)
is a deployment decision that is still gated on Phase 0 decision D04, which is
an unapproved draft. Adding a half-configured bucket client now would create an
evidence store nobody has accepted, so ``get_storage`` raises a clear error for
any backend other than ``local`` and the deployment choice stays visible.

**Deployment requirement for the local backend:** ``EVIDENCE_STORAGE_DIR`` must
be a real mounted volume outside the source tree and outside any served static
directory. On the default container path (``/app/evidence-store``) with no
volume, evidence is lost on every redeploy, which would destroy the audit trail
the artifact rows promise.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import secrets
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

import anyio

from app.core.config import Settings, get_settings

logger = logging.getLogger("api")

# secrets.token_urlsafe(32) is 43 characters, which is exactly the width of
# EvidenceArtifact.object_id.
OBJECT_ID_ENTROPY_BYTES = 32
OBJECT_ID_LENGTH = 43

OBJECT_ID_PATTERN = re.compile(r"\A[A-Za-z0-9_-]{43}\Z")
_KEY_SEGMENT_PATTERN = re.compile(r"\A[A-Za-z0-9_-]{1,64}\Z")

LOCAL_BACKEND = "local"

# Owner-only permissions; evidence is never group or world readable.
_DIRECTORY_MODE = 0o700
_FILE_MODE = 0o600

DEFAULT_READ_CHUNK_BYTES = 1024 * 1024


class EvidenceStorageError(RuntimeError):
    """Base class for storage failures that must never reach a caller raw."""


class EvidenceStorageKeyError(EvidenceStorageError):
    """A key was malformed, absolute, traversing or escaped the store root."""


class EvidenceTooLargeError(EvidenceStorageError):
    """The stream crossed the configured byte ceiling and was abandoned."""

    def __init__(self, limit: int) -> None:
        super().__init__("evidence exceeds the configured byte ceiling")
        self.limit = limit


class EvidenceObjectMissingError(EvidenceStorageError):
    """The key resolved correctly but no stored object exists behind it."""


@dataclass(frozen=True)
class StoredObject:
    """What a completed write proved about the bytes that were stored."""

    key: str
    byte_size: int
    content_sha256: str


def new_object_id() -> str:
    """Mint an unguessable public handle for one artifact."""
    return secrets.token_urlsafe(OBJECT_ID_ENTROPY_BYTES)


def build_storage_key(user_id: int, object_id: str) -> str:
    """Derive the storage key from ownership and the random object id only.

    Never from the display filename, the strategy, or a timestamp: those are
    guessable, and a guessable key is the AUTH-01 defect in another form.
    """
    if isinstance(user_id, bool) or not isinstance(user_id, int) or user_id <= 0:
        raise EvidenceStorageKeyError("a storage key requires a positive owner id")
    if not OBJECT_ID_PATTERN.match(object_id or ""):
        raise EvidenceStorageKeyError("a storage key requires a random object id")
    return f"{user_id}/{object_id[:2]}/{object_id}"


def split_storage_key(key: str) -> tuple[str, ...]:
    """Validate a key and return its segments.

    Rejects absolute paths, drive letters, backslashes, NUL bytes, empty
    segments and any ``.``/``..`` component before the path is ever joined.
    """
    if not isinstance(key, str) or not key or len(key) > 512:
        raise EvidenceStorageKeyError("invalid evidence storage key")
    if key != key.strip() or "\\" in key or "\x00" in key or ":" in key:
        raise EvidenceStorageKeyError("invalid evidence storage key")
    if key.startswith("/") or key.endswith("/"):
        raise EvidenceStorageKeyError("invalid evidence storage key")
    segments = tuple(key.split("/"))
    if not 1 <= len(segments) <= 8:
        raise EvidenceStorageKeyError("invalid evidence storage key")
    for segment in segments:
        if not _KEY_SEGMENT_PATTERN.match(segment):
            raise EvidenceStorageKeyError("invalid evidence storage key")
    return segments


class EvidenceStorage(ABC):
    """Minimal object-store contract the evidence API depends on."""

    backend_name: str = "abstract"

    @abstractmethod
    async def put(
        self,
        key: str,
        chunks: AsyncIterator[bytes],
        *,
        max_bytes: int,
    ) -> StoredObject:
        """Stream ``chunks`` to ``key``, refusing to exceed ``max_bytes``."""

    @abstractmethod
    def open(self, key: str) -> BinaryIO:
        """Open the stored object for reading. Blocking; call off the loop."""

    @abstractmethod
    async def delete(self, key: str) -> bool:
        """Remove the stored bytes. Returns False when nothing was there."""

    @abstractmethod
    async def exists(self, key: str) -> bool:
        """Whether bytes are currently stored under ``key``."""

    async def read_bounded(self, key: str, *, max_bytes: int) -> bytes:
        """Read a stored object back, refusing anything past ``max_bytes``."""
        return await anyio.to_thread.run_sync(self.read_bounded_sync, key, max_bytes)

    def read_bounded_sync(self, key: str, max_bytes: int) -> bytes:
        """Blocking bounded read, used inside worker threads."""
        if max_bytes <= 0:
            raise EvidenceTooLargeError(max_bytes)
        with self.open(key) as handle:
            data = handle.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise EvidenceTooLargeError(max_bytes)
        return data

    async def open_reader(self, key: str) -> BinaryIO:
        """Open before responding so a concurrent delete cannot tear a stream.

        Once the descriptor exists the bytes stay readable on POSIX even if the
        directory entry is removed, so a download either fails cleanly before
        the response starts or completes.
        """
        return await anyio.to_thread.run_sync(self.open, key)

    async def iter_handle(
        self, handle: BinaryIO, *, chunk_size: int = DEFAULT_READ_CHUNK_BYTES
    ) -> AsyncIterator[bytes]:
        """Stream an already-open object without holding it all in memory."""
        size = max(4096, min(int(chunk_size), 8 * 1024 * 1024))
        try:
            while True:
                chunk = await anyio.to_thread.run_sync(handle.read, size)
                if not chunk:
                    return
                yield chunk
        finally:
            await anyio.to_thread.run_sync(handle.close)

    async def iter_chunks(
        self, key: str, *, chunk_size: int = DEFAULT_READ_CHUNK_BYTES
    ) -> AsyncIterator[bytes]:
        """Open and stream a stored object."""
        handle = await self.open_reader(key)
        async for chunk in self.iter_handle(handle, chunk_size=chunk_size):
            yield chunk


class LocalFilesystemStorage(EvidenceStorage):
    """Filesystem backend rooted at ``settings.EVIDENCE_STORAGE_DIR``."""

    backend_name = LOCAL_BACKEND

    def __init__(self, root: str | os.PathLike[str]) -> None:
        # realpath rather than Path.resolve so a symlinked root is normalised
        # once here and every later containment check compares like with like.
        self._root = Path(os.path.realpath(os.fspath(root)))
        if not self._root.is_absolute():
            raise EvidenceStorageError("evidence storage root must be absolute")

    @property
    def root(self) -> Path:
        return self._root

    def resolve(self, key: str) -> Path:
        """Validate the key and prove the result stays inside the root."""
        segments = split_storage_key(key)
        candidate = self._root.joinpath(*segments)
        resolved = Path(os.path.realpath(candidate))
        if resolved == self._root or self._root not in resolved.parents:
            raise EvidenceStorageKeyError("evidence storage key escapes the store")
        return resolved

    async def put(
        self,
        key: str,
        chunks: AsyncIterator[bytes],
        *,
        max_bytes: int,
    ) -> StoredObject:
        if max_bytes <= 0:
            raise EvidenceTooLargeError(max_bytes)
        path = self.resolve(key)
        # Filesystem faults become EvidenceStorageError here so a caller can
        # never leak an OSError message, and with it the absolute store path,
        # into a response or a traceback in the request log.
        await anyio.to_thread.run_sync(self._prepare_parent, path)
        descriptor = await anyio.to_thread.run_sync(self._create_exclusive, path)
        digest = hashlib.sha256()
        total = 0
        try:
            with os.fdopen(descriptor, "wb") as handle:
                async for chunk in chunks:
                    if not chunk:
                        continue
                    total += len(chunk)
                    if total > max_bytes:
                        # Stop here: the remainder of the body is never read
                        # into memory and never reaches the disk.
                        raise EvidenceTooLargeError(max_bytes)
                    digest.update(chunk)
                    await anyio.to_thread.run_sync(self._write, handle, chunk)
        except BaseException:
            await self._discard(path)
            raise
        return StoredObject(key=key, byte_size=total, content_sha256=digest.hexdigest())

    def open(self, key: str) -> BinaryIO:
        path = self.resolve(key)
        try:
            # O_NOFOLLOW refuses a symlinked leaf; resolve() already refused a
            # symlinked parent that points out of the store.
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError as error:
            raise EvidenceObjectMissingError("evidence object is not stored") from error
        except OSError as error:
            raise EvidenceStorageKeyError("evidence object is not readable") from error
        return os.fdopen(descriptor, "rb")

    async def delete(self, key: str) -> bool:
        """Remove the stored bytes.

        Returns False only when nothing was there. A filesystem refusal raises,
        because a delete that quietly failed would let the caller record a
        retention deletion that never happened.
        """
        path = self.resolve(key)
        return await anyio.to_thread.run_sync(self._unlink, path)

    async def exists(self, key: str) -> bool:
        path = self.resolve(key)
        return await anyio.to_thread.run_sync(self._is_regular_file, path)

    # ------------------------------------------------------------------
    # blocking helpers, always called through a worker thread
    # ------------------------------------------------------------------
    def _prepare_parent(self, path: Path) -> None:
        try:
            path.parent.mkdir(parents=True, exist_ok=True, mode=_DIRECTORY_MODE)
        except OSError as error:
            logger.error("Evidence storage directory is not writable")
            raise EvidenceStorageError("evidence storage is not writable") from error

    def _create_exclusive(self, path: Path) -> int:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        try:
            return os.open(path, flags, _FILE_MODE)
        except OSError as error:
            logger.error("Evidence object could not be created")
            raise EvidenceStorageError(
                "evidence object could not be created"
            ) from error

    def _write(self, handle, chunk: bytes) -> None:
        try:
            handle.write(chunk)
        except OSError as error:
            logger.error("Evidence object could not be written")
            raise EvidenceStorageError(
                "evidence object could not be written"
            ) from error

    def _unlink(self, path: Path) -> bool:
        try:
            os.unlink(path)
        except FileNotFoundError:
            return False
        except OSError as error:
            # Never report a failed removal as a completed one: the caller uses
            # this answer to decide whether a retention deletion really happened.
            logger.error("Evidence object could not be removed")
            raise EvidenceStorageError(
                "evidence object could not be removed"
            ) from error
        return True

    def _is_regular_file(self, path: Path) -> bool:
        try:
            return path.is_file() and not path.is_symlink()
        except OSError:
            return False

    async def _discard(self, path: Path) -> None:
        """Best effort removal of a partial write; never masks the real error."""
        try:
            await anyio.to_thread.run_sync(self._unlink, path)
        except EvidenceStorageError:
            logger.warning("Partial evidence object could not be discarded")


def get_storage(settings: Settings | None = None) -> EvidenceStorage:
    """Select the configured backend, refusing anything not implemented."""
    active = settings or get_settings()
    backend = (active.EVIDENCE_STORAGE_BACKEND or "").strip().lower()
    if backend == LOCAL_BACKEND:
        return LocalFilesystemStorage(active.EVIDENCE_STORAGE_DIR)
    raise EvidenceStorageError(
        "Unsupported EVIDENCE_STORAGE_BACKEND "
        f"{backend[:30]!r}: external object storage is deferred to the "
        "deployment decision recorded in Phase 0 decision D04."
    )
