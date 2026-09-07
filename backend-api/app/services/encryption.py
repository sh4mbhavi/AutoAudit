"""Encryption service for securing sensitive data at rest.

Uses Fernet symmetric encryption. Keys are 32-byte base64-encoded values.

``ENCRYPTION_KEY`` is the **primary** key: it is the only key that encrypts.
``ENCRYPTION_KEY_DECRYPT_ONLY`` is an ordered, comma-separated list of retired
keys that may still *decrypt*. Together they make a key rotation a window
rather than a cutover: a new primary can be deployed while the previous key is
still able to read every row written under it, and a re-encryption pass can then
move rows across at its own pace.

Before Phase 10 there was exactly one key and no fallback, so changing
``ENCRYPTION_KEY`` made every stored M365 client secret permanently unreadable
the moment the process restarted -- a fact Phase 5's deployment note warned
about but nothing in the code could soften.

A Fernet token's leading version byte identifies the *format*, not the key, so a
ciphertext cannot say which key wrote it. ``needs_rewrite`` therefore answers
that question by trial: a row the primary key can read is already current, and
anything else still has to be rewritten. That is what makes a rotation pass
resumable without adding a key-id column to five tables.

Generate a key with:
    python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from app.core.config import get_settings

if TYPE_CHECKING:  # pragma: no cover - typing only
    from fastapi import HTTPException

__all__ = [
    "InvalidToken",
    "decrypt",
    "encrypt",
    "needs_rewrite",
    "reset_key_ring",
    "unreadable_credential",
]

# The primary key alone (writes, and the "is this row current" probe) and the
# whole ring (reads). Cached because building a Fernet derives key material.
_primary: Fernet | None = None
_ring: MultiFernet | None = None


def reset_key_ring() -> None:
    """Drop the cached keys so the next call re-reads configuration.

    A deployed process still needs a restart to pick up a new key -- this exists
    for the rotation tool, which runs as its own process, and for tests.
    """
    global _primary, _ring
    _primary = None
    _ring = None


def _load() -> tuple[Fernet, MultiFernet]:
    global _primary, _ring
    if _primary is None or _ring is None:
        settings = get_settings()
        if not settings.ENCRYPTION_KEY:
            raise ValueError(
                "ENCRYPTION_KEY environment variable is required. "
                'Generate one with: python -c "from cryptography.fernet import '
                'Fernet; print(Fernet.generate_key().decode())"'
            )
        primary = Fernet(settings.ENCRYPTION_KEY.encode())
        # MultiFernet decrypts with the first key that accepts the token and
        # encrypts with the first key in the list, so the primary must lead.
        keys = [primary] + [
            Fernet(key.encode()) for key in settings.decrypt_only_keys()
        ]
        _primary, _ring = primary, MultiFernet(keys)
    return _primary, _ring


def get_fernet() -> MultiFernet:
    """The whole key ring: encrypts under the primary, decrypts under any key.

    Retained under its original name because call sites and tests reference it.
    """
    return _load()[1]


def encrypt(plaintext: str) -> str:
    """Encrypt a string under the primary key and return the ciphertext.

    An empty plaintext stays empty: three call sites store the empty string to
    mean "no secret held", and that is not something to encrypt.
    """
    if not plaintext:
        return ""
    return get_fernet().encrypt(plaintext.encode()).decode()


def decrypt(ciphertext: str) -> str:
    """Decrypt a ciphertext under any key in the ring.

    Raises:
        InvalidToken: if no key in the ring can read the ciphertext. The
            exception carries no key material and no plaintext; callers must not
            add either when they handle it.
    """
    if not ciphertext:
        return ""
    return get_fernet().decrypt(ciphertext.encode()).decode()


def needs_rewrite(ciphertext: str) -> bool:
    """Whether this ciphertext was written under something other than the primary.

    Empty ciphertext is nothing stored, so nothing to rewrite. A ciphertext no
    key in the ring can read returns True -- it is surfaced as work rather than
    silently reported as current, because a row nobody can decrypt is exactly
    what an operator needs to hear about.
    """
    if not ciphertext:
        return False
    primary, _ = _load()
    try:
        primary.decrypt(ciphertext.encode())
    except InvalidToken:
        return True
    return False


def unreadable_credential(column: str) -> "HTTPException":
    """The response for ciphertext no key in the ring can read.

    Shared rather than written per call site: there are three decrypt call sites
    on stored connection secrets, and an earlier version of this phase guarded
    two of them. The third -- the scan readiness check -- kept raising an
    unhandled InvalidToken, so the one endpoint a user hits *before* starting a
    scan was the one that answered 500 with a traceback.

    409, not 500: it is not a server fault. It means the deployment is carrying
    the wrong key ring, which an operator fixes and a retry does not. The detail
    names no ciphertext, no tenant and no key.
    """
    # Imported here so this module stays importable without FastAPI.
    from fastapi import HTTPException, status

    from app.core.metrics import decryption_failures_total

    decryption_failures_total.labels(column=column).inc()
    return HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail={"code": "credential_unreadable"},
    )
