"""Characterisation and key-ring tests for the application encryption service.

Before Phase 10 this module had no test at all: nothing asserted a round trip,
nothing asserted what a wrong key does, and nothing asserted the empty-string
short circuit that three call sites depend on. Those characterisations are
written first, deliberately, because Phase 10 changes the module underneath
them -- a rotation capability is only safe to add on top of behaviour that is
pinned.

The key ring itself is the Phase 10 change: ``ENCRYPTION_KEY`` still encrypts,
and ``ENCRYPTION_KEY_DECRYPT_ONLY`` names keys that may still decrypt. That is
what makes a rotation a window rather than a cutover.
"""

from __future__ import annotations

import pytest
from cryptography.fernet import Fernet, InvalidToken

from app.core.config import Settings
from app.services import encryption


PRIMARY = Fernet.generate_key().decode()
RETIRED = Fernet.generate_key().decode()
STRANGER = Fernet.generate_key().decode()

# Pinned by backend-api/tests/test_phase5_config.py as the banned development
# key. Repeated here because Phase 10 must ban it in *every* key-ring slot, not
# only the primary one.
DEV_KEY = "Ps-HiS3ww5QzQPc_Mdu5-JyA_jCNbdFHMdiwWSlAfgM="  # pragma: allowlist secret


@pytest.fixture(autouse=True)
def _reset_key_ring():
    """Every test starts from a cold cache; no test leaks a key into the next."""
    encryption.reset_key_ring()
    yield
    encryption.reset_key_ring()


def _use(monkeypatch, primary: str, decrypt_only: str = "") -> None:
    settings = Settings(
        ENCRYPTION_KEY=primary, ENCRYPTION_KEY_DECRYPT_ONLY=decrypt_only
    )
    monkeypatch.setattr(encryption, "get_settings", lambda: settings)
    encryption.reset_key_ring()


# ---------------------------------------------------------------------------
# Characterisation: behaviour that existed before Phase 10 and must survive it.
# ---------------------------------------------------------------------------


def test_round_trip_returns_the_original_plaintext(monkeypatch):
    _use(monkeypatch, PRIMARY)
    assert encryption.decrypt(encryption.encrypt("tenant-secret")) == "tenant-secret"


def test_ciphertext_is_not_the_plaintext(monkeypatch):
    _use(monkeypatch, PRIMARY)
    assert encryption.encrypt("tenant-secret") != "tenant-secret"


def test_empty_plaintext_encrypts_to_empty_string(monkeypatch):
    """Three call sites store the empty string for 'no secret held'."""
    _use(monkeypatch, PRIMARY)
    assert encryption.encrypt("") == ""


def test_empty_ciphertext_decrypts_to_empty_string(monkeypatch):
    """Empty ciphertext is 'nothing stored', never a decryption failure.

    A rotation pass depends on this distinction: an empty column is a row with
    nothing to rotate, not a row whose key is missing.
    """
    _use(monkeypatch, PRIMARY)
    assert encryption.decrypt("") == ""


def test_missing_key_raises_before_any_ciphertext_is_touched(monkeypatch):
    _use(monkeypatch, "")
    with pytest.raises(ValueError, match="ENCRYPTION_KEY"):
        encryption.encrypt("tenant-secret")


def test_unicode_survives_the_round_trip(monkeypatch):
    _use(monkeypatch, PRIMARY)
    assert encryption.decrypt(encryption.encrypt("naïve—secret✓")) == "naïve—secret✓"


# ---------------------------------------------------------------------------
# The Phase 10 key ring.
# ---------------------------------------------------------------------------


def test_a_key_outside_the_ring_cannot_decrypt(monkeypatch):
    _use(monkeypatch, PRIMARY)
    ciphertext = encryption.encrypt("tenant-secret")
    _use(monkeypatch, STRANGER)
    with pytest.raises(InvalidToken):
        encryption.decrypt(ciphertext)


def test_a_retired_key_still_decrypts_what_it_encrypted(monkeypatch):
    """The rotation window: new key writes, old key still reads."""
    _use(monkeypatch, RETIRED)
    legacy = encryption.encrypt("tenant-secret")

    _use(monkeypatch, PRIMARY, decrypt_only=RETIRED)
    assert encryption.decrypt(legacy) == "tenant-secret"


def test_new_ciphertext_is_written_under_the_primary_key_only(monkeypatch):
    """Retiring a key must actually retire it for writes."""
    _use(monkeypatch, PRIMARY, decrypt_only=RETIRED)
    fresh = encryption.encrypt("tenant-secret")

    # The retired key alone cannot read it, so the primary key wrote it.
    assert Fernet(PRIMARY.encode()).decrypt(fresh.encode()).decode() == "tenant-secret"
    with pytest.raises(InvalidToken):
        Fernet(RETIRED.encode()).decrypt(fresh.encode())


def test_several_retired_keys_are_accepted_in_order(monkeypatch):
    third = Fernet.generate_key().decode()
    _use(monkeypatch, third)
    oldest = encryption.encrypt("oldest")
    _use(monkeypatch, RETIRED)
    middle = encryption.encrypt("middle")

    _use(monkeypatch, PRIMARY, decrypt_only=f"{RETIRED},{third}")
    assert encryption.decrypt(oldest) == "oldest"
    assert encryption.decrypt(middle) == "middle"
    assert encryption.decrypt(encryption.encrypt("newest")) == "newest"


def test_decrypt_only_whitespace_and_blank_entries_are_ignored(monkeypatch):
    _use(monkeypatch, RETIRED)
    legacy = encryption.encrypt("tenant-secret")
    _use(monkeypatch, PRIMARY, decrypt_only=f"  ,  {RETIRED} ,, ")
    assert encryption.decrypt(legacy) == "tenant-secret"


def test_key_ring_reports_whether_a_ciphertext_needs_rewriting(monkeypatch):
    """The rotation tool needs to know which rows are already current.

    ``needs_rewrite`` is what makes the pass resumable: a row already written
    under the primary key is skipped rather than decrypted and rewritten.
    """
    _use(monkeypatch, RETIRED)
    legacy = encryption.encrypt("tenant-secret")
    _use(monkeypatch, PRIMARY, decrypt_only=RETIRED)
    current = encryption.encrypt("tenant-secret")

    assert encryption.needs_rewrite(legacy) is True
    assert encryption.needs_rewrite(current) is False
    # Nothing stored is nothing to rewrite.
    assert encryption.needs_rewrite("") is False


def test_needs_rewrite_is_true_for_a_ciphertext_no_key_can_read(monkeypatch):
    """An unreadable row must be surfaced, never silently reported as current."""
    _use(monkeypatch, PRIMARY)
    stranger_ciphertext = Fernet(STRANGER.encode()).encrypt(b"x").decode()
    assert encryption.needs_rewrite(stranger_ciphertext) is True


def test_a_malformed_ciphertext_raises_invalid_token(monkeypatch):
    _use(monkeypatch, PRIMARY)
    with pytest.raises(InvalidToken):
        encryption.decrypt("not-a-fernet-token")


# ---------------------------------------------------------------------------
# The banned development key must be banned in every slot.
# ---------------------------------------------------------------------------


def test_development_key_is_rejected_as_the_primary_outside_dev():
    with pytest.raises(ValueError, match="development encryption key"):
        Settings(**_production_settings(ENCRYPTION_KEY=DEV_KEY))


def test_development_key_is_rejected_in_the_decrypt_only_ring_outside_dev():
    """A retired slot is still a live key; the ban has to cover it."""
    with pytest.raises(ValueError, match="development encryption key"):
        Settings(
            **_production_settings(
                ENCRYPTION_KEY=PRIMARY, ENCRYPTION_KEY_DECRYPT_ONLY=DEV_KEY
            )
        )


def test_a_malformed_decrypt_only_key_is_rejected_outside_dev():
    with pytest.raises(ValueError, match="ENCRYPTION_KEY_DECRYPT_ONLY"):
        Settings(
            **_production_settings(
                ENCRYPTION_KEY=PRIMARY, ENCRYPTION_KEY_DECRYPT_ONLY="not-a-key"
            )
        )


def test_a_valid_decrypt_only_ring_is_accepted_outside_dev():
    settings = Settings(
        **_production_settings(
            ENCRYPTION_KEY=PRIMARY, ENCRYPTION_KEY_DECRYPT_ONLY=f"{RETIRED},{STRANGER}"
        )
    )
    assert settings.decrypt_only_keys() == [RETIRED, STRANGER]


def test_the_primary_key_may_not_repeat_in_the_decrypt_only_ring():
    """A duplicated key is a configuration mistake, not a wider window."""
    with pytest.raises(ValueError, match="ENCRYPTION_KEY_DECRYPT_ONLY"):
        Settings(
            **_production_settings(
                ENCRYPTION_KEY=PRIMARY, ENCRYPTION_KEY_DECRYPT_ONLY=PRIMARY
            )
        )


def _production_settings(**overrides) -> dict:
    """A settings payload that passes every Phase 5 production check."""
    base = {
        "APP_ENV": "production",
        "DATABASE_URL": (
            "postgresql+asyncpg://autoaudit:"
            "Zk7QwErTyUiOpAsDfGhJkLzXcVbNm1234567890@db.internal:5432/autoaudit"  # pragma: allowlist secret
        ),
        "REDIS_URL": (
            "rediss://autoaudit:Zk7QwErTyUiOpAsDfGhJkLzXcVbNm1234567890@redis.internal"  # pragma: allowlist secret
            ":6379/0?ssl_cert_reqs=required&ssl_check_hostname=true"
        ),
        "SECRET_KEY": "Zk7QwErTyUiOpAsDfGhJkLzXcVbNm1234567890",  # pragma: allowlist secret
        "ENCRYPTION_KEY": PRIMARY,
        "BACKEND_PUBLIC_URL": "https://api.autoaudit.internal",
        "FRONTEND_URL": "https://app.autoaudit.internal",
    }
    base.update(overrides)
    return base
