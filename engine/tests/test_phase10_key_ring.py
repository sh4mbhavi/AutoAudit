"""The worker half of the Phase 10 encryption key ring.

The API and the worker hold the same key ring but share no code -- the same
situation the PowerShell executor documents about its duplicated validator. A
rotation implemented in only one of them breaks the other silently, and only at
scan time, so the contract is asserted on both sides.

The worker never encrypts. Its whole obligation is: read what the API wrote,
under the primary key or under any key still listed as retired.
"""

from __future__ import annotations

import pytest
from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from worker import db
from worker.config import WorkerSettings


PRIMARY = Fernet.generate_key().decode()
RETIRED = Fernet.generate_key().decode()
STRANGER = Fernet.generate_key().decode()

DEV_KEY = "Ps-HiS3ww5QzQPc_Mdu5-JyA_jCNbdFHMdiwWSlAfgM="  # pragma: allowlist secret


@pytest.fixture(autouse=True)
def _cold_ring():
    db.reset_key_ring()
    yield
    db.reset_key_ring()


def _use(monkeypatch, primary: str, decrypt_only: str = "") -> None:
    """Point the worker's module-level settings singleton at a key ring."""
    monkeypatch.setattr(db.settings, "ENCRYPTION_KEY", primary, raising=False)
    monkeypatch.setattr(
        db.settings, "ENCRYPTION_KEY_DECRYPT_ONLY", decrypt_only, raising=False
    )
    db.reset_key_ring()


def test_worker_decrypts_what_the_primary_key_wrote(monkeypatch):
    _use(monkeypatch, PRIMARY)
    ciphertext = Fernet(PRIMARY.encode()).encrypt(b"tenant-secret").decode()
    assert db.decrypt(ciphertext) == "tenant-secret"


def test_worker_decrypts_what_a_retired_key_wrote(monkeypatch):
    """The rotation window seen from the worker: old rows still readable."""
    _use(monkeypatch, PRIMARY, decrypt_only=RETIRED)
    legacy = Fernet(RETIRED.encode()).encrypt(b"tenant-secret").decode()
    assert db.decrypt(legacy) == "tenant-secret"


def test_worker_rejects_a_key_outside_the_ring(monkeypatch):
    _use(monkeypatch, PRIMARY, decrypt_only=RETIRED)
    stranger = Fernet(STRANGER.encode()).encrypt(b"tenant-secret").decode()
    with pytest.raises(InvalidToken):
        db.decrypt(stranger)


def test_empty_ciphertext_is_nothing_stored_not_a_failure(monkeypatch):
    """Several fixtures store the empty string; it must not raise."""
    _use(monkeypatch, PRIMARY)
    assert db.decrypt("") == ""


def test_missing_key_raises_before_touching_a_ciphertext(monkeypatch):
    _use(monkeypatch, "")
    with pytest.raises(ValueError, match="ENCRYPTION_KEY"):
        db.decrypt("anything")


def test_the_ring_is_a_multifernet_but_a_plain_fernet_may_replace_it(monkeypatch):
    """test_phase3_migrated_integration monkeypatches ``_fernet`` with a Fernet.

    That substitution has to keep working: MultiFernet and Fernet share the
    decrypt() signature, and this test is what stops a future refactor from
    breaking the integration test in a way that only shows up against a real
    database.
    """
    _use(monkeypatch, PRIMARY)
    assert isinstance(db.get_fernet(), MultiFernet)

    substitute = Fernet(STRANGER.encode())
    monkeypatch.setattr(db, "_fernet", substitute)
    assert db.decrypt(substitute.encrypt(b"fixture").decode()) == "fixture"


def test_worker_and_api_agree_on_the_retired_key_parsing():
    """Both services must split ENCRYPTION_KEY_DECRYPT_ONLY identically."""
    settings = WorkerSettings(
        ENCRYPTION_KEY=PRIMARY,
        ENCRYPTION_KEY_DECRYPT_ONLY=f"  ,{RETIRED} ,, {STRANGER}",
    )
    assert settings.decrypt_only_keys() == [RETIRED, STRANGER]


def test_development_key_is_banned_in_every_slot_outside_dev():
    for ring in ({"ENCRYPTION_KEY": DEV_KEY}, {"ENCRYPTION_KEY_DECRYPT_ONLY": DEV_KEY}):
        with pytest.raises(ValueError, match="development encryption key"):
            WorkerSettings(**_production_settings(**ring))


def test_a_malformed_retired_key_is_rejected_outside_dev():
    with pytest.raises(ValueError, match="ENCRYPTION_KEY_DECRYPT_ONLY"):
        WorkerSettings(**_production_settings(ENCRYPTION_KEY_DECRYPT_ONLY="not-a-key"))


def test_the_primary_key_may_not_repeat_in_the_retired_ring():
    with pytest.raises(ValueError, match="ENCRYPTION_KEY_DECRYPT_ONLY"):
        WorkerSettings(**_production_settings(ENCRYPTION_KEY_DECRYPT_ONLY=PRIMARY))


def _production_settings(**overrides) -> dict:
    base = {
        "APP_ENV": "production",
        "DATABASE_URL": (
            "postgresql://autoaudit:"
            "Zk7QwErTyUiOpAsDfGhJkLzXcVbNm1234567890@db.internal:5432/autoaudit"  # pragma: allowlist secret
        ),
        "REDIS_URL": (
            "rediss://autoaudit:Zk7QwErTyUiOpAsDfGhJkLzXcVbNm1234567890@redis.internal"  # pragma: allowlist secret
            ":6379/0?ssl_cert_reqs=required&ssl_check_hostname=true"
        ),
        "ENCRYPTION_KEY": PRIMARY,
        "POWERSHELL_SERVICE_SECRET": "Zk7QwErTyUiOpAsDfGhJkLzXcVbNm1234567890",  # pragma: allowlist secret
        "POWERSHELL_SERVICE_URL": "https://powershell-service:8001",
        "ENGINE_GIT_SHA": "0" * 40,
    }
    base.update(overrides)
    return base
