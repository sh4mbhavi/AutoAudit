"""SEC-03/SEC-04: bootstrap is opt-in and lifecycle logs never carry secrets."""

import asyncio
import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.core.config import Settings
from app.core.users import UserManager
from app.db import init_db
from fastapi_users.password import PasswordHelper
from pydantic import SecretStr


@pytest.fixture
def session(monkeypatch):
    db = MagicMock()
    db.execute = AsyncMock(return_value=MagicMock())
    db.commit = AsyncMock()
    db.execute.return_value.unique.return_value.scalar_one_or_none.return_value = None
    context = MagicMock()
    context.__aenter__ = AsyncMock(return_value=db)
    context.__aexit__ = AsyncMock(return_value=False)
    factory = MagicMock(return_value=context)
    monkeypatch.setattr(init_db, "async_session_maker", factory)
    return db, factory


def configure(monkeypatch, environment="dev", enabled=True):
    password = SecretStr("local-only-" + "generated-at-test-runtime-928!")
    settings = SimpleNamespace(
        APP_ENV=environment,
        DEV_ADMIN_SEED_ENABLED=enabled,
        DEV_ADMIN_EMAIL="developer@example.invalid",
        DEV_ADMIN_PASSWORD=password,
    )
    monkeypatch.setattr(init_db, "get_settings", lambda: settings, raising=False)
    return settings


@pytest.mark.parametrize(
    "environment",
    ["production", "prod", "preview", "staging", "", "development", "DEV"],
)
def test_non_dev_seed_never_opens_database(monkeypatch, session, environment):
    configure(monkeypatch, environment)
    asyncio.run(init_db.init_db())
    session[1].assert_not_called()


def test_disabled_seed_never_opens_database(monkeypatch, session):
    configure(monkeypatch, enabled=False)
    asyncio.run(init_db.init_db())
    session[1].assert_not_called()


def test_seeding_defaults_are_disabled():
    settings = Settings(_env_file=None)
    assert getattr(settings, "DEV_ADMIN_SEED_ENABLED", None) is False
    assert not getattr(settings, "DEV_ADMIN_EMAIL", None)
    assert not getattr(settings, "DEV_ADMIN_PASSWORD", None)


def test_explicit_dev_seed_hashes_password_without_logging(
    monkeypatch, session, capsys, caplog
):
    config = configure(monkeypatch)
    with caplog.at_level(logging.INFO):
        asyncio.run(init_db.init_db())
    user = session[0].add.call_args.args[0]
    assert user.email == config.DEV_ADMIN_EMAIL
    assert PasswordHelper().verify_and_update(
        config.DEV_ADMIN_PASSWORD.get_secret_value(), user.hashed_password
    )[0]
    assert user.role == "admin" and user.is_superuser and user.is_verified
    session[0].commit.assert_awaited_once()
    output = capsys.readouterr()
    assert (
        config.DEV_ADMIN_PASSWORD.get_secret_value()
        not in output.out + output.err + caplog.text
    )


def test_existing_account_is_not_reset_or_promoted(monkeypatch, session):
    configure(monkeypatch)
    existing = SimpleNamespace(
        email="developer@example.invalid",
        hashed_password="existing-hash",  # pragma: allowlist secret - synthetic stored value
        role="user",
        is_active=False,
        is_superuser=False,
        is_verified=False,
    )
    before = vars(existing).copy()
    session[
        0
    ].execute.return_value.unique.return_value.scalar_one_or_none.return_value = (
        existing
    )
    asyncio.run(init_db.init_db())
    assert vars(existing) == before
    session[0].commit.assert_not_awaited()
    session[0].add.assert_not_called()


@pytest.mark.parametrize("missing", ["DEV_ADMIN_EMAIL", "DEV_ADMIN_PASSWORD"])
def test_missing_seed_credentials_fail_before_database(monkeypatch, session, missing):
    config = configure(monkeypatch)
    setattr(config, missing, None)
    with pytest.raises(ValueError, match="DEV_ADMIN"):
        asyncio.run(init_db.init_db())
    session[1].assert_not_called()


@pytest.mark.parametrize(
    "callback", ["on_after_forgot_password", "on_after_request_verify"]
)
def test_lifecycle_logs_do_not_expose_tokens(callback, capsys, caplog):
    token = "sensitive-" + "runtime-canary-92831"
    manager = UserManager(MagicMock())
    with caplog.at_level(logging.INFO):
        asyncio.run(getattr(manager, callback)(SimpleNamespace(id=42), token))
    captured = capsys.readouterr()
    assert token not in captured.out + captured.err + caplog.text
    assert "42" in caplog.text


def test_short_seed_password_fails_before_database(monkeypatch, session):
    config = configure(monkeypatch)
    config.DEV_ADMIN_PASSWORD = SecretStr("too-short")
    with pytest.raises(ValueError, match="at least 16"):
        asyncio.run(init_db.init_db())
    session[1].assert_not_called()


@pytest.mark.parametrize("environment", ["dev", "preview", "production"])
def test_container_entrypoint_only_migrates_and_starts(environment, tmp_path):
    import os
    import subprocess
    from pathlib import Path

    calls = tmp_path / "calls"
    uv = tmp_path / "uv"
    uv.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$CALLS"\n')
    uv.chmod(0o755)
    entrypoint = Path(__file__).resolve().parents[1] / "entrypoint.sh"
    subprocess.run(
        ["bash", str(entrypoint)],
        check=True,
        capture_output=True,
        env={
            **os.environ,
            "PATH": str(tmp_path) + os.pathsep + os.environ["PATH"],
            "CALLS": str(calls),
            "APP_ENV": environment,
            "DEV_ADMIN_SEED_ENABLED": "true",
        },
    )
    assert calls.read_text().splitlines() == [
        "run alembic upgrade head",
        "run uvicorn app.main:app --host 0.0.0.0 --port 8000",
    ]
