"""Worker production settings cannot opt out of authenticated TLS boundaries."""

import secrets
import pytest
from cryptography.fernet import Fernet
from pydantic import ValidationError
from worker.config import WorkerSettings


def production():
    return dict(
        APP_ENV="production",
        DATABASE_URL=f"postgresql://worker:{secrets.token_hex(32)}@db/autoaudit",
        REDIS_URL=f"rediss://worker:{secrets.token_hex(32)}@redis:6379/0?ssl_cert_reqs=required&ssl_check_hostname=true",
        ENCRYPTION_KEY=Fernet.generate_key().decode(),
        POWERSHELL_SERVICE_SECRET=secrets.token_hex(32),
        POWERSHELL_SERVICE_URL="https://powershell-service:8001",
    )


def test_valid_production_worker():
    assert WorkerSettings(_env_file=None, **production()).APP_ENV == "production"


@pytest.mark.parametrize(
    "key,value",
    [
        ("APP_ENV", ""),
        ("POWERSHELL_SERVICE_SECRET", ""),
        ("POWERSHELL_SERVICE_URL", "http://powershell-service:8001"),
        ("REDIS_URL", "redis://redis:6379"),
        ("ENCRYPTION_KEY", ""),
        ("DATABASE_URL", "postgresql://worker@db/autoaudit"),
    ],
)
def test_worker_rejects_unsafe_production_config(key, value):
    values = production()
    values[key] = value
    with pytest.raises(ValidationError):
        WorkerSettings(_env_file=None, **values)


@pytest.mark.parametrize(
    "suffix", ["", "?ssl_cert_reqs=required&ssl_check_hostname=false"]
)
def test_redis_cannot_implicitly_disable_certificate_or_hostname_checks(suffix):
    values = production()
    values["REDIS_URL"] = values["REDIS_URL"].split("?", 1)[0] + suffix
    with pytest.raises(ValidationError):
        WorkerSettings(_env_file=None, **values)


def test_kombu_preserves_required_certificate_and_hostname_verification():
    import ssl
    from celery import Celery

    app = Celery(
        "synthetic",
        broker=production()["REDIS_URL"],
        broker_use_ssl={"ssl_cert_reqs": ssl.CERT_REQUIRED, "ssl_check_hostname": True},
    )
    connection = app.connection_for_write()
    assert connection.ssl["ssl_cert_reqs"] == ssl.CERT_REQUIRED
    assert connection.ssl["ssl_check_hostname"] is True


def test_redis_failover_cannot_disable_tls():
    values = production()
    values["REDIS_URL"] += (
        "#;rediss://worker:synthetic@other/0?ssl_cert_reqs=none&ssl_check_hostname=false"  # pragma: allowlist secret
    )
    with pytest.raises(ValidationError):
        WorkerSettings(_env_file=None, **values)


def test_startup_validation_does_not_print_secret_inputs():
    values = production()
    values["DATABASE_URL"] = (
        "postgresql://user:SYNTHETIC_CANARY@db/autoaudit"  # pragma: allowlist secret
    )
    with pytest.raises(ValidationError) as error:
        WorkerSettings(_env_file=None, **values)
    assert "SYNTHETIC_CANARY" not in str(error.value)
    assert values["ENCRYPTION_KEY"] not in str(error.value)
