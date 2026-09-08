"""Production settings reject development defaults before opening services."""

import secrets
import pytest
from cryptography.fernet import Fernet
from pydantic import ValidationError
from app.core.config import Settings


def production():
    return dict(
        APP_ENV="production",
        SECRET_KEY=secrets.token_hex(32),
        DATABASE_URL=f"postgresql+asyncpg://api:{secrets.token_hex(32)}@db/autoaudit",
        REDIS_URL=f"rediss://worker:{secrets.token_hex(32)}@redis:6379/0?ssl_cert_reqs=required&ssl_check_hostname=true",
        ENCRYPTION_KEY=Fernet.generate_key().decode(),
        BACKEND_PUBLIC_URL="https://api.example.invalid",
        FRONTEND_URL="https://app.example.invalid",
    )


@pytest.mark.parametrize(
    "environment", ["production", "staging", "preview", "test", "DEV", ""]
)
def test_nondev_defaults_fail(environment):
    with pytest.raises(ValidationError):
        Settings(_env_file=None, APP_ENV=environment)


def test_explicit_production_settings_are_valid():
    assert Settings(_env_file=None, **production()).APP_ENV == "production"


@pytest.mark.parametrize(
    "key,value",
    [
        ("SECRET_KEY", "change-this-to-a-secure-random-string-in-production"),
        ("ENCRYPTION_KEY", ""),
        ("ENCRYPTION_KEY", "Ps-HiS3ww5QzQPc_Mdu5-JyA_jCNbdFHMdiwWSlAfgM="),
        ("DATABASE_URL", "postgresql://autoaudit:autoaudit_dev_password@db/autoaudit"),
        ("REDIS_URL", "redis://redis:6379"),
        ("REDIS_URL", "rediss://redis:6379"),
        ("FRONTEND_URL", "*"),
        ("FRONTEND_URL", "http://app.example.invalid"),
        ("BACKEND_PUBLIC_URL", "https://localhost"),
        ("FRONTEND_URL", "https://app.example.invalid/path"),
        ("DEV_ADMIN_SEED_ENABLED", True),
        ("ACCESS_TOKEN_EXPIRE_MINUTES", 0),
    ],
)
def test_production_rejects_unsafe_settings(key, value):
    values = production()
    values[key] = value
    with pytest.raises(ValidationError):
        Settings(_env_file=None, **values)


def test_redis_tls_verification_cannot_be_disabled():
    values = production()
    values["REDIS_URL"] = values["REDIS_URL"].replace("required", "none")
    with pytest.raises(ValidationError):
        Settings(_env_file=None, **values)


@pytest.mark.parametrize(
    "suffix", ["", "?ssl_cert_reqs=required&ssl_check_hostname=false"]
)
def test_redis_cannot_implicitly_disable_certificate_or_hostname_checks(suffix):
    values = production()
    values["REDIS_URL"] = values["REDIS_URL"].split("?", 1)[0] + suffix
    with pytest.raises(ValidationError):
        Settings(_env_file=None, **values)


def test_redis_failover_cannot_disable_tls():
    values = production()
    values["REDIS_URL"] += (
        "#;rediss://worker:synthetic@other/0?ssl_cert_reqs=none&ssl_check_hostname=false"
    )
    with pytest.raises(ValidationError):
        Settings(_env_file=None, **values)


def test_startup_validation_does_not_print_secret_inputs():
    values = production()
    values["DATABASE_URL"] = "postgresql://user:SYNTHETIC_CANARY@db/autoaudit"
    with pytest.raises(ValidationError) as error:
        Settings(_env_file=None, **values)
    assert "SYNTHETIC_CANARY" not in str(error.value)
    assert values["ENCRYPTION_KEY"] not in str(error.value)
