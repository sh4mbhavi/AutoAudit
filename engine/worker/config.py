"""Configuration for the Celery worker."""

from urllib.parse import urlsplit, unquote, parse_qs
from cryptography.fernet import Fernet
from pydantic import Field, model_validator

import os

from pydantic_settings import BaseSettings


class WorkerSettings(BaseSettings):
    """Worker configuration loaded from environment variables."""

    APP_ENV: str = "dev"

    # Database
    DATABASE_URL: str = "postgresql://autoaudit:autoaudit_dev_password@localhost:5432/autoaudit"  # pragma: allowlist secret

    # Redis (Celery broker)
    REDIS_URL: str = "redis://localhost:6379/0"

    # Durable scan lifecycle; recovery is a standalone DB polling service.
    SCAN_DEADLINE_SECONDS: int = Field(default=3600, ge=30)
    DISPATCH_POLL_SECONDS: float = Field(default=5, ge=0.1)
    DISPATCH_RETRY_SECONDS: int = Field(default=15, ge=1)
    DISPATCH_STALL_SECONDS: int = Field(default=1200, ge=30)
    DISPATCH_MAX_ATTEMPTS: int = Field(default=8, ge=1, le=100)
    DISPATCH_BATCH_SIZE: int = Field(default=100, ge=1)

    # Phase 9 collection shape.
    #
    # GRAPH_MAX_CONCURRENCY bounds what a single collector may have in flight
    # against one tenant. It is deliberately small: Graph throttles per
    # application per tenant, and the purpose of bounded concurrency is to
    # remove serial latency from per-item requests, not to raise the burst rate.
    # POWERSHELL_MAX_BATCH bounds how many reviewed operations may share one
    # remote session, so a tenant with thousands of mailboxes cannot build an
    # unbounded script or hold one session open indefinitely.
    GRAPH_MAX_CONCURRENCY: int = Field(default=4, ge=1, le=16)
    POWERSHELL_MAX_BATCH: int = Field(default=25, ge=1, le=200)

    # OPA (Open Policy Agent)
    OPA_BINARY: str = "opa"
    ENGINE_GIT_SHA: str = ""
    ENGINE_IMAGE_DIGEST: str = ""

    OPA_URL: str = "http://localhost:8181"

    # Encryption key for decrypting credentials
    ENCRYPTION_KEY: str = ""

    # Policies directory
    POLICIES_DIR: str = os.path.join(os.path.dirname(__file__), "..", "policies")

    # PowerShell service URL (optional - if set, uses HTTP instead of Docker)
    POWERSHELL_SERVICE_URL: str | None = None
    POWERSHELL_SERVICE_SECRET: str = ""
    POWERSHELL_CA_FILE: str | None = None

    # Deprecated compatibility settings; scan execution never reads global SharePoint identity.
    SHAREPOINT_ADMIN_URL: str | None = None
    # Certificate alias resolved by the PowerShell service SHAREPOINT_CERT_ALIASES map.
    # V1 uses a single mounted alias.
    SHAREPOINT_CERT_ALIAS: str = "default"

    # Performance mode: PowerShell-based controls (Exchange/Compliance/Teams) are much slower
    # than Graph-based controls. Default is True to preserve full scan coverage.
    ENABLE_POWERSHELL_CONTROLS: bool = True

    # Configuration drift (Phase 8). The key is the gate, not a boolean flag: with no
    # usable DRIFT_FACT_HMAC_KEY zero factprint rows are written and drift reports
    # fingerprints_unavailable. A short or malformed key writes nothing; there is never
    # a fallback to an unkeyed digest, because an unkeyed digest of a boolean or a small
    # enum is a lookup table rather than a pseudonym.
    DRIFT_FACT_HMAC_KEY: str = ""
    DRIFT_MAX_EVENTS_PER_RUN: int = Field(default=2000, ge=1)
    DRIFT_MAX_SET_MEMBERS: int = Field(default=25, ge=1)

    @model_validator(mode="after")
    def validate_runtime_security(self):
        if self.APP_ENV == "dev":
            return self
        if self.APP_ENV not in {"production", "prod", "staging", "preview", "test"}:
            raise ValueError("APP_ENV must be an explicit supported environment")

        def strong(value):
            return len(value) >= 32 and not any(
                marker in value.lower()
                for marker in (
                    "change",
                    "example",
                    "password",
                    "autoaudit_dev",
                    "your-",
                    "dev-secret",
                )
            )

        database = urlsplit(self.DATABASE_URL)
        redis = urlsplit(self.REDIS_URL)
        if ";" in self.REDIS_URL or redis.fragment:
            raise ValueError("Redis failover lists and fragments are prohibited")
        if (
            database.scheme not in {"postgresql", "postgresql+asyncpg"}
            or not database.hostname
            or not database.username
            or not strong(unquote(database.password or ""))
        ):
            raise ValueError(
                "DATABASE_URL requires explicit database credentials outside dev"
            )
        if (
            redis.scheme != "rediss"
            or not redis.hostname
            or not strong(unquote(redis.password or ""))
        ):
            raise ValueError("REDIS_URL requires authenticated TLS outside dev")
        # TLS verification may not be disabled through URL options.
        options = parse_qs(redis.query)
        if options.get("ssl_cert_reqs") != ["required"]:
            raise ValueError("Redis TLS certificate verification is required")
        if options.get("ssl_check_hostname") != ["true"]:
            raise ValueError("Redis TLS hostname verification is required")
        try:
            Fernet(self.ENCRYPTION_KEY.encode())
        except (ValueError, TypeError):
            raise ValueError("A valid ENCRYPTION_KEY is required outside dev") from None
        if (
            self.ENCRYPTION_KEY
            == "Ps-HiS3ww5QzQPc_Mdu5-JyA_jCNbdFHMdiwWSlAfgM="  # pragma: allowlist secret
        ):  # pragma: allowlist secret
            raise ValueError("The development encryption key is prohibited")
        if not strong(self.POWERSHELL_SERVICE_SECRET):
            raise ValueError("POWERSHELL_SERVICE_SECRET is required outside dev")
        service = urlsplit(self.POWERSHELL_SERVICE_URL or "")
        if (
            service.scheme != "https"
            or not service.hostname
            or service.username
            or service.password
        ):
            raise ValueError("POWERSHELL_SERVICE_URL requires HTTPS outside dev")
        return self

    class Config:
        env_file = ".env"
        hide_input_in_errors = True


def get_settings() -> WorkerSettings:
    """Get worker settings instance."""
    return WorkerSettings()


settings = get_settings()
