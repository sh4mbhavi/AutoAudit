from urllib.parse import urlsplit, unquote, parse_qs
from cryptography.fernet import Fernet
from pydantic import model_validator
from pydantic import EmailStr, SecretStr, Field
from pydantic_settings import BaseSettings

# Pinned by tests as the one key that may never be used outside development.
DEV_ENCRYPTION_KEY = (
    "Ps-HiS3ww5QzQPc_Mdu5-JyA_jCNbdFHMdiwWSlAfgM="  # pragma: allowlist secret
)


class Settings(BaseSettings):
    # The below settings are defaults, and not duplicates of .env
    # The contents of .env overrides what is defined here.
    APP_ENV: str = "dev"
    # Explicit opt-in for local development only; never reset existing accounts.
    DEV_ADMIN_SEED_ENABLED: bool = False
    DEV_ADMIN_EMAIL: EmailStr | None = None
    DEV_ADMIN_PASSWORD: SecretStr | None = None

    API_PREFIX: str = "/v1"

    # Database
    DATABASE_URL: str = "postgresql+asyncpg://autoaudit:autoaudit_dev_password@localhost:5432/autoaudit"  # pragma: allowlist secret

    # Authentication
    SECRET_KEY: str = "change-this-to-a-secure-random-string-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    SESSION_ABSOLUTE_SECONDS: int = 8 * 60 * 60

    # Public URLs (used for OAuth redirects)
    # These must be the externally reachable URLs (e.g. localhost from the browser).
    BACKEND_PUBLIC_URL: str = "http://localhost:8000"
    FRONTEND_URL: str = "http://localhost:3000"

    # Google OAuth (SSO)
    GOOGLE_OAUTH_CLIENT_ID: str = ""
    GOOGLE_OAUTH_CLIENT_SECRET: str = ""

    # Redis (for Celery broker)
    REDIS_URL: str = "redis://localhost:6379"
    SCAN_DEADLINE_SECONDS: int = Field(default=3600, ge=60, le=86400)

    # OPA (Open Policy Agent)
    OPA_URL: str = "http://localhost:8181"

    # Encryption (for securing credentials at rest)
    # Generate with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    ENCRYPTION_KEY: str = ""
    # Phase 10 key ring. Retired keys, comma-separated, most recent first. They
    # may still decrypt; only ENCRYPTION_KEY encrypts. A rotation deploys a new
    # primary with the previous one listed here, runs
    # tools/ops/rotate_encryption_key.py, and only then drops the entry --
    # removing it earlier makes every not-yet-rewritten row unreadable.
    ENCRYPTION_KEY_DECRYPT_ONLY: str = ""

    # Policies directory (for benchmark/control metadata)
    POLICIES_DIR: str = "/app/policies"

    # Versioned SOC 2 crosswalk mappings, mounted read-only alongside the policies.
    MAPPINGS_DIR: str = "/app/mappings"
    # The mapping a new scan pins. Reports render from the pinned snapshot, so
    # changing this only affects scans created afterwards.
    SOC2_MAPPING_ID: str = "soc2-common-criteria-to-cis-m365"
    SOC2_MAPPING_VERSION: str = "v1.0.0"

    # ------------------------------------------------------------------
    # Phase 7 evidence bounds. Every limit fails closed: exceeding one rejects
    # the upload rather than truncating it, because truncated evidence that is
    # scored as complete is exactly the failure this phase exists to prevent.
    # ------------------------------------------------------------------
    EVIDENCE_STORAGE_BACKEND: str = "local"
    EVIDENCE_STORAGE_DIR: str = "/app/evidence-store"
    EVIDENCE_MAX_UPLOAD_BYTES: int = Field(
        default=25 * 1024 * 1024, ge=1, le=512 * 1024 * 1024
    )
    # Read in bounded chunks so an oversized body is rejected before it is buffered.
    EVIDENCE_READ_CHUNK_BYTES: int = Field(
        default=1024 * 1024, ge=4096, le=8 * 1024 * 1024
    )
    EVIDENCE_MAX_PDF_PAGES: int = Field(default=200, ge=1, le=5000)
    EVIDENCE_MAX_IMAGE_PIXELS: int = Field(
        default=40_000_000, ge=1_000_000, le=500_000_000
    )
    # Guards zip-based container formats (docx) against decompression bombs.
    EVIDENCE_MAX_ARCHIVE_ENTRIES: int = Field(default=512, ge=1, le=10_000)
    EVIDENCE_MAX_ARCHIVE_RATIO: int = Field(default=120, ge=2, le=10_000)
    EVIDENCE_MAX_EXTRACTED_CHARS: int = Field(default=2_000_000, ge=1000)
    EVIDENCE_PROCESSING_TIMEOUT_SECONDS: int = Field(default=120, ge=5, le=3600)
    EVIDENCE_PROCESSING_MEMORY_MB: int = Field(default=1024, ge=128, le=16384)

    # D04 is an unapproved draft, so these are engineering defaults bound to a
    # recorded policy version rather than a retention commitment.
    EVIDENCE_RETENTION_POLICY_VERSION: str = "phase7-draft-1"
    EVIDENCE_RETENTION_DAYS: int = Field(default=365, ge=1, le=3650)
    EVIDENCE_TEMP_RETENTION_HOURS: int = Field(default=24, ge=1, le=720)

    def decrypt_only_keys(self) -> list[str]:
        """The retired keys, in order, with blank entries dropped.

        Order matters only for how quickly a read finds its key; correctness
        does not depend on it.
        """
        return [
            key.strip()
            for key in self.ENCRYPTION_KEY_DECRYPT_ONLY.split(",")
            if key.strip()
        ]

    @model_validator(mode="after")
    def validate_runtime_security(self):
        if not 60 <= self.SESSION_ABSOLUTE_SECONDS <= 8 * 60 * 60:
            raise ValueError(
                "Session absolute lifetime must be between 60 seconds and 8 hours"
            )
        if (
            not 1 <= self.ACCESS_TOKEN_EXPIRE_MINUTES <= 60
            or self.ACCESS_TOKEN_EXPIRE_MINUTES * 60 > self.SESSION_ABSOLUTE_SECONDS
        ):
            raise ValueError(
                "Session idle lifetime must fit within the absolute lifetime"
            )
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
        # A retired key is still a live key: it decrypts stored tenant
        # credentials. Every check applied to the primary applies to the ring.
        retired = self.decrypt_only_keys()
        for key in retired:
            try:
                Fernet(key.encode())
            except (ValueError, TypeError):
                raise ValueError(
                    "ENCRYPTION_KEY_DECRYPT_ONLY must list valid Fernet keys"
                ) from None
        if len(set(retired)) != len(retired) or self.ENCRYPTION_KEY in retired:
            raise ValueError(
                "ENCRYPTION_KEY_DECRYPT_ONLY must not repeat a key or the primary"
            )
        if DEV_ENCRYPTION_KEY in {self.ENCRYPTION_KEY, *retired}:
            raise ValueError("The development encryption key is prohibited")
        if not strong(self.SECRET_KEY):
            raise ValueError("A strong SECRET_KEY is required outside dev")
        if self.DEV_ADMIN_SEED_ENABLED:
            raise ValueError("Development administrator seeding is prohibited")
        if self.ALGORITHM != "HS256" or not 1 <= self.ACCESS_TOKEN_EXPIRE_MINUTES <= 60:
            raise ValueError("Invalid authentication lifetime or algorithm")
        for value in (self.BACKEND_PUBLIC_URL, self.FRONTEND_URL):
            origin = urlsplit(value)
            if (
                origin.scheme != "https"
                or not origin.hostname
                or origin.username
                or origin.password
                or origin.query
                or origin.fragment
                or origin.path not in {"", "/"}
                or "*" in value
                or origin.hostname in {"localhost", "127.0.0.1", "::1"}
            ):
                raise ValueError(
                    "Public URLs must be explicit HTTPS origins outside dev"
                )
        return self

    class Config:
        env_file = ".env"
        hide_input_in_errors = True


def get_settings() -> Settings:
    return Settings()
