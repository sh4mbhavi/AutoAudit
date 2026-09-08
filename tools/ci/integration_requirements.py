"""CI must never silently skip the database and real OPA integration suites."""

import os
import subprocess
from urllib.parse import urlsplit

import pytest


def pytest_sessionstart(session):
    if os.environ.get("AUTOAUDIT_REQUIRE_INTEGRATION") != "1":
        return
    url = urlsplit(os.environ.get("MIGRATION_TEST_ADMIN_URL", ""))
    if url.scheme != "postgresql" or url.hostname not in {"127.0.0.1", "::1"}:
        raise pytest.UsageError(
            "CI requires a disposable loopback MIGRATION_TEST_ADMIN_URL"
        )
    binary = os.environ.get("OPA_BINARY")
    if not binary:
        raise pytest.UsageError(
            "CI requires OPA_BINARY; integration tests cannot be skipped"
        )
    result = subprocess.run(
        [binary, "version"], capture_output=True, text=True, check=True
    )
    if "Version: 1.20.2\n" not in result.stdout:
        raise pytest.UsageError("CI requires reviewed OPA 1.20.2")
