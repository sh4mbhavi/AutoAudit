"""The actual project pytest commands must reject missing CI prerequisites."""

import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("project", ["backend-api", "engine"])
def test_ci_collection_refuses_missing_integration_configuration(project):
    environment = {**os.environ, "AUTOAUDIT_REQUIRE_INTEGRATION": "1"}
    environment.pop("MIGRATION_TEST_ADMIN_URL", None)
    environment.pop("OPA_BINARY", None)
    command = ["uv", "run", "--frozen", "--project", project, "--extra", "dev"]
    if project == "backend-api":
        command += ["--extra", "evidence"]
    command += ["python", "-m", "pytest", f"{project}/tests", "--collect-only", "-q"]
    result = subprocess.run(
        command,
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert (
        result.returncode == 4
    ), "CI must refuse collection without its integration prerequisites"
    assert "CI requires a disposable loopback MIGRATION_TEST_ADMIN_URL" in result.stderr
