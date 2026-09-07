"""Render the standalone production template without starting infrastructure."""

import json
import os
from pathlib import Path
import secrets
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("sharepoint", [False, True])
def test_production_compose_has_private_tls_boundaries(sharepoint):
    environment = {**os.environ}
    for name in [
        "POSTGRES_PASSWORD",
        "SECRET_KEY",
        "ENCRYPTION_KEY",
        "POWERSHELL_SERVICE_SECRET",
        "API_DATABASE_URL",
        "WORKER_DATABASE_URL",
        "REDIS_URL",
        "BACKEND_PUBLIC_URL",
        "FRONTEND_URL",
        "ENGINE_GIT_SHA",
        # Phase 10 made the drift fingerprint key required rather than absent.
        "DRIFT_FACT_HMAC_KEY",
    ]:
        environment[name] = secrets.token_hex(32)
    for name in [
        "RUNTIME_CA_FILE",
        "REDIS_CERT_FILE",
        "REDIS_KEY_FILE",
        "REDIS_ACL_FILE",
        "POWERSHELL_CERT_FILE",
        "POWERSHELL_KEY_FILE",
    ]:
        environment[name] = "/tmp/synthetic-unread-config-check"
    environment["SHAREPOINT_ADMIN_URL"] = "https://synthetic-admin.sharepoint.com"
    environment["SHAREPOINT_PFX_FILE"] = "/tmp/synthetic.pfx"
    environment["SHAREPOINT_PASSWORD_FILE"] = "/tmp/synthetic-password"
    command = ["docker", "compose", "-f", "docker-compose.production.yml"]
    if sharepoint:
        command += ["-f", "docker-compose.sharepoint.yml"]
    result = subprocess.run(
        command + ["config", "--format", "json"],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    config = json.loads(result.stdout)
    assert config["networks"]["private"]["internal"] is True
    for name in ["db", "redis", "powershell-service"]:
        assert not config["services"][name].get("ports")
    assert set(config["services"]["redis"]["networks"]) == {"private"}
    assert set(config["services"]["db"]["networks"]) == {"private"}
    assert config["services"]["worker"]["environment"][
        "POWERSHELL_SERVICE_URL"
    ].startswith("https://")
    redis = (ROOT / "infrastructure/runtime/redis.conf").read_text()
    for required in [
        "port 0",
        "tls-port 6379",
        "aclfile /run/secrets/redis_acl",
        'save ""',
        "appendonly no",
    ]:
        assert required in redis

    if sharepoint:
        worker = config["services"]["worker"]
        service = config["services"]["powershell-service"]
        assert "SHAREPOINT_ADMIN_URL" not in worker["environment"]
        assert "SHAREPOINT_CERT_ALIAS" not in worker["environment"]
        alias = "default"
        mapping = json.loads(service["environment"]["SHAREPOINT_CERT_ALIASES"])
        assert mapping[alias]["path"] == "/run/secrets/sharepoint_pfx"
        assert "sharepoint_pfx" in {item["source"] for item in service["secrets"]}
        assert "sharepoint_pfx" not in {item["source"] for item in worker["secrets"]}

    dispatcher = config["services"]["dispatcher"]
    assert dispatcher["command"] == ["python", "-m", "worker.dispatcher"]
    assert "redis" not in dispatcher.get("depends_on", {})
    assert not dispatcher.get("ports")
