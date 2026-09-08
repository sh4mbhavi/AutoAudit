"""Render the Purview certificate overlay without starting infrastructure."""

import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[2]

OVERLAY = "docker-compose.compliance.yml"
EXAMPLE = "docker-compose.compliance.override.yml.example"

# Every ${VAR:?} the production template refuses to render without.
REQUIRED_VALUES = [
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
    # Phase 10 made the drift fingerprint key required rather than absent; with
    # it unset no factprint row is ever written.
    "DRIFT_FACT_HMAC_KEY",
]
REQUIRED_FILES = [
    "RUNTIME_CA_FILE",
    "REDIS_CERT_FILE",
    "REDIS_KEY_FILE",
    "REDIS_ACL_FILE",
    "POWERSHELL_CERT_FILE",
    "POWERSHELL_KEY_FILE",
]


@pytest.fixture(scope="module")
def rendered(tmp_path_factory):
    """Render production + compliance overlay once for the whole module."""
    if shutil.which("docker") is None:
        pytest.skip("docker CLI is unavailable")
    tmp_path = tmp_path_factory.mktemp("compliance-overlay")
    environment = {**os.environ}
    for name in REQUIRED_VALUES:
        environment[name] = secrets.token_hex(32)
    for name in REQUIRED_FILES:
        placeholder = tmp_path / name.lower()
        placeholder.write_text("synthetic-unread-config-check\n")
        environment[name] = str(placeholder)
    # A synthetic canary stands in for certificate material: `config` must never
    # read a secret file, so this value must not appear in the rendered output.
    canary = "canary-" + secrets.token_hex(16)
    pfx = tmp_path / "compliance.pfx"
    pfx.write_text(canary + "\n")
    password = tmp_path / "compliance.password"
    password.write_text(canary + "\n")
    environment["COMPLIANCE_PFX_FILE"] = str(pfx)
    environment["COMPLIANCE_PASSWORD_FILE"] = str(password)
    result = subprocess.run(
        [
            "docker",
            "compose",
            "-f",
            "docker-compose.production.yml",
            "-f",
            OVERLAY,
            "config",
            "--format",
            "json",
        ],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=60,
    )
    return {
        "result": result,
        "canary": canary,
        "pfx": str(pfx),
        "password": str(password),
    }


def _config(rendered):
    result = rendered["result"]
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def _sources(service):
    return {item["source"] for item in service.get("secrets", []) or []}


def test_compliance_overlay_renders(rendered):
    config = _config(rendered)
    service = config["services"]["powershell-service"]
    assert "COMPLIANCE_CERT_ALIASES" in service["environment"]
    assert config["secrets"]["compliance_pfx"]["file"] == rendered["pfx"]
    assert config["secrets"]["compliance_password"]["file"] == rendered["password"]
    # `config` renders the secret's path, never its bytes.
    assert rendered["canary"] not in rendered["result"].stdout


def test_certificate_material_reaches_only_the_powershell_service(rendered):
    config = _config(rendered)
    services = config["services"]
    assert {"compliance_pfx", "compliance_password"} <= _sources(
        services["powershell-service"]
    )
    for name, service in services.items():
        if name == "powershell-service":
            continue
        assert not _sources(service) & {"compliance_pfx", "compliance_password"}, name
        assert "COMPLIANCE_CERT_ALIASES" not in (service.get("environment") or {}), name


def test_alias_map_points_at_mounted_secrets(rendered):
    config = _config(rendered)
    service = config["services"]["powershell-service"]
    mapping = json.loads(service["environment"]["COMPLIANCE_CERT_ALIASES"])
    assert mapping["default"] == {
        "path": "/run/secrets/compliance_pfx",
        "password_file": "/run/secrets/compliance_password",
    }


def test_overlay_adds_no_port_and_keeps_the_private_network_internal(rendered):
    config = _config(rendered)
    assert config["networks"]["private"]["internal"] is True
    assert not config["services"]["powershell-service"].get("ports")


def test_example_override_contains_no_real_secret():
    text = (ROOT / EXAMPLE).read_text()
    for marker in ["-----BEGIN", "PRIVATE KEY", "CERTIFICATE"]:
        assert marker not in text
    # A PFX is DER, so a real one could not survive as this file's text.
    assert text.isascii()
    hosts = [
        line.strip()[len("- ") :].split(":", 1)[0]
        for line in text.splitlines()
        if line.strip().startswith("- /")
    ]
    assert hosts, "the example must mount the certificate and its password"
    for host in hosts:
        assert "<USER>" in host, host
