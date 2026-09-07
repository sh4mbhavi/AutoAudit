"""Runtime invariants of the reviewed production topology.

Phase 5 established the network shape and asserted it: private internal network,
no host ports on the stateful and execution services, TLS everywhere. Phase 10
adds the operational half, which that template had none of while the
*development* compose had all of it -- so the reviewed production topology was
measurably less defended at runtime than a developer's laptop.

Everything here is rendered with ``docker compose config``. No container starts;
``tools/ci/container_smoke.py`` is where a running container is exercised.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess  # nosec B404 # controlled docker compose config invocation
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

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
    # Phase 10: the drift fingerprint key. Declared required so the template
    # cannot render without it -- see test_drift_fingerprint_key_is_required.
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

STATEFUL_AND_EXECUTION = ("db", "redis", "powershell-service")


@pytest.fixture(scope="module")
def rendered(tmp_path_factory):
    if shutil.which("docker") is None:
        pytest.skip("docker CLI is unavailable")
    tmp_path = tmp_path_factory.mktemp("phase10-production")
    environment = {**os.environ}
    for name in REQUIRED_VALUES:
        environment[name] = secrets.token_hex(32)
    for name in REQUIRED_FILES:
        placeholder = tmp_path / name.lower()
        placeholder.write_text("synthetic-unread-config-check\n")
        environment[name] = str(placeholder)

    result = subprocess.run(  # nosec B603 B607 # fixed docker compose arguments
        [
            "docker",
            "compose",
            "-f",
            "docker-compose.production.yml",
            "config",
            "--format",
            "json",
        ],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


# ---------------------------------------------------------------------------
# The Phase 5 shape, re-asserted because Phase 10 edits this file.
# ---------------------------------------------------------------------------


def test_no_stateful_or_execution_service_publishes_a_host_port(rendered):
    """Plan item: 'Remove production host publication for PostgreSQL, Redis,
    OPA and PowerShell.'

    Already true when Phase 10 began -- this is what turns it from a claim into
    a gate. Note there is no OPA service at all: production evaluates policy with
    the digest-pinned binary in the worker image, so there is no OPA port.
    """
    for name in STATEFUL_AND_EXECUTION:
        assert not rendered["services"][name].get("ports"), name
    assert "opa" not in rendered["services"]


def test_the_only_published_port_is_the_api_on_loopback(rendered):
    published = {
        name: service.get("ports")
        for name, service in rendered["services"].items()
        if service.get("ports")
    }
    assert set(published) == {"backend-api"}, published
    for entry in published["backend-api"]:
        assert entry["host_ip"] in {"127.0.0.1", "::1"}, entry


def test_the_private_network_stays_internal(rendered):
    assert rendered["networks"]["private"]["internal"] is True


# ---------------------------------------------------------------------------
# What Phase 10 added.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "service",
    ["db", "redis", "backend-api", "worker", "dispatcher", "powershell-service"],
)
def test_every_service_has_a_healthcheck(rendered, service):
    """The production template had none while the development one had six."""
    assert rendered["services"][service].get("healthcheck"), service


def test_the_api_readiness_probe_checks_dependencies(rendered):
    """`/liveness` returns a constant and would report healthy with no database.

    A healthcheck pointed at it is a healthcheck that cannot fail for the reason
    that matters.
    """
    probe = " ".join(rendered["services"]["backend-api"]["healthcheck"]["test"])
    assert "/readiness" in probe
    assert "/liveness" not in probe


def test_startup_is_ordered_on_health_not_merely_on_presence(rendered):
    """`depends_on` as a bare list starts the API before PostgreSQL accepts
    connections -- and the API entrypoint runs `alembic upgrade head` first."""
    for service in ("backend-api", "worker"):
        depends = rendered["services"][service].get("depends_on") or {}
        assert depends, service
        for name, spec in depends.items():
            assert spec.get("condition") == "service_healthy", (service, name)


@pytest.mark.parametrize(
    "service",
    ["db", "redis", "backend-api", "worker", "dispatcher", "powershell-service"],
)
def test_container_logs_are_bounded(rendered, service):
    """Unbounded container logs fill the host disk, and the first symptom is
    PostgreSQL refusing writes."""
    logging = rendered["services"][service].get("logging") or {}
    options = logging.get("options") or {}
    assert options.get("max-size"), service
    assert options.get("max-file"), service


@pytest.mark.parametrize(
    "service",
    ["db", "redis", "backend-api", "worker", "dispatcher", "powershell-service"],
)
def test_privilege_escalation_is_disabled(rendered, service):
    assert "no-new-privileges:true" in (
        rendered["services"][service].get("security_opt") or []
    ), service


def test_the_dispatcher_exports_metrics_on_the_private_network_only(rendered):
    """Every alert in scan_lifecycle.yaml reads a gauge this exports."""
    dispatcher = rendered["services"]["dispatcher"]
    assert dispatcher["environment"].get("METRICS_PORT")
    # Scraped from inside the private network; never published to the host.
    assert not dispatcher.get("ports")


def test_drift_fingerprint_key_is_required(rendered):
    """Phase 8's drift fingerprints were silently disabled in production.

    ``DRIFT_FACT_HMAC_KEY`` is declared in engine/worker/config.py, and with it
    unset no factprint row is ever written and drift reports
    `fingerprints_unavailable`. It appeared in no compose file, no env.example
    and no operator-facing document, so the reviewed production template shipped
    with a delivered feature turned off and nothing saying so.
    """
    # The WORKER above all: worker/tasks.py is what calls persist_factprint.
    # An earlier version of this phase set the key only on the dispatcher, which
    # fixed nothing -- the feature stayed off and the test still passed.
    assert rendered["services"]["worker"]["environment"].get("DRIFT_FACT_HMAC_KEY")
    assert rendered["services"]["dispatcher"]["environment"].get("DRIFT_FACT_HMAC_KEY")
    template = (ROOT / "docker-compose.production.yml").read_text()
    assert "DRIFT_FACT_HMAC_KEY:?" in template, "must be required, not defaulted"


@pytest.mark.parametrize("service", ["backend-api", "worker", "dispatcher"])
def test_the_encryption_key_ring_reaches_every_service(rendered, service):
    """The critical finding: the ring was configured and reached no container.

    ENCRYPTION_KEY_DECRYPT_ONLY existed in config.py, in env.example and in the
    rotation tool's documented procedure, and appeared in no compose file. Every
    service booted with a one-key ring, so an operator following step 1 of the
    rotation verbatim -- new key in ENCRYPTION_KEY, previous key in
    ENCRYPTION_KEY_DECRYPT_ONLY, then `compose up` -- would find every legacy
    row unreadable, while the rotation tool run from the host shell reported a
    healthy two-key ring. The runbook's own remediation ("restore the removed
    key to ENCRYPTION_KEY_DECRYPT_ONLY") silently did nothing.

    Compose reads .env for interpolation, not for injection, so nothing else
    would have carried it.
    """
    environment = rendered["services"][service]["environment"]
    assert (
        "ENCRYPTION_KEY_DECRYPT_ONLY" in environment
    ), f"{service} cannot participate in a key rotation without the ring"


def test_the_development_compose_can_rehearse_a_rotation():
    """A rotation should be practised somewhere before production."""
    dev = (ROOT / "docker-compose.yml").read_text()
    assert (
        dev.count("ENCRYPTION_KEY_DECRYPT_ONLY") >= 2
    ), "both the API and the worker need the ring"


def test_the_service_that_writes_factprints_is_the_one_that_holds_the_key():
    """Guard against fixing the symptom on the wrong service.

    `persist_factprint` is imported and called by engine/worker/tasks.py, which
    runs in the Celery worker. Setting DRIFT_FACT_HMAC_KEY on the dispatcher
    alone leaves every factprint unwritten while looking configured.
    """
    tasks = (ROOT / "engine" / "worker" / "tasks.py").read_text()
    assert (
        "persist_factprint" in tasks
    ), "if factprints move out of the worker, the compose template must follow"


def test_the_postgres_major_version_matches_ci_and_the_dev_compose():
    """A dump does not restore across major versions, and Phase 10 added backups.

    The dev compose ran 17 while CI, container_smoke and this template ran 16.
    """
    import re

    versions = set()
    for path in (
        ROOT / "docker-compose.yml",
        ROOT / "docker-compose.production.yml",
        ROOT / ".github" / "workflows" / "ci.backend-api.yml",
        ROOT / ".github" / "workflows" / "ci.engine.yml",
        ROOT / "tools" / "ci" / "container_smoke.py",
    ):
        versions.update(re.findall(r"postgres:(\d+)", path.read_text()))
    assert len(versions) == 1, f"PostgreSQL major versions disagree: {sorted(versions)}"


def test_the_compliance_override_is_ignored_by_git():
    """Its .example instructs operators to fill it with certificate host paths.

    The SharePoint twin was ignored; Phase 8 added this overlay and its example
    but not the rule, so the file git would happily stage was the one holding
    real paths.
    """
    ignored = (ROOT / ".gitignore").read_text()
    assert "docker-compose.compliance.override.yml" in ignored


def test_infrastructure_has_an_explicit_review_boundary():
    """The plan says 'reviewed IaC'; a catch-all owner is the default, not a boundary."""
    codeowners = (ROOT / ".github" / "CODEOWNERS").read_text()
    for path in ("/infrastructure/", "/tools/ops/", "/docker-compose.production.yml"):
        assert path in codeowners, path
