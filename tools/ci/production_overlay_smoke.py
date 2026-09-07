#!/usr/bin/env python3
"""Start every service in the reviewed production overlay and check it holds.

Phases 7, 8 and 9 each carried the same sentence forward: "The Compose overlay
was not exercised against a running container." It had only ever been *rendered*
with `docker compose config`. Rendering proves the YAML interpolates; it does
not prove PostgreSQL comes up healthy, that Redis actually refuses a plaintext
connection, or that the private network is genuinely unreachable from the host.

Phase 10 started `db` and `redis`. That scope had a reason -- the application
services need real secrets, and the PowerShell service needs a certificate
issued for its own hostname -- but it left the four services that actually run a
scan unstarted, and Phase 11 found out what was hiding there: the PowerShell
service could not import its own entrypoint on the Python its image ships, so it
crash-looped, and because the worker declares
`depends_on: powershell-service: {condition: service_healthy}` the worker never
started either. Four of six healthy, `/readiness` answering 200, and the
production topology unable to run a single scan.

So this starts all six. Secrets are needed to *boot*, not tenant credentials to
*scan*, and every one of them can be synthesised per run: a CA, per-host server
certificates carrying the right SAN, a Redis ACL whose password the client
knows, a real Fernet key, and a well-formed 40-hex engine revision. The values
must be genuinely valid rather than merely present -- `backend-api` and the two
engine services run their configuration validators at import, so a placeholder
fails as loudly as a missing value, just less informatively.

Everything it creates is torn down, and it will not run against anything but
disposable containers on a generated network.

Usage:
    python tools/ci/production_overlay_smoke.py

If the host already has something on 127.0.0.1:8000 -- the one host port the
overlay publishes -- point AUTOAUDIT_OVERLAY_EXTRA_FILE at a Compose overlay
that remaps it. The published *container* port is asserted either way, so a
remap cannot mask a service that publishes a port it should not.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import shutil
import subprocess  # nosec B404 # controlled docker/openssl invocations
import sys
import tempfile
import time
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[2]

# Ordered so that a failure is reported against the first service that broke
# rather than against everything downstream of it.
SERVICES = (
    "db",
    "redis",
    "powershell-service",
    "backend-api",
    "worker",
    "dispatcher",
)

# The overlay publishes exactly one host port, on the loopback interface, for a
# local TLS ingress proxy to connect to. Everything else must be reachable only
# from the private network.
EXPECTED_CONTAINER_PORTS = {"backend-api": ["8000/tcp"]}

# The PowerShell image installs three PowerShell modules from the gallery and
# the engine image compiles wheels, so the first build on a cold cache is long.
BUILD_TIMEOUT_SECONDS = 3600
HEALTH_TIMEOUT_SECONDS = 600

# A 40-hex revision, because engine/Dockerfile refuses to build without one that
# matches `[0-9a-f]{40}`. Synthetic: this proves the build accepts a well-formed
# revision, not that any particular commit was built.
SYNTHETIC_ENGINE_SHA = "0" * 39 + "1"


def run(command: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(  # nosec B603 # fixed argv, no shell
        command,
        cwd=kwargs.pop("cwd", ROOT),
        text=True,
        capture_output=True,
        timeout=kwargs.pop("timeout", 900),
        check=False,
        **kwargs,
    )


def openssl(*args: str) -> None:
    result = run(["openssl", *args])
    if result.returncode:
        raise RuntimeError(f"openssl {' '.join(args)} failed:\n{result.stderr}")


def make_tls_material(directory: Path, redis_password: str) -> dict[str, str]:
    """A throwaway CA and one server certificate per TLS-terminating host.

    Synthetic on purpose: this proves the *plumbing* -- that Redis loads the
    material and enforces TLS, and that the PowerShell service serves HTTPS --
    not that any real certificate is trusted.

    Each certificate carries a subjectAltName for the service's Compose name.
    The overlay's PowerShell healthcheck probes `https://powershell-service:8001`
    rather than localhost precisely because hostname verification is on, so a
    certificate without that SAN leaves the container permanently unhealthy and
    the worker, which waits on it, never starts.
    """
    ca_key, ca_crt = directory / "ca.key", directory / "ca.crt"
    openssl(
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        str(ca_key),
        "-out",
        str(ca_crt),
        "-days",
        "1",
        "-subj",
        "/CN=autoaudit-smoke-ca",
        "-sha256",
    )

    issued: dict[str, tuple[str, str]] = {}
    for host in ("redis", "powershell-service"):
        key, crt = directory / f"{host}.key", directory / f"{host}.crt"
        csr, ext = directory / f"{host}.csr", directory / f"{host}.ext"
        ext.write_text(f"subjectAltName=DNS:{host}\nextendedKeyUsage=serverAuth\n")
        openssl(
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(csr),
            "-subj",
            f"/CN={host}",
            "-sha256",
        )
        openssl(
            "x509",
            "-req",
            "-in",
            str(csr),
            "-CA",
            str(ca_crt),
            "-CAkey",
            str(ca_key),
            "-CAcreateserial",
            "-out",
            str(crt),
            "-days",
            "1",
            "-sha256",
            "-extfile",
            str(ext),
        )
        issued[host] = (str(crt), str(key))

    # A real ACL file, because redis.conf names one and Redis refuses to start
    # without it. Unlike Phase 10's version this uses the password the client is
    # about to be given, so the broker is genuinely usable by the API, the
    # worker and the dispatcher rather than merely listening.
    # `&*` is not decoration. Redis 7 starts every user with `resetchannels`,
    # so `~* +@all` grants every key and every command and still denies pub/sub.
    # Celery's mingle step opens a pidbox channel as the worker boots, and
    # without channel permissions the worker dies at startup with
    # `kombu.exceptions.OperationalError: No permissions to access a channel`,
    # which names neither Redis nor the ACL. This bit the Phase 11 harness.
    acl = directory / "redis.acl"
    acl.write_text(
        f"user autoaudit on >{redis_password} ~* &* +@all\nuser default off\n"
    )

    return {
        "RUNTIME_CA_FILE": str(ca_crt),
        "REDIS_CERT_FILE": issued["redis"][0],
        "REDIS_KEY_FILE": issued["redis"][1],
        "REDIS_ACL_FILE": str(acl),
        "POWERSHELL_CERT_FILE": issued["powershell-service"][0],
        "POWERSHELL_KEY_FILE": issued["powershell-service"][1],
    }


def _password() -> str:
    """A password the runtime validators accept.

    `Settings.validate_runtime_security` requires at least 32 characters and
    rejects anything containing "change", "example", "password", "autoaudit_dev",
    "your-" or "dev-secret". It also has to survive being embedded in a URL, so
    the URL-unsafe characters token_urlsafe can emit are folded away.
    """
    return secrets.token_urlsafe(36).replace("-", "x").replace("_", "y")


def synthetic_environment(directory: Path) -> dict[str, str]:
    postgres_password = _password()
    redis_password = _password()
    environment = {**os.environ}
    environment.update(
        {
            "POSTGRES_PASSWORD": postgres_password,
            "API_DATABASE_URL": (
                f"postgresql+asyncpg://autoaudit:{postgres_password}@db:5432/autoaudit"
            ),
            "WORKER_DATABASE_URL": (
                f"postgresql://autoaudit:{postgres_password}@db:5432/autoaudit"
            ),
            # rediss with verification and hostname checking both required: the
            # validator rejects plaintext, and it rejects a URL that turns either
            # check off.
            "REDIS_URL": (
                f"rediss://autoaudit:{redis_password}@redis:6379/0"
                "?ssl_cert_reqs=required&ssl_check_hostname=true"
                "&ssl_ca_certs=/run/secrets/runtime_ca"
            ),
            "SECRET_KEY": secrets.token_urlsafe(48),
            # A real Fernet key. The API constructs Fernet(ENCRYPTION_KEY) during
            # validation, so 32 random characters would not do.
            "ENCRYPTION_KEY": base64.urlsafe_b64encode(
                secrets.token_bytes(32)
            ).decode(),
            "ENCRYPTION_KEY_DECRYPT_ONLY": "",
            "POWERSHELL_SERVICE_SECRET": secrets.token_urlsafe(32),
            "DRIFT_FACT_HMAC_KEY": secrets.token_urlsafe(32),
            "BACKEND_PUBLIC_URL": "https://api.smoke.invalid",
            "FRONTEND_URL": "https://app.smoke.invalid",
            "ENGINE_GIT_SHA": SYNTHETIC_ENGINE_SHA,
            "DISPATCHER_METRICS_PORT": "9101",
        }
    )
    environment.update(make_tls_material(directory, redis_password))
    return environment


def _compose_files() -> list[str]:
    files = ["-f", "docker-compose.production.yml"]
    extra = os.environ.get("AUTOAUDIT_OVERLAY_EXTRA_FILE")
    if extra:
        files += ["-f", extra]
    return files


def compose(environment: dict[str, str], project: str, *args: str, **kwargs):
    return run(
        ["docker", "compose", "-p", project, *_compose_files(), *args],
        env=environment,
        **kwargs,
    )


def wait_healthy(environment, project, service, seconds=HEALTH_TIMEOUT_SECONDS) -> str:
    deadline = time.monotonic() + seconds
    last = "unknown"
    restarting = 0
    while time.monotonic() < deadline:
        result = compose(environment, project, "ps", "--format", "json", service)
        for line in result.stdout.splitlines():
            if not line.strip():
                continue
            entry = json.loads(line)
            last = entry.get("Health") or entry.get("State") or "unknown"
            if last == "healthy":
                return last
            # A service that has exited is not going to become healthy. Neither
            # is one Docker keeps restarting: `restart: unless-stopped` turns a
            # crash into an indefinite loop, and waiting out the timeout only
            # delays the logs. Two consecutive observations, because a container
            # is briefly "restarting" on its way up as well.
            if last in {"exited", "dead"}:
                return last
            if last == "restarting":
                restarting += 1
                if restarting >= 2:
                    return "restarting (crash loop)"
            else:
                restarting = 0
        time.sleep(3)
    return last


def published_ports(environment, project, service) -> list:
    """The container ports this container has a host binding for.

    Asking "is 8000 free on this host" is the wrong question -- any unrelated
    process would fail it, and a container publishing on a *different* host port
    would pass it. The right question is which of the container's own ports
    Docker gave a host binding to at all, which is also why remapping the host
    side for a local run cannot weaken this check.
    """
    container = compose(environment, project, "ps", "-q", service).stdout.strip()
    if not container:
        raise RuntimeError(f"{service} has no container")
    inspected = run(
        [
            "docker",
            "inspect",
            container,
            "--format",
            "{{json .HostConfig.PortBindings}}",
        ]
    )
    bindings = json.loads(inspected.stdout or "null") or {}
    return sorted(bindings)


def _dump(environment, project, service, stream=sys.stderr) -> None:
    logs = compose(environment, project, "logs", "--tail", "80", service)
    print(f"--- {service} logs ---\n{logs.stdout[-8000:]}", file=stream)


def main() -> int:
    if shutil.which("docker") is None or shutil.which("openssl") is None:
        print("docker and openssl are required", file=sys.stderr)
        return 2
    if run(["docker", "info"]).returncode:
        print("docker daemon unavailable", file=sys.stderr)
        return 2

    project = "autoaudit-overlay-smoke-" + uuid4().hex[:10]
    checks: list[str] = []

    with tempfile.TemporaryDirectory(prefix="autoaudit-overlay-") as raw:
        directory = Path(raw)
        environment = synthetic_environment(directory)
        try:
            started = compose(
                environment,
                project,
                "up",
                "-d",
                "--build",
                *SERVICES,
                timeout=BUILD_TIMEOUT_SECONDS,
            )
            if started.returncode:
                print(started.stdout + started.stderr, file=sys.stderr)
                return 1

            for service in SERVICES:
                health = wait_healthy(environment, project, service)
                if health != "healthy":
                    print(f"{service} never became healthy ({health})", file=sys.stderr)
                    _dump(environment, project, service)
                    return 1
                checks.append(f"{service} reached healthy")

            # The boundary that matters: only backend-api may be reachable from
            # the host, and only on the port the overlay documents. `docker
            # compose config` can only show the presence or absence of a `ports`
            # key in the rendered YAML; this shows what the running containers
            # were actually given.
            for service in SERVICES:
                bindings = published_ports(environment, project, service)
                expected = EXPECTED_CONTAINER_PORTS.get(service, [])
                if bindings != expected:
                    print(
                        f"{service}: host bindings for {bindings or 'none'}, "
                        f"expected {expected or 'none'}",
                        file=sys.stderr,
                    )
                    return 1
                checks.append(f"{service} publishes {bindings or 'no host port'}")

            # Redis must refuse plaintext. redis.conf sets `port 0` and
            # `tls-port 6379`, and a rendered config cannot prove the running
            # server honours it.
            #
            # The ACL disables the default user, so the protocol-level answer
            # over TLS is "-NOAUTH Authentication required". That is the correct
            # success signal here: it proves the TLS handshake completed and the
            # server processed a command. A plaintext attempt never gets that far.
            plaintext = compose(
                environment,
                project,
                "exec",
                "-T",
                "redis",
                "redis-cli",
                "-h",
                "127.0.0.1",
                "-p",
                "6379",
                "ping",
            )
            answered = (plaintext.stdout + plaintext.stderr).upper()
            if "PONG" in answered or "NOAUTH" in answered:
                print(
                    "redis answered a plaintext PING; TLS is not enforced",
                    file=sys.stderr,
                )
                return 1
            checks.append("redis refuses a plaintext connection")

            over_tls = compose(
                environment,
                project,
                "exec",
                "-T",
                "redis",
                "redis-cli",
                "--tls",
                "--cacert",
                "/run/secrets/runtime_ca",
                "-h",
                "127.0.0.1",
                "-p",
                "6379",
                "ping",
            )
            answered = (over_tls.stdout + over_tls.stderr).upper()
            if "PONG" not in answered and "NOAUTH" not in answered:
                print(
                    f"redis did not answer over TLS: {over_tls.stdout}{over_tls.stderr}",
                    file=sys.stderr,
                )
                return 1
            checks.append("redis completes a TLS handshake and enforces its ACL")

            # PostgreSQL genuinely accepts connections, from inside the network.
            ready = compose(
                environment,
                project,
                "exec",
                "-T",
                "db",
                "psql",
                "-U",
                "autoaudit",
                "-d",
                "autoaudit",
                "-tAc",
                "SELECT 1",
            )
            if ready.stdout.strip() != "1":
                print(
                    f"postgres did not answer: {ready.stdout}{ready.stderr}",
                    file=sys.stderr,
                )
                return 1
            checks.append("postgres accepts connections on the private network")

            # The API's own readiness endpoint, which is what its healthcheck
            # probes and what an ingress proxy would poll. Reported here so a
            # future failure names the failing dependency instead of only
            # "unhealthy".
            readiness = compose(
                environment,
                project,
                "exec",
                "-T",
                "backend-api",
                "curl",
                "-fsS",
                "http://localhost:8000/readiness",
            )
            if readiness.returncode:
                print(
                    f"/readiness failed: {readiness.stdout}{readiness.stderr}",
                    file=sys.stderr,
                )
                return 1
            checks.append(f"backend-api /readiness -> {readiness.stdout.strip()}")

            # The worker answering a Celery ping is the whole point of starting
            # all six. It only gets to run at all once powershell-service is
            # healthy, so this is the assertion that a service which cannot
            # import its own entrypoint can no longer pass unnoticed.
            pinged = compose(
                environment,
                project,
                "exec",
                "-T",
                "worker",
                "celery",
                "-A",
                "worker.celery_app",
                "inspect",
                "ping",
            )
            if "pong" not in (pinged.stdout + pinged.stderr).lower():
                print(
                    f"worker did not answer a celery ping: "
                    f"{pinged.stdout}{pinged.stderr}",
                    file=sys.stderr,
                )
                return 1
            checks.append("worker answers a celery ping over the TLS broker")

        finally:
            compose(environment, project, "down", "-v", "--remove-orphans")

    print("PASS: production Compose overlay exercised against running containers")
    for check in checks:
        print(f"  - {check}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
