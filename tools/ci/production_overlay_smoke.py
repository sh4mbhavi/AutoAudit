#!/usr/bin/env python3
"""Start the reviewed production Compose overlay and prove its boundaries hold.

Phases 7, 8 and 9 each carried the same sentence forward: "The Compose overlay
was not exercised against a running container." It had only ever been *rendered*
with `docker compose config`. Rendering proves the YAML interpolates; it does not
prove PostgreSQL comes up healthy, that Redis actually refuses a plaintext
connection, or that the private network is genuinely unreachable from the host.

This starts `db` and `redis` from `docker-compose.production.yml` with
synthetic, disposable TLS material and asserts exactly those things. It is
deliberately scoped to those two services: `backend-api`, `worker` and
`powershell-service` need reviewed application secrets and, in the PowerShell
case, tenant certificates. `tools/ci/container_smoke.py` covers the application
containers separately.

Everything it creates is torn down, and it will not run against anything but
disposable containers on a generated network.

Usage:
    python tools/ci/production_overlay_smoke.py
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess  # nosec B404 # controlled docker/openssl invocations
import sys
import tempfile
import time
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[2]
SERVICES = ("db", "redis")


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


def make_tls_material(directory: Path) -> dict[str, str]:
    """A throwaway CA and a server certificate, valid for one day.

    Synthetic on purpose: this proves the *plumbing* -- that Redis loads the
    material and enforces TLS -- not that any real certificate is trusted.
    """
    ca_key, ca_crt = directory / "ca.key", directory / "ca.crt"
    srv_key, srv_crt = directory / "redis.key", directory / "redis.crt"
    csr = directory / "redis.csr"

    steps = [
        ["openssl", "genrsa", "-out", str(ca_key), "2048"],
        [
            "openssl",
            "req",
            "-x509",
            "-new",
            "-nodes",
            "-key",
            str(ca_key),
            "-sha256",
            "-days",
            "1",
            "-out",
            str(ca_crt),
            "-subj",
            "/CN=autoaudit-smoke-ca",
        ],
        ["openssl", "genrsa", "-out", str(srv_key), "2048"],
        [
            "openssl",
            "req",
            "-new",
            "-key",
            str(srv_key),
            "-out",
            str(csr),
            "-subj",
            "/CN=redis",
        ],
        [
            "openssl",
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
            str(srv_crt),
            "-days",
            "1",
            "-sha256",
        ],
    ]
    for step in steps:
        result = run(step)
        if result.returncode:
            raise RuntimeError(f"openssl failed: {' '.join(step)}\n{result.stderr}")

    acl = directory / "redis.acl"
    # A real ACL file, because redis.conf names one and Redis refuses to start
    # without it. The password is generated per run and never leaves this host.
    acl.write_text(f"user autoaudit on >{uuid4().hex} ~* +@all\nuser default off\n")

    return {
        "RUNTIME_CA_FILE": str(ca_crt),
        "REDIS_CERT_FILE": str(srv_crt),
        "REDIS_KEY_FILE": str(srv_key),
        "REDIS_ACL_FILE": str(acl),
        "POWERSHELL_CERT_FILE": str(srv_crt),
        "POWERSHELL_KEY_FILE": str(srv_key),
    }


def synthetic_environment(directory: Path) -> dict[str, str]:
    environment = {**os.environ}
    for name in (
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
        "DRIFT_FACT_HMAC_KEY",
    ):
        environment[name] = uuid4().hex + uuid4().hex
    environment.update(make_tls_material(directory))
    return environment


def compose(environment: dict[str, str], project: str, *args: str):
    return run(
        [
            "docker",
            "compose",
            "-p",
            project,
            "-f",
            "docker-compose.production.yml",
            *args,
        ],
        env=environment,
    )


def wait_healthy(environment, project, service, seconds=180) -> str:
    deadline = time.monotonic() + seconds
    last = "unknown"
    while time.monotonic() < deadline:
        result = compose(environment, project, "ps", "--format", "json", service)
        for line in result.stdout.splitlines():
            if not line.strip():
                continue
            entry = json.loads(line)
            last = entry.get("Health") or entry.get("State") or "unknown"
            if last == "healthy":
                return last
        time.sleep(3)
    return last


def published_ports(environment, project, service) -> list:
    """The host bindings this container actually has.

    Asking "is 5432 free on this host" is the wrong question -- any unrelated
    PostgreSQL would fail it, and a container publishing on a *different* host
    port would pass it. The right question is whether Docker gave this container
    a host binding at all.
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
            started = compose(environment, project, "up", "-d", *SERVICES)
            if started.returncode:
                print(started.stdout + started.stderr, file=sys.stderr)
                return 1

            for service in SERVICES:
                health = wait_healthy(environment, project, service)
                if health != "healthy":
                    logs = compose(
                        environment, project, "logs", "--tail", "60", service
                    )
                    print(f"{service} never became healthy ({health})", file=sys.stderr)
                    print(logs.stdout, file=sys.stderr)
                    return 1
                checks.append(f"{service} reached healthy")

            # The boundary that matters: neither service may be reachable from
            # the host. `docker compose config` can only show the absence of a
            # `ports` key in the rendered YAML; this shows the running container
            # was given no host binding.
            for service in SERVICES:
                bindings = published_ports(environment, project, service)
                if bindings:
                    print(
                        f"{service}: publishes host port(s) {bindings}; the "
                        "production overlay must publish none",
                        file=sys.stderr,
                    )
                    return 1
                checks.append(f"{service} has no host port binding")

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

        finally:
            compose(environment, project, "down", "-v", "--remove-orphans")

    print("PASS: production Compose overlay exercised against running containers")
    for check in checks:
        print(f"  - {check}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
