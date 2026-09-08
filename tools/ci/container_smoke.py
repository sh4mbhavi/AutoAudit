#!/usr/bin/env python3
"""Build and start API/worker against disposable containers; never tenant services."""

import argparse
import os
import subprocess
import time
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[2]


def docker(*args, check=True):
    result = subprocess.run(
        ["docker", *args],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=1800,
    )
    if check and result.returncode:
        raise RuntimeError(f"Docker {args[0]} failed:\n{result.stdout}")
    return result


def wait_for(probe, description):
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        if probe():
            return
        time.sleep(2)
    raise RuntimeError(f"Timed out waiting for {description}")


def main(skip_build=False):
    suffix = uuid4().hex[:12]
    network = "autoaudit-ci-" + suffix
    names = {
        kind: f"{network}-{kind}" for kind in ("postgres", "redis", "api", "worker")
    }
    images = {kind: f"autoaudit-phase4-{kind}:smoke" for kind in ("api", "worker")}
    if not skip_build:
        sha = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip()
        docker(
            "build",
            "--build-arg",
            f"ENGINE_GIT_SHA={sha}",
            "-t",
            images["worker"],
            "engine",
        )
        print("Worker image built", flush=True)
        docker("build", "-f", "backend-api/Dockerfile", "-t", images["api"], ".")
        print("API image built", flush=True)
    docker("network", "create", "--internal", network)
    try:
        docker(
            "run",
            "-d",
            "--name",
            names["postgres"],
            "--network",
            network,
            "-e",
            "POSTGRES_HOST_AUTH_METHOD=trust",
            "-e",
            "POSTGRES_DB=autoaudit",
            "postgres:16",
        )
        docker(
            "run",
            "-d",
            "--name",
            names["redis"],
            "--network",
            network,
            "redis:7-alpine",
        )
        wait_for(
            lambda: docker(
                "exec", names["postgres"], "pg_isready", "-U", "postgres", check=False
            ).returncode
            == 0,
            "PostgreSQL",
        )
        # Runtime generated secrets are passed via environment names, never command values.
        import base64

        os.environ["ENCRYPTION_KEY"] = base64.urlsafe_b64encode(os.urandom(32)).decode()
        os.environ["SECRET_KEY"] = uuid4().hex + uuid4().hex
        common = [
            "--network",
            network,
            "-e",
            "APP_ENV=dev",
            "-e",
            "ENCRYPTION_KEY",
            "-e",
            "SECRET_KEY",
            "-e",
            f"REDIS_URL=redis://{names['redis']}:6379/0",
        ]
        database = f"postgresql://postgres@{names['postgres']}:5432/autoaudit"
        docker(
            "run",
            "-d",
            "--name",
            names["api"],
            *common,
            "-e",
            "DATABASE_URL="
            + database.replace("postgresql://", "postgresql+asyncpg://"),
            images["api"],
        )

        # Probe inside the isolated network; no published ports or external credentials.
        def healthy():
            probe = docker(
                "exec",
                names["api"],
                "/app/.venv/bin/python",
                "-c",
                "import json,urllib.request; assert json.load(urllib.request.urlopen('http://127.0.0.1:8000/liveness'))['status']=='healthy'",
                check=False,
            )
            return probe.returncode == 0

        wait_for(healthy, "API entrypoint, migrations and liveness")
        docker(
            "run",
            "-d",
            "--name",
            names["worker"],
            *common,
            "-e",
            "DATABASE_URL=" + database,
            images["worker"],
        )

        def ready():
            probe = docker(
                "exec",
                names["worker"],
                "celery",
                "-A",
                "worker.celery_app",
                "inspect",
                "ping",
                "--timeout=2",
                check=False,
            )
            return probe.returncode == 0 and "pong" in probe.stdout

        wait_for(ready, "worker entrypoint and broker registration")
        print("PASS: API migration/startup/liveness and Celery worker ping", flush=True)
    except Exception:
        for kind in ("api", "worker"):
            print(docker("logs", names[kind], check=False).stdout[-8000:])
        raise
    finally:
        for name in reversed(list(names.values())):
            docker("rm", "-fv", name, check=False)
        docker("network", "rm", network, check=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--skip-build",
        action="store_true",
        help="Use images already built by this script",
    )
    main(parser.parse_args().skip_build)
