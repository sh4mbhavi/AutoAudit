#!/usr/bin/env python3
"""Exercise production Redis TLS/auth/retention with disposable synthetic material."""

import hashlib
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=60)


def main():
    import redis

    name = "autoaudit-phase5-tls-" + uuid.uuid4().hex[:12]
    with tempfile.TemporaryDirectory(prefix="autoaudit-tls-") as directory:
        path = Path(directory)
        password = secrets.token_hex(32)
        run(
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(path / "key"),
            "-out",
            str(path / "cert"),
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost,IP:127.0.0.1",
        )
        (path / "acl").write_text(
            "user default off\nuser worker on #"
            + hashlib.sha256(password.encode()).hexdigest()
            + " ~* &* +@all\n"
        )
        # Mount synthetic disposable keys readable by the container's non-root Redis user.
        os.chmod(path / "key", 0o644)
        config = (ROOT / "infrastructure/runtime/redis.conf").read_text()
        for old, new in [
            ("redis_cert", "cert"),
            ("redis_key", "key"),
            ("runtime_ca", "cert"),
            ("redis_acl", "acl"),
        ]:
            config = config.replace("/run/secrets/" + old, "/synthetic/" + new)
        (path / "redis.conf").write_text(config)
        try:
            run(
                "docker",
                "run",
                "-d",
                "--name",
                name,
                "-p",
                "127.0.0.1::6379",
                "--mount",
                f"type=bind,src={directory},dst=/synthetic,readonly",
                "--tmpfs",
                "/data",
                "redis:7-alpine",
                "redis-server",
                "/synthetic/redis.conf",
            )
            port = int(
                run("docker", "port", name, "6379/tcp").stdout.strip().rsplit(":", 1)[1]
            )
            options = dict(
                host="127.0.0.1",
                port=port,
                username="worker",
                password=password,
                ssl=True,
                ssl_ca_certs=str(path / "cert"),
                ssl_cert_reqs="required",
                socket_connect_timeout=2,
                socket_timeout=2,
            )
            client = redis.Redis(**options)
            deadline = time.monotonic() + 20
            while True:
                try:
                    assert client.ping()
                    break
                except redis.ConnectionError:
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(0.25)
            for overrides in [
                dict(password="invalid"),  # pragma: allowlist secret
                dict(username=None, password=None),
                dict(ssl_ca_certs=None),
            ]:
                rejected = redis.Redis(**{**options, **overrides})
                try:
                    rejected.ping()
                except (redis.ConnectionError, redis.AuthenticationError):
                    pass
                else:
                    raise AssertionError("Unsafe Redis connection accepted")
                finally:
                    rejected.close()
            plain = redis.Redis(host="127.0.0.1", port=port, socket_timeout=2)
            try:
                plain.ping()
            except redis.ConnectionError:
                pass
            else:
                raise AssertionError("Plaintext Redis connection accepted")
            finally:
                plain.close()
            assert client.config_get("save")["save"] == ""
            assert client.config_get("appendonly")["appendonly"] == "no"
            client.close()
            print(
                "PASS: Redis verified TLS/auth; anonymous, wrong-password, untrusted-CA and plaintext connections rejected; persistence disabled"
            )
        finally:
            subprocess.run(
                ["docker", "rm", "-fv", name], capture_output=True, timeout=30
            )


if __name__ == "__main__":
    main()
