#!/usr/bin/env python3
"""Phase 11: start EVERY service in the reviewed production overlay.

tools/ci/production_overlay_smoke.py starts `db` and `redis` only, and says so:
"deliberately scoped to those two services: backend-api, worker and
powershell-service need reviewed application secrets and, in the PowerShell
case, tenant certificates."

Plan item 19.1.5 asks for all production-target images started with
non-development configuration. Tenant certificates are needed to *scan*, not to
*boot*, so this generates a complete set of synthetic material -- a CA, per-host
server certificates with SANs, a Redis ACL whose password is known, a real
Fernet key and a well-formed 40-hex engine revision -- and starts all six.

Verification only. Nothing here is added to the repository's tool surface.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import shutil
import subprocess  # nosec B404
import sys
import tempfile
import time
from pathlib import Path
from uuid import uuid4

ROOT = Path("/Users/clupa/Documents/projects/autoaudit/AutoAudit-phase-11")
SERVICES = ("db", "redis", "powershell-service", "backend-api", "worker", "dispatcher")


def run(cmd, **kw):
    return subprocess.run(  # nosec B603
        cmd, cwd=kw.pop("cwd", ROOT), text=True, capture_output=True,
        timeout=kw.pop("timeout", 1800), check=False, **kw)


def openssl(*args):
    r = run(["openssl", *args])
    if r.returncode:
        raise RuntimeError(f"openssl {' '.join(args)}\n{r.stderr}")
    return r


def material(d: Path, redis_password: str) -> dict[str, str]:
    ca_key, ca_crt = d / "ca.key", d / "ca.crt"
    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(ca_key),
            "-out", str(ca_crt), "-days", "1", "-subj", "/CN=autoaudit-p11-ca", "-sha256")

    out = {}
    for host in ("redis", "powershell-service"):
        key, crt, csr = d / f"{host}.key", d / f"{host}.crt", d / f"{host}.csr"
        ext = d / f"{host}.ext"
        ext.write_text(f"subjectAltName=DNS:{host}\nextendedKeyUsage=serverAuth\n")
        openssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
                "-out", str(csr), "-subj", f"/CN={host}", "-sha256")
        openssl("x509", "-req", "-in", str(csr), "-CA", str(ca_crt), "-CAkey", str(ca_key),
                "-CAcreateserial", "-out", str(crt), "-days", "1", "-sha256",
                "-extfile", str(ext))
        out[host] = (str(crt), str(key))

    acl = d / "redis.acl"
    acl.write_text(f"user autoaudit on >{redis_password} ~* +@all\nuser default off\n")
    return {
        "RUNTIME_CA_FILE": str(ca_crt),
        "REDIS_CERT_FILE": out["redis"][0],
        "REDIS_KEY_FILE": out["redis"][1],
        "REDIS_ACL_FILE": str(acl),
        "POWERSHELL_CERT_FILE": out["powershell-service"][0],
        "POWERSHELL_KEY_FILE": out["powershell-service"][1],
    }


def environment(d: Path) -> dict[str, str]:
    pg = secrets.token_urlsafe(24).replace("-", "x").replace("_", "y")
    rp = secrets.token_urlsafe(24).replace("-", "x").replace("_", "y")
    fernet = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
    env = {**os.environ}
    env.update({
        "POSTGRES_PASSWORD": pg,
        "API_DATABASE_URL": f"postgresql+asyncpg://autoaudit:{pg}@db:5432/autoaudit",
        "WORKER_DATABASE_URL": f"postgresql://autoaudit:{pg}@db:5432/autoaudit",
        "REDIS_URL": (f"rediss://autoaudit:{rp}@redis:6379/0"
                      "?ssl_cert_reqs=required&ssl_check_hostname=true"
                      "&ssl_ca_certs=/run/secrets/runtime_ca"),
        "SECRET_KEY": secrets.token_urlsafe(48),
        "ENCRYPTION_KEY": fernet,
        "ENCRYPTION_KEY_DECRYPT_ONLY": "",
        "POWERSHELL_SERVICE_SECRET": secrets.token_urlsafe(32),
        "DRIFT_FACT_HMAC_KEY": secrets.token_urlsafe(32),
        "BACKEND_PUBLIC_URL": "https://api.p11.invalid",
        "FRONTEND_URL": "https://app.p11.invalid",
        "ENGINE_GIT_SHA": "8736fcb93565dcc1e1a60a06392a879f5a585335",
        "DISPATCHER_METRICS_PORT": "9101",
    })
    env.update(material(d, rp))
    return env


def compose(env, project, *args):
    return run(["docker", "compose", "-f", "docker-compose.production.yml", "-f", os.environ["P11_OVERRIDE"],
                "-p", project, *args], env=env)


def health(env, project, service, seconds=300):
    deadline = time.time() + seconds
    last = "unknown"
    while time.time() < deadline:
        r = compose(env, project, "ps", "--format", "json", service)
        for line in (r.stdout or "").splitlines():
            try:
                row = json.loads(line)
            except ValueError:
                continue
            last = row.get("Health") or row.get("State") or "unknown"
            if last in {"healthy", "exited", "dead"}:
                return last
        time.sleep(5)
    return last


def bindings(env, project, service):
    cid = compose(env, project, "ps", "-q", service).stdout.strip()
    if not cid:
        return []
    r = run(["docker", "inspect", cid, "--format", "{{json .HostConfig.PortBindings}}"])
    return sorted(json.loads(r.stdout or "null") or {})


def main() -> int:
    if shutil.which("docker") is None or shutil.which("openssl") is None:
        print("docker and openssl required", file=sys.stderr)
        return 2
    project = "autoaudit-p11-full-" + uuid4().hex[:10]
    checks, failures = [], []
    with tempfile.TemporaryDirectory(prefix="autoaudit-p11-") as raw:
        d = Path(raw)
        env = environment(d)
        try:
            up = compose(env, project, "up", "-d", "--build", *SERVICES)
            if up.returncode:
                print("compose up failed:\n" + up.stdout + up.stderr, file=sys.stderr)
                failures.append("compose up returned non-zero")
            for service in SERVICES:
                state = health(env, project, service)
                if state == "healthy":
                    checks.append(f"{service}: healthy")
                else:
                    failures.append(f"{service}: {state}")
                    logs = compose(env, project, "logs", "--tail", "40", service)
                    print(f"--- {service} ({state}) ---\n{logs.stdout[-4000:]}", file=sys.stderr)
            for service in SERVICES:
                b = bindings(env, project, service)
                expected = ["8000/tcp"] if service == "backend-api" else []
                if b == expected:
                    checks.append(f"{service}: host bindings {b or 'none'}")
                else:
                    failures.append(f"{service}: unexpected host bindings {b}")
        finally:
            compose(env, project, "down", "-v", "--remove-orphans")
    print("\n".join("  " + c for c in checks))
    if failures:
        print("FAIL:\n" + "\n".join("  " + f for f in failures))
        return 1
    print("PASS: every service in the production overlay started and reported healthy")
    return 0


if __name__ == "__main__":
    sys.exit(main())
