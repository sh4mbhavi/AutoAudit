#!/usr/bin/env python3
"""Install the reviewed OPA release, verifying a source-controlled SHA-256."""

import hashlib
import os
import platform
import sys
import tempfile
import urllib.request
from pathlib import Path

VERSION = "1.20.2"
# Official v1.20.2 GitHub release asset digests, reviewed 2026-09-05.
ASSETS = {
    ("Linux", "x86_64"): (
        "opa_linux_amd64_static",
        "69da5179ee403d10fa11bab6cfb4ffb0d23dba5f9b682fa977db772a1da5670f",  # pragma: allowlist secret - public release checksum
    ),
    ("Linux", "aarch64"): (
        "opa_linux_arm64_static",
        "431bed5a365578241ab06c7cc1c7d0cdff8c11dcbc6f12c3488590deb8b8d66d",  # pragma: allowlist secret - public release checksum
    ),
    ("Darwin", "arm64"): (
        "opa_darwin_arm64",
        "54e7008e696d39e8e4f96594e2b71bcbe45fd9a4f838102bcf1240638bf3fbe1",  # pragma: allowlist secret - public release checksum
    ),
}


def install(destination: Path) -> None:
    asset, digest = ASSETS[(platform.system(), platform.machine())]
    url = (
        f"https://github.com/open-policy-agent/opa/releases/download/v{VERSION}/{asset}"
    )
    with urllib.request.urlopen(url, timeout=120) as response:
        data = response.read()
    if hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("OPA checksum mismatch; refusing to install")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=destination.parent, delete=False) as output:
        temporary = Path(output.name)
        output.write(data)
    try:
        temporary.chmod(0o755)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


if __name__ == "__main__":
    install(Path(sys.argv[1]).resolve())
