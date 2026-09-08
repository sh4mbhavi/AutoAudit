"""Install a checksum-verified ``promtool``.

``ci.validate-alerts.yml`` installed promtool with ``apt-get install -y
prometheus``: an unpinned Ubuntu package, whose version changes without notice
and whose contents nothing verifies. Meanwhile ``tools/ci/install_opa.py`` --
written in Phase 4 for exactly the same job -- pins a version and refuses to
install on a digest mismatch. This closes that inconsistency; the two files are
deliberately the same shape.

Usage:
    python tools/ci/install_promtool.py /usr/local/bin/promtool
"""

from __future__ import annotations

import hashlib
import io
import stat
import sys
import tarfile
import urllib.request
from pathlib import Path

VERSION = "3.7.3"
# Official v3.7.3 GitHub release archive digests, taken from the release's own
# sha256sums.txt and reviewed 2026-09-07.
ARCHIVES = {
    ("Linux", "x86_64"): (
        "prometheus-3.7.3.linux-amd64.tar.gz",
        "fc9e5da126817438cf2820d9a7206c75e3122802ba8d20add3a6219a59ca6913",  # pragma: allowlist secret - public release checksum
    ),
    ("Linux", "aarch64"): (
        "prometheus-3.7.3.linux-arm64.tar.gz",
        "6af448fa4f3640eb9bd51ce71575689a1ef79843b1cf08ef1fcc7ff9a1928bfd",  # pragma: allowlist secret - public release checksum
    ),
    ("Darwin", "arm64"): (
        "prometheus-3.7.3.darwin-arm64.tar.gz",
        "322025a09dce52c8599a0e1c9fe712221de87b1d9673664f7ba4e56ef200fe15",  # pragma: allowlist secret - public release checksum
    ),
}


def main(argv: list[str]) -> int:
    import platform

    if len(argv) != 2:
        print(f"usage: {argv[0]} <destination>", file=sys.stderr)
        return 2
    destination = Path(argv[1])

    key = (platform.system(), platform.machine())
    if key not in ARCHIVES:
        print(f"No reviewed promtool archive for {key}", file=sys.stderr)
        return 2
    archive, digest = ARCHIVES[key]

    url = (
        "https://github.com/prometheus/prometheus/releases/download/"
        f"v{VERSION}/{archive}"
    )
    with urllib.request.urlopen(url) as response:  # nosec B310 # fixed https release URL
        payload = response.read()

    if hashlib.sha256(payload).hexdigest() != digest:
        print("promtool checksum mismatch; refusing to install", file=sys.stderr)
        return 1

    # Extract exactly one member, by name, after the whole archive has been
    # verified. Never extractall: a tar member can name a path outside the
    # destination, and the digest check proves the archive is the reviewed one,
    # not that unpacking it is safe in general.
    member_name = f"{archive.removesuffix('.tar.gz')}/promtool"
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as bundle:
        member = bundle.getmember(member_name)
        extracted = bundle.extractfile(member)
        if extracted is None:
            print(f"{member_name} is not a file in the archive", file=sys.stderr)
            return 1
        destination.write_bytes(extracted.read())

    destination.chmod(
        destination.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH
    )
    print(f"Installed promtool {VERSION} at {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
