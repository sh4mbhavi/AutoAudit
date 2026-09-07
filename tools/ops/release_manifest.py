"""Produce a release manifest: what a build is made of, and from what source.

Before Phase 10 there was no way to answer "which build is in production". The
repository has no git tags, no CHANGELOG, no ``__version__``, no ``/version``
endpoint, and every ``pyproject.toml`` and ``package.json`` still carries the
literal ``0.1.0`` it was created with. The single exception is
``ENGINE_GIT_SHA``, which the worker image demands at build time and writes into
every scan's provenance record -- but that is worker-only, and reading it
requires having run a scan.

This tool generalises that one good idea. It records, for a given source
revision:

* the source revision itself, and whether the tree was clean when it was taken;
* the SHA-256 of every lockfile, which is what actually determines the
  dependency set an image contains;
* the SHA-256 of the policy corpus and the SOC 2 mapping, because a scan's
  result depends on those exactly as much as on the code;
* the digest of each built image, when the images have been built.

**What this is not.** It is not a supply-chain attestation. It is not signed, and
nothing verifies it. Note also that "provenance" in this codebase overwhelmingly
means *scan evidence* provenance -- the record proving which policy digest
evaluated which input digest -- which is a completed, separate concern. Build
provenance in the SLSA sense (a signed statement by the builder about what it
built) does not exist here and is named as a gap in the Phase 10 handoff rather
than implied by this file.

Usage:
    python tools/ops/release_manifest.py                    # source only
    python tools/ops/release_manifest.py --image worker=autoaudit-worker:abc123
    python tools/ops/release_manifest.py --output release.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess  # nosec B404 # controlled git/docker invocations
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# Every input whose change would change what a build does. A lockfile determines
# the dependency set; the policy corpus and mapping determine what a scan
# concludes. All three belong in the same manifest.
TRACKED_FILES = {
    "backend-api/uv.lock": "python dependency set for the API image",
    "engine/uv.lock": "python dependency set for the worker image",
    "frontend/package-lock.json": "javascript dependency set for the frontend image",
}

TRACKED_TREES = {
    "engine/policies": "the Rego corpus a scan evaluates",
    "engine/mappings": "the SOC 2 crosswalk a report renders from",
}


def _git(*arguments: str) -> str | None:
    if shutil.which("git") is None:
        return None
    result = subprocess.run(  # nosec B603 B607 # fixed git arguments
        ["git", *arguments],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tree_digest(root: Path) -> tuple[str, int]:
    """A digest over a directory's contents, stable across filesystems.

    Paths are hashed alongside contents and the walk is sorted, so a rename is a
    change and the ordering of a directory listing is not.
    """
    digest = hashlib.sha256()
    files = sorted(p for p in root.rglob("*") if p.is_file())
    for path in files:
        digest.update(str(path.relative_to(root)).encode())
        digest.update(b"\0")
        digest.update(file_digest(path).encode())
        digest.update(b"\0")
    return digest.hexdigest(), len(files)


def image_digest(reference: str) -> str | None:
    if shutil.which("docker") is None:
        return None
    result = subprocess.run(  # nosec B603 B607 # fixed docker arguments
        ["docker", "image", "inspect", "--format", "{{.Id}}", reference],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    return result.stdout.strip() or None if result.returncode == 0 else None


def build(images: dict[str, str], *, generated_at: str | None = None) -> dict:
    revision = _git("rev-parse", "HEAD")
    status = _git("status", "--porcelain")

    manifest: dict = {
        "schema": "autoaudit.release-manifest/v1",
        "source": {
            "revision": revision,
            # A manifest taken from a dirty tree does not describe a
            # reproducible build, and saying so is the whole value of recording it.
            "tree_clean": (status == "") if status is not None else None,
            "note": (
                "ENGINE_GIT_SHA must equal this revision for the worker image's "
                "scan provenance to name the source it was built from."
            ),
        },
        "generated_at": generated_at,
        "lockfiles": {},
        "trees": {},
        "images": {},
    }

    for relative, description in sorted(TRACKED_FILES.items()):
        path = ROOT / relative
        manifest["lockfiles"][relative] = {
            "sha256": file_digest(path) if path.exists() else None,
            "description": description,
        }

    for relative, description in sorted(TRACKED_TREES.items()):
        path = ROOT / relative
        if path.is_dir():
            digest, count = tree_digest(path)
        else:
            digest, count = None, 0
        manifest["trees"][relative] = {
            "sha256": digest,
            "file_count": count,
            "description": description,
        }

    for name, reference in sorted(images.items()):
        manifest["images"][name] = {
            "reference": reference,
            "id": image_digest(reference),
        }

    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--image",
        action="append",
        default=[],
        metavar="NAME=REFERENCE",
        help="record the digest of a built image, e.g. worker=autoaudit-worker:abc",
    )
    parser.add_argument("--output", type=Path, help="write JSON here instead of stdout")
    parser.add_argument(
        "--generated-at",
        help="ISO timestamp to record; supplied by the caller so the manifest is reproducible",
    )
    args = parser.parse_args(argv)

    images = {}
    for entry in args.image:
        if "=" not in entry:
            print(f"--image expects NAME=REFERENCE, got {entry!r}", file=sys.stderr)
            return 2
        name, reference = entry.split("=", 1)
        images[name] = reference

    manifest = build(images, generated_at=args.generated_at)
    payload = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(payload)
        print(f"Wrote {args.output}")
    else:
        sys.stdout.write(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
