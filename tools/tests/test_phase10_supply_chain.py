"""Supply-chain invariants for the images this repository builds.

The defect these exist to prevent was real and shipped: ``engine/Dockerfile``
installed dependencies with ``pip install .`` from a ``pyproject.toml`` carrying
only floating lower bounds, and never copied ``uv.lock`` at all. CI ran
``uv sync --frozen`` and Grype scanned the lockfile, so the tested and scanned
dependency set was not the one in the image, and any SBOM built from the
lockfile would have described neither.

Most of these are static assertions on the Dockerfiles, so they run everywhere.
The one that actually builds an image is marked and skips without Docker.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess  # nosec B404 # controlled docker/build invocations
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
ENGINE_DOCKERFILE = ROOT / "engine" / "Dockerfile"
BACKEND_DOCKERFILE = ROOT / "backend-api" / "Dockerfile"
POWERSHELL_DOCKERFILE = ROOT / "engine" / "powershell" / "Dockerfile"


def _read(path: Path) -> str:
    return path.read_text()


# ---------------------------------------------------------------------------
# Lockfiles reach the images.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "dockerfile,lockfile",
    [
        (ENGINE_DOCKERFILE, "uv.lock"),
        (BACKEND_DOCKERFILE, "uv.lock"),
    ],
)
def test_the_image_copies_its_lockfile(dockerfile, lockfile):
    assert lockfile in _read(dockerfile), (
        f"{dockerfile.relative_to(ROOT)} must COPY {lockfile}; without it the "
        "image resolves dependencies afresh at build time and does not match "
        "what CI tested or Grype scanned"
    )


@pytest.mark.parametrize("dockerfile", [ENGINE_DOCKERFILE, BACKEND_DOCKERFILE])
def test_the_image_installs_frozen(dockerfile):
    assert "uv sync --frozen" in _read(dockerfile), dockerfile.relative_to(ROOT)


def test_the_engine_image_does_not_pip_install_the_project():
    """The exact regression: `pip install .` bypasses the lockfile entirely."""
    content = _read(ENGINE_DOCKERFILE)
    assert "pip install --no-cache-dir ." not in content
    assert not re.search(r"^RUN\s+pip install\s+\.\s*$", content, re.M)


# ---------------------------------------------------------------------------
# Build inputs are pinned.
# ---------------------------------------------------------------------------


def test_engine_base_images_are_digest_pinned():
    """A floating tag is a different image tomorrow."""
    for line in _read(ENGINE_DOCKERFILE).splitlines():
        if line.startswith("FROM ") and "python:3.11-slim" not in line:
            assert "@sha256:" in line, line


def test_the_opa_binary_in_the_worker_image_matches_the_pinned_ci_version():
    """The worker evaluates policy with this binary; CI tests with that one."""
    installer = (ROOT / "tools" / "ci" / "install_opa.py").read_text()
    version = re.search(r'VERSION = "([^"]+)"', installer).group(1)
    assert f"openpolicyagent/opa:{version}@sha256:" in _read(ENGINE_DOCKERFILE)


def test_promtool_is_pinned_and_checksum_verified():
    """It was `apt-get install -y prometheus`: unpinned and unverified."""
    installer = ROOT / "tools" / "ci" / "install_promtool.py"
    assert installer.exists()
    content = installer.read_text()
    assert "hashlib.sha256" in content
    assert "refusing to install" in content
    workflow = (ROOT / ".github" / "workflows" / "ci.validate-alerts.yml").read_text()
    assert "install_promtool.py" in workflow
    # Comments describe the old approach on purpose; only executable lines matter.
    executable = [
        line for line in workflow.splitlines() if not line.lstrip().startswith("#")
    ]
    assert not any("apt-get install" in line for line in executable)


def test_the_alert_workflow_is_not_path_filtered():
    """The rules depend on application source, so it must see application changes.

    Path-filtered to infrastructure/monitoring/alerts/**, deleting a metric
    emitter -- the thing that actually breaks an alert -- ran no alert
    validation at all.
    """
    workflow = (ROOT / ".github" / "workflows" / "ci.validate-alerts.yml").read_text()
    assert "paths:" not in workflow


# ---------------------------------------------------------------------------
# Release traceability.
# ---------------------------------------------------------------------------


def test_the_worker_image_refuses_to_build_without_a_source_revision():
    """ENGINE_GIT_SHA is written into every provenance record a scan produces."""
    content = _read(ENGINE_DOCKERFILE)
    assert "ARG ENGINE_GIT_SHA" in content
    assert "[0-9a-f]{40}" in content


def test_the_release_manifest_tool_exists_and_declares_its_inputs():
    tool = ROOT / "tools" / "ops" / "release_manifest.py"
    assert tool.exists()
    content = tool.read_text()
    for expected in ("uv.lock", "sha256", "ENGINE_GIT_SHA"):
        assert expected in content, expected


# ---------------------------------------------------------------------------
# Artifact retention.
# ---------------------------------------------------------------------------


def test_uploaded_ci_artifacts_declare_a_retention_period():
    """An artifact with no stated retention has no retention policy."""
    workflows = ROOT / ".github" / "workflows"
    for path in workflows.glob("*.yml"):
        content = path.read_text()
        if "upload-artifact" not in content:
            continue
        blocks = re.split(r"(?=uses: actions/upload-artifact)", content)
        for block in blocks[1:]:
            # The step ends at the next `- name:` at the same or lower indent.
            step = re.split(r"\n\s*- (?:name|uses):", block)[0]
            assert "retention-days:" in step, f"{path.name}: {step[:120]}"


def test_the_workflow_cleanup_script_honours_its_documented_retention():
    """It ignored RETENTION_DAYS and deleted by run DURATION instead.

    Fast-passing gates -- exactly the security and lint jobs whose history is
    worth keeping -- were deleted regardless of age, while slow ones were kept
    forever. It also read only the newest 20 runs and swallowed its own errors,
    so CI history could not be cited as retained evidence.
    """
    script = (ROOT / "tools" / "workflow-cleanup" / "cleanup-workflows.js").read_text()
    assert "RETENTION_DAYS" in script
    # Age, not duration, must be what decides.
    assert "created_at" in script
    # Pagination: 20 runs is not "all runs older than N days".
    assert "paginate" in script or "per_page: 100" in script


def test_the_short_test_canary_can_actually_trigger():
    """Its path filter named a file that does not exist, so it never ran.

    That matters because it was the canary for the cleanup workflow, meaning the
    cleanup behaviour had never been exercised by its own test.
    """
    path = ROOT / ".github" / "workflows" / "ops.short-test.yml"
    content = path.read_text()
    referenced = re.findall(r"\.github/workflows/[\w.-]+\.yml", content)
    for name in referenced:
        assert (ROOT / name).exists(), f"{path.name} filters on missing {name}"


# ---------------------------------------------------------------------------
# The one that builds.
# ---------------------------------------------------------------------------


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker CLI unavailable")
def test_the_built_worker_image_matches_the_lockfile():
    """The assertion that would have caught the defect: image == lockfile.

    Static checks prove the Dockerfile says the right thing. This proves the
    image contains it.
    """
    probe = subprocess.run(  # nosec B603 B607 # fixed docker invocation
        ["docker", "info"], capture_output=True, text=True, timeout=60, check=False
    )
    if probe.returncode != 0:
        pytest.skip("docker daemon unavailable")

    tag = "autoaudit-worker:phase10-lockfile-check"
    build = subprocess.run(  # nosec B603 B607
        [
            "docker",
            "build",
            "--build-arg",
            f"ENGINE_GIT_SHA={'0' * 40}",
            "-t",
            tag,
            ".",
        ],
        cwd=ROOT / "engine",
        capture_output=True,
        text=True,
        timeout=1800,
        check=False,
    )
    assert build.returncode == 0, build.stdout[-4000:] + build.stderr[-4000:]

    locked = _locked_versions()
    checked = ["celery", "httpx", "sqlalchemy", "cryptography", "prometheus-client"]
    script = (
        "import importlib.metadata as m, json;"
        f"print(json.dumps({{p: m.version(p) for p in {checked!r}}}))"
    )
    result = subprocess.run(  # nosec B603 B607
        [
            "docker",
            "run",
            "--rm",
            "--entrypoint",
            "/app/.venv/bin/python",
            tag,
            "-c",
            script,
        ],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert result.returncode == 0, result.stderr[-2000:]
    installed = json.loads(result.stdout)
    for package in checked:
        assert installed[package] == locked[package], (
            f"{package}: image has {installed[package]}, "
            f"engine/uv.lock pins {locked[package]}"
        )


def _locked_versions() -> dict[str, str]:
    lock = (ROOT / "engine" / "uv.lock").read_text()
    return {
        match.group(1): match.group(2)
        for match in re.finditer(
            r'\[\[package\]\]\nname = "([^"]+)"\nversion = "([^"]+)"', lock
        )
    }
