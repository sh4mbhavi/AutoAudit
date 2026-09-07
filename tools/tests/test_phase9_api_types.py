"""The frontend's scan types must equal what the backend's OpenAPI schema says.

The gate is the point: a hand-written frontend type agrees with the API until
someone edits a Pydantic model, and nothing notices. ``--check`` is the same
shape as ``tools/docs/generate_control_status.py --check``, which already gates
the generated control-status documents.
"""

import subprocess  # nosec B404 - fixed argv, no shell
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
GENERATOR = ROOT / "tools" / "frontend" / "generate_api_types.py"
GENERATED = ROOT / "frontend" / "src" / "api" / "generated" / "scans.ts"


def _run(*arguments):
    return subprocess.run(  # nosec B603 - fixed interpreter and script path
        [sys.executable, str(GENERATOR), *arguments],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=180,
    )


@pytest.fixture(scope="module")
def generator_available():
    result = _run("--check")
    if "ModuleNotFoundError" in result.stderr:
        pytest.skip("generator needs the backend-api environment")
    return result


def test_the_committed_types_match_the_backend_schema(generator_available):
    assert generator_available.returncode == 0, (
        generator_available.stdout + generator_available.stderr
    )
    assert "matches the backend OpenAPI schema" in generator_available.stdout


def test_check_fails_and_shows_a_diff_when_the_file_drifts(generator_available):
    original = GENERATED.read_text(encoding="utf-8")
    try:
        GENERATED.write_text(
            original.replace(
                "export interface ScanSummary {", "export interface Drifted {"
            ),
            encoding="utf-8",
        )
        result = _run("--check")
        assert result.returncode == 1
        assert "is stale" in result.stdout
        assert "ScanSummary" in result.stdout
    finally:
        GENERATED.write_text(original, encoding="utf-8")


def test_the_generated_file_is_marked_generated_and_names_its_generator():
    text = GENERATED.read_text(encoding="utf-8")
    assert text.startswith("// GENERATED FILE -- DO NOT EDIT.")
    assert "tools/frontend/generate_api_types.py" in text


def test_the_scan_response_types_the_frontend_consumes_are_all_present():
    text = GENERATED.read_text(encoding="utf-8")
    for name in (
        "ScanListItem",
        "ScanRead",
        "ScanResultRead",
        "ScanSummary",
        "ScanCreatedResponse",
        "ScanProvenanceRead",
        "ControlCategoryBreakdown",
    ):
        assert f"export interface {name} " in text, name


def test_the_generated_types_are_imported_by_the_api_client():
    client = (ROOT / "frontend" / "src" / "api" / "client.ts").read_text(
        encoding="utf-8"
    )
    assert 'from "./generated/scans"' in client
    # The scan reads Phase 9 touches must not be Promise<any> any more.
    for signature in (
        "export async function getScans(",
        "export async function getScan(",
        "export async function getScanSummary(",
        "export async function getScanResults(",
        "export async function createScan(",
    ):
        start = client.index(signature)
        declaration = client[start : client.index("{", start)]
        assert "Promise<any>" not in declaration, signature
