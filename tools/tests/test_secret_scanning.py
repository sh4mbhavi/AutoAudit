"""SEC-01: exercise the actual hook/configuration with an ephemeral canary."""

import json
import secrets
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def test_example_canary_is_rejected(tmp_path):
    for name in (".pre-commit-config.yaml", ".secrets.baseline"):
        shutil.copyfile(ROOT / name, tmp_path / name)
    (tmp_path / "tools").mkdir()
    shutil.copyfile(
        ROOT / "tools/google_oauth_secret_detector.py",
        tmp_path / "tools/google_oauth_secret_detector.py",
    )
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    # Random synthetic Google-shaped value, never sent to a provider or persisted.
    (tmp_path / "env.example").write_text(
        "GOOGLE_OAUTH_CLIENT_SECRET=GOCSPX-" + secrets.token_urlsafe(24) + "\n"
    )
    subprocess.run(["git", "add", "env.example"], cwd=tmp_path, check=True)
    result = subprocess.run(
        [
            "uv",
            "tool",
            "run",
            "--from",
            "pre-commit==4.5.1",
            "pre-commit",
            "run",
            "detect-secrets",
            "--files",
            "env.example",
        ],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
    )
    # Do not echo scanner output: it can contain the canary.
    assert result.returncode == 1, "The secret hook must reject env.example"
    assert "Potential secrets about to be committed" in result.stdout + result.stderr


def test_baseline_does_not_hide_examples():
    import re

    baseline = json.loads((ROOT / ".secrets.baseline").read_text())
    for item in baseline["filters_used"]:
        if item["path"].endswith("should_exclude_file"):
            patterns = item["pattern"]
            if isinstance(patterns, str):
                patterns = [patterns]
            for path in (
                "env.example",
                "backend-api/.env.example",
                "frontend/.env.example",
            ):
                assert not any(re.search(pattern, path) for pattern in patterns)


# What git would ignore. A clean checkout that has been `uv sync`ed carries
# thousands of vendored files, and handing them all to the hook is both wrong
# and unusable.
_EXCLUDED = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "node_modules",
        "site-packages",
        "__pycache__",
        "dist",
        "build",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
    }
)


def _example_files() -> list[str]:
    """Every `*.example` in the tree, whether or not this is a git checkout.

    This used to be `git ls-files "*.example"`, which fails with exit 128 in a
    source tree that is not a repository -- a released tarball, an unpacked
    image layer, or the clean-checkout run the release verification does on
    purpose. The gate is about the files that ship, so it reads the files that
    are there; git is used when it is available because it also excludes
    anything ignored.
    """
    try:
        listed = subprocess.check_output(
            ["git", "ls-files", "*.example"],
            cwd=ROOT,
            text=True,
            stderr=subprocess.DEVNULL,
        ).splitlines()
    except (subprocess.CalledProcessError, FileNotFoundError):
        listed = [
            str(path.relative_to(ROOT))
            for path in sorted(ROOT.rglob("*.example"))
            if not _EXCLUDED.intersection(path.parts)
        ]
    assert listed, "no *.example files found; this gate would pass vacuously"
    return listed


def test_tracked_examples_pass(tmp_path):
    """Every shipped `*.example` must pass the secret hook.

    Run inside a throwaway repository rather than against ROOT.
    `detect-secrets-hook` shells out to `git diff` to decide what changed, so it
    fails outside a working tree -- which is what a released tarball, an
    unpacked image layer, and the clean-checkout release verification all are.
    Copying the same files into a fresh `git init` checks the same content and
    makes the gate independent of how the source was obtained.
    """
    baseline = tmp_path / ".secrets.baseline"
    shutil.copyfile(ROOT / ".secrets.baseline", baseline)
    paths = _example_files()
    assert "env.example" in paths

    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    for relative in paths:
        destination = tmp_path / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, destination)
    subprocess.run(["git", "add", "-A"], cwd=tmp_path, check=True)

    result = subprocess.run(
        [
            "uv",
            "tool",
            "run",
            "--from",
            "detect-secrets==1.5.0",
            "detect-secrets-hook",
            "--baseline",
            str(baseline),
            "--no-verify",
            *paths,
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert (
        result.returncode == 0
    ), "Tracked examples must pass the secret hook; inspect locally without publishing values"


def test_the_fallback_listing_matches_git():
    """The fallback must select the same files, or the gate changes meaning.

    Skipped where git cannot answer -- which is the case the fallback exists
    for, and where there is nothing to compare against.
    """
    try:
        tracked = sorted(
            subprocess.check_output(
                ["git", "ls-files", "*.example"],
                cwd=ROOT,
                text=True,
                stderr=subprocess.DEVNULL,
            ).splitlines()
        )
    except (subprocess.CalledProcessError, FileNotFoundError):  # pragma: no cover
        pytest.skip("not a git checkout; the fallback is the only listing")
    walked = sorted(
        str(path.relative_to(ROOT))
        for path in ROOT.rglob("*.example")
        if not _EXCLUDED.intersection(path.parts)
    )
    assert walked == tracked
