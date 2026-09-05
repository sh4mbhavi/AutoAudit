"""SEC-01: exercise the actual hook/configuration with an ephemeral canary."""

import json
import secrets
import shutil
import subprocess
from pathlib import Path

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


def test_tracked_examples_pass(tmp_path):
    baseline = tmp_path / "baseline.json"
    shutil.copyfile(ROOT / ".secrets.baseline", baseline)
    paths = subprocess.check_output(
        ["git", "ls-files", "*.example"], cwd=ROOT, text=True
    ).splitlines()
    assert "env.example" in paths
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
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert (
        result.returncode == 0
    ), "Tracked examples must pass the secret hook; inspect locally without publishing values"
