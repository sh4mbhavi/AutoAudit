"""Public source snapshots and digests; never persist additional tenant payloads."""

import hashlib
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from worker.config import settings


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical_digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode()
    ).hexdigest()


def engine_identity() -> dict:
    root = Path(__file__).resolve().parents[1]
    sha = settings.ENGINE_GIT_SHA
    dirty = None
    if not sha:
        try:
            sha = (
                subprocess.check_output(
                    ["git", "rev-parse", "HEAD"],
                    cwd=root,
                    stderr=subprocess.DEVNULL,
                    timeout=5,
                )
                .decode()
                .strip()
            )
            dirty = bool(
                subprocess.check_output(
                    [
                        "git",
                        "status",
                        "--porcelain",
                        "--",
                        "worker",
                        "collectors",
                        "opa_client.py",
                    ],
                    cwd=root,
                    stderr=subprocess.DEVNULL,
                    timeout=5,
                ).strip()
            )
        except (OSError, subprocess.SubprocessError):
            sha = ""
    if sha and not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError("Invalid engine source revision")
    image = settings.ENGINE_IMAGE_DIGEST or None
    if image and not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
        raise ValueError("Invalid engine image digest")
    if not sha and not image:
        raise ValueError("ENGINE_GIT_SHA or ENGINE_IMAGE_DIGEST is required")
    files = sorted(
        [
            root / "opa_client.py",
            *root.glob("worker/*.py"),
            *root.glob("collectors/**/*.py"),
        ]
    )
    sources = {
        str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in files
    }
    return {
        "engine_git_sha": sha or None,
        "engine_image_digest": image,
        "engine_worktree_dirty": dirty,
        "engine_source_digest": canonical_digest(sources),
    }


def initial_provenance(
    framework: str,
    benchmark: str,
    version: str,
    control: dict,
    context: dict | None = None,
) -> dict:
    context = context or {}
    return {
        "schema_version": 1,
        "framework": framework,
        "benchmark": benchmark,
        "benchmark_version": version,
        "control_id": control["control_id"],
        "metadata_digest": context.get("metadata_digest"),
        "correlation_id": context.get("correlation_id"),
        "collector_id": control.get("data_collector_id"),
        "policy_file": control.get("policy_file"),
        "policy_digest": None,
        "policy_source": None,
        "input_digest": None,
        "engine_git_sha": None,
        "engine_image_digest": None,
        "opa_version": None,
        "collection_started_at": None,
        "collection_completed_at": None,
        "evaluation_started_at": None,
        "evaluated_at": None,
        "recorded_at": utc_now(),
        "provenance_status": "not_executed",
    }


def capture_policy(
    framework: str, benchmark: str, version: str, policy_file: str
) -> str:
    # A policy_file is a flat filename inside the benchmark directory, and all 69
    # shipped values are, so this rejects nothing that exists today. It is what
    # keeps engine/policies/candidate/ structurally unreachable: without it a
    # future metadata entry of "candidate/3.2.2_dlp_policies_teams.rego" would
    # resolve under the policies root, pass the suffix check and be loaded and
    # evaluated, making candidate isolation a test convention rather than a
    # property of the code.
    if (
        type(policy_file) is not str
        or "/" in policy_file
        or "\\" in policy_file
        or policy_file in ("", ".", "..")
    ):
        raise ValueError("Invalid policy path")
    root = Path(settings.POLICIES_DIR).resolve()
    path = (root / framework / benchmark / version / policy_file).resolve()
    if not path.is_relative_to(root) or path.suffix != ".rego":
        raise ValueError("Invalid policy path")
    return path.read_text(encoding="utf-8")
