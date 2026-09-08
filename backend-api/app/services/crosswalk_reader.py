"""Read versioned SOC 2 crosswalk mappings and benchmark policy corpus digests.

Mappings are mounted read-only beside the policies, laid out as::

    mappings/{family}/{criteria_family}/{version}/mapping.json

for example ``mappings/soc2/common-criteria/v1.0.0/mapping.json``.

This module produces the two digests that scan creation freezes onto the scan row.

``mapping_digest``
    SHA-256 over the **raw bytes** of ``mapping.json``. Byte exact, so any edit at
    all - including whitespace or key reordering - yields a different digest. It is
    deliberately not a digest over the parsed document: the artifact an auditor is
    handed is the file, and the digest has to identify that file.

``policy_corpus_digest``
    SHA-256 over the canonical JSON object ``{policy_filename: sha256_hex(bytes)}``
    for every ``*.rego`` in a benchmark version directory, serialised with
    ``json.dumps(payload, sort_keys=True, separators=(",", ":"))`` and encoded
    UTF-8. ``metadata_digest`` covers ``metadata.json`` only, so a policy can be
    rewritten - changing what every scan evaluates - without changing
    ``metadata_digest``. This digest closes that gap at scan level. A per-file map
    rather than a concatenation means a rename is also a change.

Failures here are loud. A missing, unreadable or structurally invalid mapping
raises; nothing is defaulted, guessed or silently skipped, because a SOC 2 report
rendered from a guessed mapping is worse than no report at all. This is the one
place where the reading style deliberately differs from
``benchmark_reader.list_benchmarks()``, which swallows decode and OS errors.

Nothing in this module reads, computes, promotes or alters a rating. Ratings are
human-owned GRC judgments; the structural check below reports findings only.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from app.core.config import get_settings

# The mapping file name is fixed by the layout above.
MAPPING_FILENAME = "mapping.json"

# family / criteria-family / version / mapping.json
_MAPPING_GLOB = "*/*/*/" + MAPPING_FILENAME

# Read files in bounded chunks so a corrupt oversized artifact cannot be buffered
# whole just to digest it.
_DIGEST_CHUNK_BYTES = 1024 * 1024

# Keys a mapping document must carry before it can be pinned to a scan.
_REQUIRED_MAPPING_KEYS = (
    "schema_version",
    "mapping_id",
    "mapping_version",
    "status",
    "benchmark",
    "soc2",
    "rating_vocabulary",
    "approval",
    "points_of_focus",
    "control_resolution",
)

# Keys every point of focus must carry. ``rating`` is the human-owned judgment.
_REQUIRED_POINT_KEYS = ("point_id", "criterion", "point_of_focus", "rating")


class CrosswalkError(RuntimeError):
    """Base class for every crosswalk failure. Always fails closed."""


class CrosswalkNotFoundError(CrosswalkError):
    """The requested mapping or benchmark policy directory does not exist."""


class CrosswalkIntegrityError(CrosswalkError):
    """A mapping file exists but cannot be parsed or is structurally invalid."""


@dataclass(frozen=True)
class LoadedMapping:
    """One mapping document with the digest of the exact bytes it came from."""

    mapping_id: str
    mapping_version: str
    digest: str
    document: dict[str, Any]

    def applies_to(self, framework: str, slug: str, version: str) -> bool:
        """Whether this mapping was written for that benchmark version.

        A mapping is bound to one benchmark release. Scanning a different
        benchmark is perfectly valid, it simply has no SOC 2 projection; the
        caller must leave the pin null rather than stretch this mapping over it.
        """
        benchmark = self.document.get("benchmark") or {}
        return (
            _normalize(benchmark.get("framework")) == _normalize(framework)
            and _normalize(benchmark.get("slug")) == _normalize(slug)
            and _normalize(benchmark.get("version")) == _normalize(version)
        )


def _normalize(value: Any) -> str:
    """Case-insensitive, whitespace-insensitive identity comparison."""
    return str(value or "").strip().lower()


def sha256_bytes_of_file(path: Path) -> str:
    """SHA-256 hex digest of a file's raw bytes, read in bounded chunks."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(_DIGEST_CHUNK_BYTES)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def canonical_digest(payload: Any) -> str:
    """SHA-256 over canonical JSON: sorted keys, no insignificant whitespace."""
    return hashlib.sha256(
        json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    ).hexdigest()


def policy_corpus_digest_for_directory(directory: Path) -> str:
    """Digest every ``*.rego`` in one benchmark version directory.

    Returns the SHA-256 of ``{filename: sha256_hex(file bytes)}`` in canonical
    JSON. Editing, adding, removing or renaming a policy changes the result;
    editing ``metadata.json`` does not, because metadata has its own digest.

    Raises:
        CrosswalkNotFoundError: the directory does not exist.
        CrosswalkIntegrityError: a policy file could not be read.
    """
    if not directory.is_dir():
        raise CrosswalkNotFoundError("Benchmark policy directory is not present")
    per_file: dict[str, str] = {}
    for policy in sorted(directory.glob("*.rego")):
        if not policy.is_file():
            continue
        try:
            per_file[policy.name] = sha256_bytes_of_file(policy)
        except OSError as error:
            raise CrosswalkIntegrityError(
                f"Policy file {policy.name} could not be read for digesting"
            ) from error
    return canonical_digest(per_file)


def check_control_resolution(
    document: dict[str, Any], metadata: dict[str, Any] | None
) -> list[dict[str, str]]:
    """Structural check that a mapping's control references still resolve.

    Reports findings; it never edits the mapping and never touches a rating. The
    authoritative validator lives with the engine; this is the small backend-side
    check that a pinned mapping can still be projected onto a pinned benchmark.

    Findings use these codes:

    ``control_missing``
        The mapping names a control the benchmark metadata does not define.
    ``control_not_ready``
        The control exists but is not ``automation_status == "ready"``, so it
        cannot produce automated configuration evidence.
    ``policy_file_mismatch`` / ``collector_mismatch``
        The mapping and the metadata disagree about which policy or collector
        answers the control.
    ``unresolved_point_reference``
        A point of focus cites a control id that ``control_resolution`` omits.
    """
    # Both arguments may be pinned snapshots that predate the loader's validation,
    # so shape is checked rather than assumed.
    raw_controls = metadata.get("controls") if isinstance(metadata, dict) else None
    controls = {
        control["control_id"]: control
        for control in (raw_controls if isinstance(raw_controls, list) else [])
        if isinstance(control, dict) and isinstance(control.get("control_id"), str)
    }
    findings: list[dict[str, str]] = []
    resolved: set[str] = set()

    resolution = (
        document.get("control_resolution") if isinstance(document, dict) else None
    )
    for row in resolution if isinstance(resolution, list) else []:
        # Tolerant of an older pin written before the loader validated shape.
        if not isinstance(row, dict):
            continue
        control_id = row.get("control_id")
        if not isinstance(control_id, str) or not control_id:
            continue
        resolved.add(control_id)
        control = controls.get(control_id)
        if control is None:
            findings.append(
                {
                    "code": "control_missing",
                    "control_id": control_id,
                    "detail": "Control is absent from the pinned benchmark metadata.",
                }
            )
            continue
        automation_status = control.get("automation_status")
        if automation_status != "ready":
            findings.append(
                {
                    "code": "control_not_ready",
                    "control_id": control_id,
                    "detail": f"Automation status is {automation_status!r}, not 'ready'.",
                }
            )
        expected_policy = row.get("policy_file")
        if expected_policy and control.get("policy_file") != expected_policy:
            findings.append(
                {
                    "code": "policy_file_mismatch",
                    "control_id": control_id,
                    "detail": "Mapping and benchmark metadata name different policy files.",
                }
            )
        expected_collector = row.get("data_collector_id")
        if (
            expected_collector
            and control.get("data_collector_id") != expected_collector
        ):
            findings.append(
                {
                    "code": "collector_mismatch",
                    "control_id": control_id,
                    "detail": "Mapping and benchmark metadata name different collectors.",
                }
            )

    points = document.get("points_of_focus") if isinstance(document, dict) else None
    for point in points if isinstance(points, list) else []:
        if not isinstance(point, dict):
            continue
        cited = point.get("cis_control_ids")
        for control_id in cited if isinstance(cited, list) else []:
            if isinstance(control_id, str) and control_id not in resolved:
                findings.append(
                    {
                        "code": "unresolved_point_reference",
                        "control_id": control_id,
                        "detail": (
                            "Point of focus "
                            f"{point.get('point_id', 'unknown')} cites a control "
                            "the mapping does not resolve."
                        ),
                    }
                )
    return findings


def _validate_document(document: Any, source: str) -> dict[str, Any]:
    """Reject anything that cannot be safely pinned or rendered.

    Deliberately hand-written rather than schema-driven: no new third-party
    dependency may be added, and the engine owns the authoritative validator.
    """
    if not isinstance(document, dict):
        raise CrosswalkIntegrityError(f"Mapping {source} is not a JSON object")
    missing = [key for key in _REQUIRED_MAPPING_KEYS if key not in document]
    if missing:
        raise CrosswalkIntegrityError(
            f"Mapping {source} is missing required keys: {', '.join(sorted(missing))}"
        )
    for key in ("benchmark", "soc2", "approval"):
        if not isinstance(document[key], dict):
            raise CrosswalkIntegrityError(f"Mapping {source} has a non-object {key}")
    # ``approved`` gates the whole document's status. A truthy string such as
    # "false" must never be able to read as approved anywhere downstream.
    if not isinstance(document["approval"].get("approved"), bool):
        raise CrosswalkIntegrityError(
            f"Mapping {source} has a non-boolean approval flag"
        )
    vocabulary = document["rating_vocabulary"]
    if (
        not isinstance(vocabulary, list)
        or not vocabulary
        or not all(isinstance(word, str) and word for word in vocabulary)
    ):
        raise CrosswalkIntegrityError(
            f"Mapping {source} has no rating vocabulary to copy ratings from"
        )
    points = document["points_of_focus"]
    if not isinstance(points, list) or not points:
        raise CrosswalkIntegrityError(f"Mapping {source} has no points of focus")
    allowed = set(vocabulary)
    seen_ids: set[str] = set()
    for point in points:
        if not isinstance(point, dict):
            raise CrosswalkIntegrityError(
                f"Mapping {source} has a non-object point of focus"
            )
        absent = [
            key
            for key in _REQUIRED_POINT_KEYS
            if not isinstance(point.get(key), str) or not point.get(key)
        ]
        if absent:
            raise CrosswalkIntegrityError(
                f"Mapping {source} has a point of focus missing {', '.join(absent)}"
            )
        cited = point.get("cis_control_ids")
        if cited is not None and (
            not isinstance(cited, list)
            or not all(isinstance(item, str) and item for item in cited)
        ):
            raise CrosswalkIntegrityError(
                f"Mapping {source} cites malformed control ids in {point['point_id']}"
            )
        selector = point.get("evidence_selector")
        if selector is not None and not isinstance(selector, str):
            raise CrosswalkIntegrityError(
                f"Mapping {source} has a non-string selector in {point['point_id']}"
            )
        if point["rating"] not in allowed:
            # A rating outside the declared vocabulary cannot be rendered
            # verbatim with any confidence about what it means.
            raise CrosswalkIntegrityError(
                f"Mapping {source} rates {point['point_id']} outside its vocabulary"
            )
        if point["point_id"] in seen_ids:
            raise CrosswalkIntegrityError(
                f"Mapping {source} repeats point id {point['point_id']}"
            )
        seen_ids.add(point["point_id"])
    resolution = document["control_resolution"]
    if not isinstance(resolution, list):
        raise CrosswalkIntegrityError(
            f"Mapping {source} has a non-list control resolution"
        )
    for row in resolution:
        # A malformed row would pin cleanly and then break at render time, long
        # after the pin became immutable. Reject it here instead.
        if (
            not isinstance(row, dict)
            or not isinstance(row.get("control_id"), str)
            or not row["control_id"]
        ):
            raise CrosswalkIntegrityError(
                f"Mapping {source} has a malformed control resolution row"
            )
    summary = document.get("criteria_coverage_summary")
    if summary is not None and (
        not isinstance(summary, list)
        or not all(isinstance(row, dict) for row in summary)
    ):
        raise CrosswalkIntegrityError(
            f"Mapping {source} has a malformed criteria coverage summary"
        )
    return document


def _load_from_path(path: Path) -> LoadedMapping:
    """Read, digest and validate one mapping file. Never swallows an error.

    A file that is absent and a file that is present but unreadable are different
    failures. Only the first may be treated by a caller as "no mapping here"; a
    permission or I/O error on a mounted mapping is an integrity failure, because
    proceeding would pin nothing and the pin cannot be repaired afterwards.
    """
    try:
        raw = path.read_bytes()
    except FileNotFoundError as error:
        raise CrosswalkNotFoundError("Mapping file is not present") from error
    except OSError as error:
        raise CrosswalkIntegrityError("Mapping file could not be read") from error
    digest = hashlib.sha256(raw).hexdigest()
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CrosswalkIntegrityError(
            f"Mapping at {path.parent.name}/{MAPPING_FILENAME} is not valid JSON"
        ) from error
    # The root type is checked before anything reads a key off it, so a JSON
    # array or literal raises the sanitised integrity error rather than an
    # AttributeError that would escape as an unhandled 500.
    if not isinstance(document, dict):
        raise CrosswalkIntegrityError(
            f"Mapping at {path.parent.name}/{MAPPING_FILENAME} is not a JSON object"
        )
    source = str(document.get("mapping_id") or path.parent.name)
    document = _validate_document(document, source)
    return LoadedMapping(
        mapping_id=str(document["mapping_id"]),
        mapping_version=str(document["mapping_version"]),
        digest=digest,
        document=document,
    )


class CrosswalkFileReader:
    """Locate, read and digest mapping documents under ``MAPPINGS_DIR``.

    Nothing is cached. A mapping is read and re-digested on every call, so the
    digest that gets frozen onto a scan is always the digest of the bytes on disk
    at that moment. A stat-keyed cache would be faster and wrong: a replacement
    of identical size with a preserved timestamp would keep pinning the old
    document and the old digest for the life of the process. Reads happen once
    per scan creation over a file of tens of kilobytes, and the report itself
    never touches the filesystem, so there is nothing here worth caching.
    """

    def __init__(
        self,
        mappings_dir: Path | str | None = None,
        policies_dir: Path | str | None = None,
    ):
        settings = get_settings()
        if mappings_dir is None:
            mappings_dir = getattr(settings, "MAPPINGS_DIR", "/app/mappings")
        if policies_dir is None:
            policies_dir = getattr(settings, "POLICIES_DIR", "/app/policies")
        self.mappings_dir = Path(mappings_dir)
        self.policies_dir = Path(policies_dir)

    # ---------------------------------------------------------------- mappings

    def mappings_available(self) -> bool:
        """Whether a mapping corpus is mounted at all.

        False means SOC 2 projection is not deployed here. That is a
        configuration state, not corruption, and callers report it as "no
        projection" rather than treating the deployment as broken.
        """
        return self.mappings_dir.is_dir()

    def _candidate_paths(self) -> list[Path]:
        if not self.mappings_available():
            raise CrosswalkNotFoundError("No mapping directory is mounted")
        try:
            return sorted(self.mappings_dir.glob(_MAPPING_GLOB))
        except OSError as error:
            raise CrosswalkIntegrityError(
                "The mapping directory could not be listed"
            ) from error

    def load_mapping(self, mapping_id: str, mapping_version: str) -> LoadedMapping:
        """Load one mapping by identity.

        Every mapping file found is parsed and validated, so a corrupt neighbour
        is a loud failure rather than a silently skipped file.

        Raises:
            CrosswalkNotFoundError: no mapping corpus, or no such identity.
            CrosswalkIntegrityError: some mapping file is unreadable or invalid.
        """
        for path in self._candidate_paths():
            mapping = _load_from_path(path)
            if (
                mapping.mapping_id == mapping_id
                and mapping.mapping_version == mapping_version
            ):
                return mapping
        raise CrosswalkNotFoundError(
            f"Mapping {mapping_id} {mapping_version} is not present"
        )

    def load_configured_mapping(self) -> LoadedMapping:
        """Load the mapping new scans pin, per settings."""
        settings = get_settings()
        return self.load_mapping(
            settings.SOC2_MAPPING_ID, settings.SOC2_MAPPING_VERSION
        )

    # ---------------------------------------------------------------- policies

    def policy_corpus_digest(self, framework: str, slug: str, version: str) -> str:
        """Digest every ``*.rego`` of one benchmark version. See module docstring."""
        return policy_corpus_digest_for_directory(
            self.policies_dir / framework / slug / version
        )

    def check_resolution(
        self, document: dict[str, Any], metadata: dict[str, Any] | None
    ) -> list[dict[str, str]]:
        """Structural resolution findings. Never mutates a rating."""
        return check_control_resolution(document, metadata)


@lru_cache(maxsize=1)
def get_crosswalk_reader() -> CrosswalkFileReader:
    """One reader instance. Only the configured paths are reused, never content."""
    return CrosswalkFileReader()
