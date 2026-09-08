"""Load, digest and structurally validate the SOC 2 crosswalk; never rate a control.

The crosswalk is the human-owned SOC 2 -> CIS mapping stored under ``mappings/``.
Every rating in it is a GRC judgment transcribed from the execution plan's
Appendix A. Nothing in this module creates, promotes, infers or edits a rating,
and nothing in this module writes to the filesystem: it reads the mapping, reads
the benchmark metadata, and reports structural drift as data.

Executing this module is free of side effects: it touches no file and needs no
worker configuration until a function is called. (Importing it as
``worker.crosswalk`` still runs ``worker/__init__.py``, which builds the Celery
app and the settings object; that is the package's behaviour, not this module's.)
"""

import hashlib
import json
import os
import re
from collections.abc import Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# worker.config builds and validates runtime settings at import time and
# worker.provenance imports it, so both are imported lazily: loading a mapping
# and reading digests must not require a configured worker environment.

# --------------------------------------------------------------------------
# Pinned crosswalk identity
# --------------------------------------------------------------------------

SCHEMA_VERSION = 1
MAPPINGS_DIR_ENV = "MAPPINGS_DIR"
MAPPING_FILENAME = "mapping.json"
METADATA_FILENAME = "metadata.json"
DEFAULT_MAPPING_FAMILY = "soc2/common-criteria"
DEFAULT_MAPPING_VERSION = "v1.0.0"

#: A rating of "No" means SOC 2 configuration coverage is not claimed at all, so
#: such a row may carry no automated evidence. The vocabulary itself is declared
#: by the mapping; this constant only names the one value with a structural rule.
NO_RATING = "No"

#: Points of focus covered by "every ready CIS control" rather than an explicit
#: list. The selector is resolved against metadata, never written back.
ALL_READY_SELECTOR = "all_automated_cis_m365_v6"
EVIDENCE_SELECTORS = frozenset({ALL_READY_SELECTOR})

READY_STATUS = "ready"
REQUIRED_CRITERIA = ("CC1", "CC2", "CC3", "CC4", "CC5", "CC6", "CC7", "CC8", "CC9")

SEVERITY_ERROR = "error"
SEVERITY_WARNING = "warning"

# --------------------------------------------------------------------------
# Finding codes
# --------------------------------------------------------------------------

UNSUPPORTED_SCHEMA = "unsupported_schema_version"
BENCHMARK_IDENTITY_MISMATCH = "benchmark_identity_mismatch"
BENCHMARK_PATH_UNUSABLE = "benchmark_path_unusable"
APPROVAL_INCONSISTENT = "approval_inconsistent"
CRITERIA_COVERAGE_INCOMPLETE = "criteria_coverage_incomplete"
CRITERIA_COVERAGE_UNEXPECTED = "criteria_coverage_unexpected"
MALFORMED_SECTION = "malformed_section"
MALFORMED_POINT = "malformed_point"
MALFORMED_RESOLUTION_ROW = "malformed_resolution_row"
DUPLICATE_POINT_ID = "duplicate_point_id"
DUPLICATE_RESOLUTION_ROW = "duplicate_resolution_row"
RATING_VOCABULARY_INVALID = "rating_vocabulary_invalid"
RATING_OUT_OF_VOCABULARY = "rating_out_of_vocabulary"
RATING_NO_WITH_EVIDENCE = "no_rating_carries_evidence"
RATED_POINT_WITHOUT_EVIDENCE = "rated_point_without_evidence"
UNKNOWN_EVIDENCE_SELECTOR = "unknown_evidence_selector"
SELECTOR_RESOLVES_TO_NOTHING = "selector_resolves_to_nothing"
RESOLUTION_ROW_MISSING = "resolution_row_missing"
RESOLUTION_ROW_UNREFERENCED = "resolution_row_unreferenced"
CONTROL_NOT_IN_METADATA = "control_not_in_metadata"
CONTROL_NOT_READY = "control_not_ready"
POLICY_FILE_MISMATCH = "policy_file_mismatch"
POLICY_FILE_MISSING = "policy_file_missing"
COLLECTOR_ID_MISMATCH = "collector_id_mismatch"
COLLECTOR_NOT_REGISTERED = "collector_not_registered"
DUPLICATE_METADATA_CONTROL = "duplicate_metadata_control_id"
MALFORMED_METADATA_CONTROL = "malformed_metadata_control"

_SEGMENT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")


# --------------------------------------------------------------------------
# Resolved records
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Finding:
    """One structural defect. Findings are returned, never raised, never rated."""

    code: str
    severity: str
    subject: str
    detail: str


@dataclass(frozen=True, slots=True)
class ResolvedControl:
    """A CIS control resolved to its metadata record, policy file and collector."""

    control_id: str
    record: dict
    policy_path: Path
    collector_id: str

    def as_tuple(self) -> tuple[dict, Path, str]:
        """Return ``(metadata_record, policy_path, collector_id)``."""
        return (self.record, self.policy_path, self.collector_id)


@dataclass(frozen=True, slots=True)
class ResolvedPointOfFocus:
    """A point of focus with its selector expanded. ``rating`` is copied verbatim."""

    point_id: str
    criterion: str
    point_of_focus: str
    rating: str
    control_ids: tuple[str, ...]
    evidence_selector: str | None
    residual_limitation: str
    residual_scope: str


# --------------------------------------------------------------------------
# Path resolution
# --------------------------------------------------------------------------


def engine_root() -> Path:
    """Engine source root; ``mappings/`` and ``policies/`` sit directly under it."""
    return Path(__file__).resolve().parents[1]


def mappings_dir() -> Path:
    """Crosswalk root, resolved the way ``worker.config`` resolves ``POLICIES_DIR``.

    ``MAPPINGS_DIR`` overrides the location for images that mount the artifact
    elsewhere; the default resolves against the engine root so a plain checkout
    needs no environment at all.
    """
    override = os.environ.get(MAPPINGS_DIR_ENV)
    return _resolve(Path(override)) if override else engine_root() / "mappings"


def policies_dir() -> Path:
    """Benchmark policy root, resolved exactly like ``provenance.capture_policy``."""
    from worker.config import settings

    return _resolve(Path(settings.POLICIES_DIR))


def _safe_segment(value: object, label: str) -> str:
    if not isinstance(value, str) or not _SEGMENT_RE.match(value):
        raise ValueError(f"Invalid {label} path segment")
    return value


def _resolve(path: Path) -> Path:
    """Canonicalize a path, turning an unresolvable one into a ValueError."""
    try:
        return path.resolve()
    except (OSError, RuntimeError) as error:
        # A symlink loop resolves to neither a path nor a useful error, so it is
        # normalised here: every caller only has to handle ValueError.
        raise ValueError(f"Unresolvable path: {error}") from None


def _under(base: Path, *segments: str) -> Path:
    """Join validated segments and prove the real target stays under ``base``.

    The segment pattern already excludes ``..`` and separators; resolving the
    result additionally defeats a symlinked directory or file inside the tree.
    """
    path = base
    for segment in segments:
        path = path / segment
    resolved = _resolve(path)
    if not resolved.is_relative_to(base):
        raise ValueError("Resolved path escapes its root")
    return resolved


def mapping_path(
    family: str = DEFAULT_MAPPING_FAMILY,
    version: str = DEFAULT_MAPPING_VERSION,
    root: Path | str | None = None,
) -> Path:
    """Absolute path of one versioned mapping artifact."""
    base = _resolve(Path(root) if root is not None else mappings_dir())
    segments = [_safe_segment(part, "mapping family") for part in family.split("/")]
    segments.append(_safe_segment(version, "mapping version"))
    segments.append(MAPPING_FILENAME)
    return _under(base, *segments)


def benchmark_dir(
    framework: str,
    slug: str,
    version: str,
    root: Path | str | None = None,
) -> Path:
    """Absolute path of one pinned benchmark version directory."""
    base = _resolve(Path(root) if root is not None else policies_dir())
    return _under(
        base,
        _safe_segment(framework, "framework"),
        _safe_segment(slug, "benchmark slug"),
        _safe_segment(version, "benchmark version"),
    )


def metadata_path(
    framework: str,
    slug: str,
    version: str,
    root: Path | str | None = None,
) -> Path:
    """Absolute path of one pinned benchmark ``metadata.json``."""
    return _under(benchmark_dir(framework, slug, version, root), METADATA_FILENAME)


# --------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------


def load_mapping(path: Path | str | None = None) -> dict:
    """Parse a mapping artifact. Read-only; the caller owns the returned dict."""
    target = Path(path) if path is not None else mapping_path()
    return json.loads(target.read_bytes().decode("utf-8"))


def load_metadata(
    framework: str,
    slug: str,
    version: str,
    root: Path | str | None = None,
) -> dict:
    """Parse one pinned benchmark's ``metadata.json``."""
    return json.loads(
        metadata_path(framework, slug, version, root).read_bytes().decode("utf-8")
    )


def load_pinned_metadata(
    mapping: Mapping[str, Any] | None = None,
    root: Path | str | None = None,
) -> dict:
    """Parse the metadata for exactly the benchmark the mapping pins."""
    benchmark = (mapping if mapping is not None else load_mapping()).get(
        "benchmark", {}
    )
    return load_metadata(
        benchmark.get("framework", ""),
        benchmark.get("slug", ""),
        benchmark.get("version", ""),
        root,
    )


# --------------------------------------------------------------------------
# Digests
# --------------------------------------------------------------------------


def mapping_digest(path_or_bytes: Path | str | bytes) -> str:
    """SHA-256 hex digest of the RAW mapping file bytes.

    The digest is deliberately taken over file bytes rather than over canonical
    JSON: byte hashing is unambiguous in every language a downstream consumer
    might use, needs no shared canonicalization rules, and makes ANY byte change
    to the artifact -- including reformatting or a comment-only edit -- change
    the digest. ``bytes`` are hashed directly; anything else is read as a path.
    """
    data = (
        path_or_bytes
        if isinstance(path_or_bytes, bytes)
        else Path(path_or_bytes).read_bytes()
    )
    return hashlib.sha256(data).hexdigest()


def policy_corpus_digest(
    framework: str,
    slug: str,
    version: str,
    root: Path | str | None = None,
) -> str:
    """Canonical digest over ``{policy_filename: sha256(file bytes)}`` for a version.

    ``metadata_digest`` in scan provenance covers ``metadata.json`` only, so a
    change to the Rego that actually decides compliance leaves it untouched.
    This digest closes that gap by covering the whole executable policy corpus.
    Canonicalization is reused from ``worker.provenance.canonical_digest`` so
    there is one canonical-JSON implementation in the engine, not two.
    """
    directory = benchmark_dir(framework, slug, version, root)
    corpus = {
        policy.name: hashlib.sha256(
            _under(directory, policy.name).read_bytes()
        ).hexdigest()
        for policy in sorted(directory.glob("*.rego"))
    }
    if not corpus:
        raise ValueError(f"No Rego policies found under {directory}")
    from worker.provenance import canonical_digest

    return canonical_digest(corpus)


def benchmark_metadata_digest(
    framework: str,
    slug: str,
    version: str,
    root: Path | str | None = None,
) -> str:
    """Canonical digest of parsed ``metadata.json``, matching scan provenance."""
    from worker.provenance import canonical_digest

    return canonical_digest(load_metadata(framework, slug, version, root))


# --------------------------------------------------------------------------
# Resolution
# --------------------------------------------------------------------------


def _metadata_index(metadata: Mapping[str, Any]) -> dict[str, dict]:
    controls = metadata.get("controls")
    if not isinstance(controls, list):
        return {}
    return {
        control["control_id"]: control
        for control in controls
        if isinstance(control, dict) and isinstance(control.get("control_id"), str)
    }


def _check_metadata_integrity(metadata: Mapping[str, Any]) -> list[Finding]:
    """Prove the benchmark resolves every control id to exactly one record.

    This runs before the selector population is derived, because a duplicated or
    nameless metadata row would otherwise quietly shrink that population instead
    of failing: the index keeps one record per id and drops the rest.
    """
    controls = metadata.get("controls")
    if not isinstance(controls, list):
        return [
            Finding(
                MALFORMED_SECTION,
                SEVERITY_ERROR,
                "metadata.controls",
                "The benchmark metadata declares no control list",
            )
        ]
    findings: list[Finding] = []
    seen: set[str] = set()
    for index, control in enumerate(controls):
        control_id = control.get("control_id") if isinstance(control, dict) else None
        if not isinstance(control_id, str) or not control_id.strip():
            findings.append(
                Finding(
                    MALFORMED_METADATA_CONTROL,
                    SEVERITY_ERROR,
                    f"metadata.controls[{index}]",
                    f"Control record has no usable control_id, found {control_id!r}",
                )
            )
            continue
        if control_id in seen:
            findings.append(
                Finding(
                    DUPLICATE_METADATA_CONTROL,
                    SEVERITY_ERROR,
                    control_id,
                    "The pinned benchmark defines this control more than once, so "
                    "the mapping cannot resolve it unambiguously",
                )
            )
        seen.add(control_id)
    return findings


def ready_control_ids(metadata: Mapping[str, Any]) -> tuple[str, ...]:
    """Control ids whose ``automation_status`` is ``ready``, in metadata order."""
    return tuple(
        control_id
        for control_id, record in _metadata_index(metadata).items()
        if record.get("automation_status") == READY_STATUS
    )


def mapping_control_ids(mapping: Mapping[str, Any] | None = None) -> tuple[str, ...]:
    """Every CIS control id the mapping resolves, sorted and de-duplicated.

    This is the single source of truth for "the Appendix A/B control population";
    tests must read it from here rather than repeating a literal list.
    """
    rows = (mapping if mapping is not None else load_mapping()).get(
        "control_resolution", []
    )
    return tuple(
        sorted(
            {
                row["control_id"]
                for row in rows
                if isinstance(row, dict) and isinstance(row.get("control_id"), str)
            }
        )
    )


def resolve_control(
    control_id: str,
    metadata: Mapping[str, Any] | None = None,
    root: Path | str | None = None,
) -> ResolvedControl:
    """Resolve one control to ``(metadata_record, policy_path, collector_id)``.

    Raises ``ValueError`` for an unknown control or one without a policy file;
    use :func:`validate_mapping` when you want every defect at once instead.
    """
    if metadata is None:
        metadata = load_pinned_metadata(root=root)
    record = _metadata_index(metadata).get(control_id)
    if record is None:
        raise ValueError(f"Unknown control: {control_id}")
    policy_file = record.get("policy_file")
    if not isinstance(policy_file, str) or not policy_file.endswith(".rego"):
        raise ValueError(f"Control {control_id} has no Rego policy file")
    directory = benchmark_dir(
        metadata.get("framework", ""),
        metadata.get("slug", ""),
        metadata.get("version", ""),
        root,
    )
    return ResolvedControl(
        control_id=control_id,
        record=record,
        policy_path=_under(directory, _safe_segment(policy_file, "policy file")),
        collector_id=record.get("data_collector_id"),
    )


def resolve_points_of_focus(
    mapping: Mapping[str, Any],
    metadata: Mapping[str, Any],
) -> list[ResolvedPointOfFocus]:
    """Expand evidence selectors into concrete control ids.

    Ratings are copied verbatim from the mapping. This function performs no
    judgment: it only says which CIS controls a human-rated row already points at.
    A selector always widens a row: it is unioned with any explicit ids so this
    function and :func:`validate_mapping` can never disagree about the population.
    """
    ready = ready_control_ids(metadata)
    resolved: list[ResolvedPointOfFocus] = []
    for point in mapping.get("points_of_focus", []):
        if not isinstance(point, dict):
            continue
        explicit = tuple(_string_list(point.get("cis_control_ids")))
        selector = point.get("evidence_selector")
        control_ids = (
            tuple(dict.fromkeys(explicit + ready))
            if selector == ALL_READY_SELECTOR
            else explicit
        )
        resolved.append(
            ResolvedPointOfFocus(
                point_id=str(point.get("point_id", "")),
                criterion=str(point.get("criterion", "")),
                point_of_focus=str(point.get("point_of_focus", "")),
                rating=point.get("rating"),
                control_ids=tuple(control_ids),
                evidence_selector=selector,
                residual_limitation=str(point.get("residual_limitation", "")),
                residual_scope=str(point.get("residual_scope", "")),
            )
        )
    return resolved


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


# --------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------


def _check_benchmark_identity(
    mapping: Mapping[str, Any], metadata: Mapping[str, Any]
) -> list[Finding]:
    findings: list[Finding] = []
    benchmark = mapping.get("benchmark")
    if not isinstance(benchmark, dict):
        return [
            Finding(
                MALFORMED_SECTION,
                SEVERITY_ERROR,
                "benchmark",
                "The mapping declares no benchmark identity object",
            )
        ]
    for field_name in ("framework", "benchmark", "slug", "version"):
        claimed = benchmark.get(field_name)
        actual = metadata.get(field_name)
        if not isinstance(claimed, str) or not claimed:
            findings.append(
                Finding(
                    BENCHMARK_IDENTITY_MISMATCH,
                    SEVERITY_ERROR,
                    f"benchmark.{field_name}",
                    f"The mapping does not pin a {field_name}; found {claimed!r}",
                )
            )
        elif claimed != actual:
            findings.append(
                Finding(
                    BENCHMARK_IDENTITY_MISMATCH,
                    SEVERITY_ERROR,
                    f"benchmark.{field_name}",
                    f"Mapping pins {claimed!r} but metadata declares {actual!r}",
                )
            )
    return findings


def _check_approval(mapping: Mapping[str, Any]) -> list[Finding]:
    approval = mapping.get("approval")
    if not isinstance(approval, dict):
        return [
            Finding(
                MALFORMED_SECTION,
                SEVERITY_ERROR,
                "approval",
                "The mapping declares no approval object",
            )
        ]
    approved = approval.get("approved")
    if not isinstance(approved, bool):
        return [
            Finding(
                APPROVAL_INCONSISTENT,
                SEVERITY_ERROR,
                "approval.approved",
                f"approved must be a boolean, found {approved!r}",
            )
        ]
    if not approved:
        return []
    missing = [
        name
        for name in ("reviewer_name", "reviewer_role", "approved_at")
        if not approval.get(name)
    ]
    if missing:
        return [
            Finding(
                APPROVAL_INCONSISTENT,
                SEVERITY_ERROR,
                "approval",
                f"approved is true but {', '.join(missing)} is unset",
            )
        ]
    return []


def _check_criteria_coverage(mapping: Mapping[str, Any]) -> list[Finding]:
    rows = mapping.get("criteria_coverage_summary")
    if not isinstance(rows, list):
        return [
            Finding(
                MALFORMED_SECTION,
                SEVERITY_ERROR,
                "criteria_coverage_summary",
                "The mapping declares no criteria coverage summary",
            )
        ]
    seen = [row.get("criterion") for row in rows if isinstance(row, dict)]
    findings = [
        Finding(
            CRITERIA_COVERAGE_INCOMPLETE,
            SEVERITY_ERROR,
            criterion,
            "criteria_coverage_summary does not classify this criterion",
        )
        for criterion in REQUIRED_CRITERIA
        if criterion not in seen
    ]
    findings.extend(
        Finding(
            CRITERIA_COVERAGE_UNEXPECTED,
            SEVERITY_ERROR,
            str(criterion),
            "criteria_coverage_summary carries an unknown or duplicate criterion",
        )
        for criterion in sorted(
            {
                str(criterion)
                for criterion in seen
                if criterion not in REQUIRED_CRITERIA or seen.count(criterion) > 1
            }
        )
    )
    return findings


def _check_points(
    mapping: Mapping[str, Any], vocabulary: Sequence[str]
) -> tuple[dict[str, list[str]], set[str], list[Finding]]:
    """Return (control_id -> referencing point ids, selectors used, findings)."""
    findings: list[Finding] = []
    referenced: dict[str, list[str]] = {}
    selectors: set[str] = set()
    points = mapping.get("points_of_focus")
    if not isinstance(points, list):
        return (
            referenced,
            selectors,
            [
                Finding(
                    MALFORMED_SECTION,
                    SEVERITY_ERROR,
                    "points_of_focus",
                    "The mapping declares no points of focus",
                )
            ],
        )

    seen: set[str] = set()
    for index, point in enumerate(points):
        if not isinstance(point, dict):
            findings.append(
                Finding(
                    MALFORMED_POINT,
                    SEVERITY_ERROR,
                    f"points_of_focus[{index}]",
                    "Point of focus is not an object",
                )
            )
            continue
        point_id = point.get("point_id")
        if not isinstance(point_id, str) or not point_id.strip():
            findings.append(
                Finding(
                    MALFORMED_POINT,
                    SEVERITY_ERROR,
                    f"points_of_focus[{index}]",
                    "Point of focus has no point_id",
                )
            )
            # Keep going: a nameless row still references controls that must
            # resolve, and the caller asked for every defect at once.
            point_id = f"points_of_focus[{index}]"
        elif point_id in seen:
            findings.append(
                Finding(
                    DUPLICATE_POINT_ID,
                    SEVERITY_ERROR,
                    point_id,
                    "point_id appears more than once in points_of_focus",
                )
            )
        seen.add(point_id)

        rating = point.get("rating")
        if rating not in vocabulary:
            findings.append(
                Finding(
                    RATING_OUT_OF_VOCABULARY,
                    SEVERITY_ERROR,
                    point_id,
                    f"Rating {rating!r} is not in rating_vocabulary {list(vocabulary)}",
                )
            )

        raw_ids = point.get("cis_control_ids")
        control_ids = _string_list(raw_ids)
        if not isinstance(raw_ids, list) or len(control_ids) != len(raw_ids):
            findings.append(
                Finding(
                    MALFORMED_POINT,
                    SEVERITY_ERROR,
                    point_id,
                    "cis_control_ids must be a list of control id strings",
                )
            )

        selector = point.get("evidence_selector")
        if selector is not None:
            if isinstance(selector, str) and selector in EVIDENCE_SELECTORS:
                selectors.add(selector)
            else:
                findings.append(
                    Finding(
                        UNKNOWN_EVIDENCE_SELECTOR,
                        SEVERITY_ERROR,
                        point_id,
                        f"Unknown evidence_selector {selector!r}",
                    )
                )

        if rating == NO_RATING and (control_ids or selector is not None):
            findings.append(
                Finding(
                    RATING_NO_WITH_EVIDENCE,
                    SEVERITY_ERROR,
                    point_id,
                    "A 'No' rating claims no configuration coverage, so it may "
                    "carry neither cis_control_ids nor an evidence_selector",
                )
            )
        if (
            rating in vocabulary
            and rating != NO_RATING
            and not control_ids
            and selector is None
        ):
            findings.append(
                Finding(
                    RATED_POINT_WITHOUT_EVIDENCE,
                    SEVERITY_ERROR,
                    point_id,
                    f"Rating {rating!r} claims coverage but names no CIS control",
                )
            )

        for control_id in control_ids:
            referenced.setdefault(control_id, []).append(point_id)

    return referenced, selectors, findings


def _check_resolution_rows(
    mapping: Mapping[str, Any],
) -> tuple[dict[str, dict], list[Finding]]:
    findings: list[Finding] = []
    rows = mapping.get("control_resolution")
    if not isinstance(rows, list):
        return {}, [
            Finding(
                MALFORMED_SECTION,
                SEVERITY_ERROR,
                "control_resolution",
                "The mapping declares no control resolution table",
            )
        ]
    resolution: dict[str, dict] = {}
    for index, row in enumerate(rows):
        if not isinstance(row, dict) or not isinstance(row.get("control_id"), str):
            findings.append(
                Finding(
                    MALFORMED_RESOLUTION_ROW,
                    SEVERITY_ERROR,
                    f"control_resolution[{index}]",
                    "Resolution row is not an object with a control_id",
                )
            )
            continue
        control_id = row["control_id"]
        if control_id in resolution:
            findings.append(
                Finding(
                    DUPLICATE_RESOLUTION_ROW,
                    SEVERITY_ERROR,
                    control_id,
                    "control_id appears more than once in control_resolution",
                )
            )
        resolution[control_id] = row
    return resolution, findings


def _check_control(
    control_id: str,
    record: dict | None,
    row: dict | None,
    registry: Collection[str],
    directory: Path | None,
) -> list[Finding]:
    findings: list[Finding] = []
    if record is None:
        return [
            Finding(
                CONTROL_NOT_IN_METADATA,
                SEVERITY_ERROR,
                control_id,
                "The mapping references a control the pinned benchmark does not define",
            )
        ]

    status = record.get("automation_status")
    if status != READY_STATUS:
        findings.append(
            Finding(
                CONTROL_NOT_READY,
                SEVERITY_ERROR,
                control_id,
                f"automation_status is {status!r}; the crosswalk may only claim "
                "automated evidence for 'ready' controls",
            )
        )

    policy_file = record.get("policy_file")
    if row is not None and row.get("policy_file") != policy_file:
        findings.append(
            Finding(
                POLICY_FILE_MISMATCH,
                SEVERITY_ERROR,
                control_id,
                f"control_resolution names {row.get('policy_file')!r} but metadata "
                f"names {policy_file!r}",
            )
        )
    if not isinstance(policy_file, str) or not policy_file.endswith(".rego"):
        findings.append(
            Finding(
                POLICY_FILE_MISSING,
                SEVERITY_ERROR,
                control_id,
                f"metadata policy_file is {policy_file!r}, not a Rego policy",
            )
        )
    elif directory is not None:
        try:
            policy_path = _under(directory, _safe_segment(policy_file, "policy file"))
            exists = policy_path.is_file()
        except (OSError, TypeError, ValueError):
            policy_path, exists = directory / policy_file, False
        if not exists:
            findings.append(
                Finding(
                    POLICY_FILE_MISSING,
                    SEVERITY_ERROR,
                    control_id,
                    f"Policy file does not exist at {policy_path}",
                )
            )

    collector_id = record.get("data_collector_id")
    if row is not None and row.get("data_collector_id") != collector_id:
        findings.append(
            Finding(
                COLLECTOR_ID_MISMATCH,
                SEVERITY_ERROR,
                control_id,
                f"control_resolution names {row.get('data_collector_id')!r} but "
                f"metadata names {collector_id!r}",
            )
        )
    if not isinstance(collector_id, str) or collector_id not in registry:
        findings.append(
            Finding(
                COLLECTOR_NOT_REGISTERED,
                SEVERITY_ERROR,
                control_id,
                f"Collector {collector_id!r} is not a key of DATA_COLLECTORS",
            )
        )
    return findings


def validate_mapping(
    mapping: Mapping[str, Any],
    metadata: Mapping[str, Any],
    registry_ids: Iterable[str],
    policies_root: Path | str | None = None,
) -> list[Finding]:
    """Prove the crosswalk resolves; report every defect instead of raising.

    Checks, for every CIS control the mapping references (explicitly or through
    an evidence selector), that the control exists in the pinned benchmark, is
    ``ready``, resolves to a Rego policy that exists on disk, and resolves to a
    registered collector -- and that the mapping's own tables agree with each
    other and with the metadata header.

    This function assigns, promotes, infers and modifies exactly nothing. It
    never edits a rating, never derives one, never writes a file, and never
    mutates either argument; a rating is a human GRC judgment and the only thing
    this code may say about one is whether its supporting references still hold.

    Args:
        mapping: Parsed mapping artifact.
        metadata: Parsed ``metadata.json`` for the benchmark the mapping pins.
        registry_ids: Keys of ``collectors.registry.DATA_COLLECTORS``.
        policies_root: Policy tree root; defaults to the configured POLICIES_DIR.

    Returns:
        Structured findings, empty when the crosswalk resolves cleanly.
    """
    if not isinstance(mapping, Mapping):
        return [
            Finding(
                MALFORMED_SECTION,
                SEVERITY_ERROR,
                "mapping",
                f"The mapping artifact is not an object, found {type(mapping).__name__}",
            )
        ]
    if not isinstance(metadata, Mapping):
        return [
            Finding(
                MALFORMED_SECTION,
                SEVERITY_ERROR,
                "metadata",
                f"The benchmark metadata is not an object, "
                f"found {type(metadata).__name__}",
            )
        ]

    findings: list[Finding] = []
    try:
        registry = frozenset(item for item in registry_ids if isinstance(item, str))
    except TypeError:
        registry = frozenset()
        findings.append(
            Finding(
                MALFORMED_SECTION,
                SEVERITY_ERROR,
                "registry_ids",
                "The collector registry is not iterable",
            )
        )

    if mapping.get("schema_version") != SCHEMA_VERSION:
        findings.append(
            Finding(
                UNSUPPORTED_SCHEMA,
                SEVERITY_ERROR,
                str(mapping.get("mapping_id", "mapping")),
                f"schema_version {mapping.get('schema_version')!r} is not "
                f"{SCHEMA_VERSION}",
            )
        )

    findings.extend(_check_benchmark_identity(mapping, metadata))
    findings.extend(_check_approval(mapping))
    findings.extend(_check_criteria_coverage(mapping))

    raw_vocabulary = mapping.get("rating_vocabulary")
    vocabulary = _string_list(raw_vocabulary)
    if not isinstance(raw_vocabulary, list) or len(vocabulary) != len(raw_vocabulary):
        findings.append(
            Finding(
                RATING_VOCABULARY_INVALID,
                SEVERITY_ERROR,
                "rating_vocabulary",
                "rating_vocabulary must be a list of rating strings",
            )
        )

    findings.extend(_check_metadata_integrity(metadata))

    referenced, selectors, point_findings = _check_points(mapping, vocabulary)
    findings.extend(point_findings)
    resolution, resolution_findings = _check_resolution_rows(mapping)
    findings.extend(resolution_findings)

    for control_id, point_ids in sorted(referenced.items()):
        if control_id not in resolution:
            findings.append(
                Finding(
                    RESOLUTION_ROW_MISSING,
                    SEVERITY_ERROR,
                    control_id,
                    f"Referenced by {', '.join(sorted(set(point_ids)))} but absent "
                    "from control_resolution",
                )
            )
    for control_id in sorted(set(resolution) - set(referenced)):
        findings.append(
            Finding(
                RESOLUTION_ROW_UNREFERENCED,
                SEVERITY_ERROR,
                control_id,
                "control_resolution resolves a control no point of focus references",
            )
        )

    index = _metadata_index(metadata)
    selected: set[str] = set()
    if ALL_READY_SELECTOR in selectors:
        selected = set(ready_control_ids(metadata))
        if not selected:
            findings.append(
                Finding(
                    SELECTOR_RESOLVES_TO_NOTHING,
                    SEVERITY_ERROR,
                    ALL_READY_SELECTOR,
                    "The selector matches no ready control in the pinned benchmark",
                )
            )

    try:
        directory = benchmark_dir(
            metadata.get("framework", ""),
            metadata.get("slug", ""),
            metadata.get("version", ""),
            policies_root,
        )
    except (OSError, TypeError, ValueError):
        directory = None
        findings.append(
            Finding(
                BENCHMARK_PATH_UNUSABLE,
                SEVERITY_ERROR,
                "metadata",
                "The metadata header does not name a usable benchmark directory",
            )
        )

    # Every id the mapping names anywhere -- through a point of focus, through a
    # selector, or only through control_resolution -- has to resolve.
    for control_id in sorted(set(referenced) | selected | set(resolution)):
        findings.extend(
            _check_control(
                control_id,
                index.get(control_id),
                resolution.get(control_id),
                registry,
                directory,
            )
        )
    return findings
