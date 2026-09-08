"""Response contract for the SOC 2 report projection.

Every model here is a *projection* of two frozen inputs: the mapping pinned on
the scan and the results that scan actually produced. Nothing in this contract
lets a rating be computed, promoted or inferred - ``configuration_rating`` is
copied verbatim from the pinned mapping and is accompanied by
``rating_is_computed: false`` so a consumer cannot mistake it for a score.

Coverage is always reported as a numerator and a denominator with the percentage
alongside, never as a bare percentage, because "100%" of a two-control sample is
not the same claim as "100%" of a forty-control sample.
"""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

# A rating is whatever the pinned mapping's own ``rating_vocabulary`` allows.
# It is intentionally untyped here: this contract transcribes GRC judgments, it
# does not define them, and a future approved mapping may use other words.
Soc2Rating = str

ProjectionStatus = Literal["available", "no_projection"]

AssessmentCompleteness = Literal[
    "complete",  # every applicable control in this point of focus was assessed
    "partial",  # some applicable controls produced no assessed result
    "not_assessed",  # applicable controls exist, none were assessed
    "not_applicable",  # this scan selected none of the mapped controls
    "no_automated_coverage",  # the mapping maps this point to no automation
]

NOT_A_CERTIFICATION = (
    "This is not a SOC 2 certification, examination, attestation or audit "
    "opinion, and it is not evidence that any criterion is met. It reports "
    "Microsoft 365 configuration results projected through a crosswalk that "
    "has not been approved by a GRC reviewer."
)

RATING_OWNERSHIP = (
    "Configuration ratings are human-owned GRC judgments copied verbatim from "
    "the pinned mapping. AutoAudit never creates, computes, promotes or lowers "
    "a rating, and scan results never change one."
)


class Soc2Approval(BaseModel):
    """The pinned mapping's approval block, reproduced verbatim."""

    model_config = ConfigDict(extra="allow")

    approved: bool = False
    reviewer_name: str | None = None
    reviewer_role: str | None = None
    approved_at: str | None = None
    decision_reference: str | None = None
    note: str | None = None


class Soc2Identity(BaseModel):
    """The SOC 2 side of the mapping, reproduced verbatim."""

    model_config = ConfigDict(extra="allow")

    framework: str | None = None
    criteria_family: str | None = None
    authoritative_criteria: list[str] = Field(default_factory=list)


class Soc2ReportHeader(BaseModel):
    """Document-level header. Carries the approval state and the disclaimer."""

    mapping_id: str
    mapping_version: str
    mapping_digest: str
    mapping_status: str | None = None
    schema_version: int | None = None
    soc2: Soc2Identity
    benchmark: dict[str, Any] = Field(default_factory=dict)
    source: dict[str, Any] | None = None
    rating_vocabulary: list[str] = Field(default_factory=list)
    approval: Soc2Approval
    approval_pending: bool
    not_a_certification: str = NOT_A_CERTIFICATION
    rating_ownership: str = RATING_OWNERSHIP


class Soc2Provenance(BaseModel):
    """Everything needed to reproduce this document from frozen inputs."""

    scan_id: int
    scan_status: str
    started_at: datetime | None = None
    finished_at: datetime | None = None
    framework: str
    benchmark: str
    benchmark_version: str
    metadata_digest: str | None = None
    policy_corpus_digest: str | None = None
    mapping_id: str | None = None
    mapping_version: str | None = None
    mapping_digest: str | None = None
    correlation_id: str | None = None
    semantics_version: str | None = None
    lifecycle_version: str | None = None
    evidence_version: str | None = None
    connection_snapshot_present: bool = False
    rendered_from: Literal["pinned_mapping_snapshot"] = "pinned_mapping_snapshot"
    generated_at: datetime


class Soc2ControlEvidence(BaseModel):
    """One mapped CIS control as this scan actually found it."""

    control_id: str
    title: str | None = None
    # Whether the scan's pinned benchmark metadata defines this control at all.
    in_benchmark: bool = False
    # Whether the scan holds a result row for it.
    in_scan: bool
    selected: bool | None = None
    # A scan result status, or one of two synthetic ones. ``missing_result`` means
    # the pinned benchmark defines the control but the scan has no row - an
    # integrity gap that stays in the coverage denominator. ``not_in_benchmark``
    # means the mapping cites a control this benchmark never had. Neither is ever
    # a pass, and neither is ever a tenant failure.
    status: str
    reason_code: str | None = None
    automation_status: str | None = None
    # Execution provenance only. Collected tenant payloads are never included.
    provenance: dict[str, Any] | None = None


class Soc2Coverage(BaseModel):
    """Coverage with both terms exposed. Never a bare percentage."""

    mapped_control_count: int
    in_scan_count: int
    # Denominator: mapped controls this scan actually selected.
    applicable_count: int
    # Numerator: of those, the ones that produced passed or failed.
    assessed_count: int
    passed_count: int
    failed_count: int
    indeterminate_count: int
    error_count: int
    not_assessable_count: int
    pending_count: int
    # Controls the pinned benchmark defines but the scan holds no row for. They
    # stay in the denominator: a lost row is unknown, never covered.
    missing_result_count: int = 0
    # Selected-but-unassessed, for readability. Equals applicable - assessed.
    unassessed_count: int
    # Mapped controls the scan did not select, plus mapped controls the pinned
    # benchmark does not contain. Out of scope for this scan, not a gap.
    not_in_scope_count: int
    missing_from_benchmark_count: int
    coverage_percent: float | None = None
    compliance_percent: float | None = None
    assessment_completeness: AssessmentCompleteness
    partial_assessment: bool
    coverage_statement: str


class Soc2ManualEvidence(BaseModel):
    """An approved manual or inherited evidence record, reported separately."""

    record_id: int
    control_id: str
    evidence_source: str
    status: str
    control_owner: str | None = None
    evidence_owner: str | None = None
    collection_period_start: datetime | None = None
    collection_period_end: datetime | None = None
    expires_at: datetime | None = None
    cadence: str | None = None
    reviewed_at: datetime | None = None
    current_revision_number: int = 0
    # Structural, not advisory: manual and inherited assurance is a separate
    # stream and can never raise automated configuration coverage.
    counted_in_automated_coverage: Literal[False] = False


class Soc2Limitations(BaseModel):
    """Residual limitation text, verbatim from the pinned mapping."""

    residual_limitation: str | None = None
    residual_scope: str | None = None


class Soc2PointOfFocus(BaseModel):
    """One point of focus: its owned rating beside what the scan found."""

    point_id: str
    criterion: str
    point_of_focus: str
    configuration_rating: Soc2Rating
    rating_source: Literal["pinned_mapping"] = "pinned_mapping"
    rating_is_computed: Literal[False] = False
    evidence_selector: str | None = None
    selector_resolved: bool = True
    mapped_control_ids: list[str] = Field(default_factory=list)
    automated_evidence: list[Soc2ControlEvidence] = Field(default_factory=list)
    coverage: Soc2Coverage
    manual_residual_evidence: list[Soc2ManualEvidence] = Field(default_factory=list)
    limitations: Soc2Limitations


class Soc2CriterionCoverage(BaseModel):
    """Criterion-level classification, verbatim from the pinned mapping."""

    model_config = ConfigDict(extra="allow")

    criterion: str
    configuration_coverage_classification: str | None = None


class Soc2Totals(BaseModel):
    """Document totals, so a reader can confirm nothing was dropped."""

    points_of_focus_count: int
    unique_mapped_control_ids: int
    rating_counts: dict[str, int] = Field(default_factory=dict)
    criteria_count: int


class Soc2ManualEvidenceStream(BaseModel):
    """Status of the separate manual/inherited evidence stream."""

    available: bool
    approved_record_count: int = 0
    counted_in_automated_coverage: Literal[False] = False
    note: str


class Soc2ReportResponse(BaseModel):
    """The SOC 2 report projection for one scan."""

    scan_id: int
    projection_available: bool
    projection_status: ProjectionStatus
    message: str
    header: Soc2ReportHeader | None = None
    provenance: Soc2Provenance | None = None
    criteria_coverage_summary: list[Soc2CriterionCoverage] = Field(default_factory=list)
    points_of_focus: list[Soc2PointOfFocus] = Field(default_factory=list)
    totals: Soc2Totals | None = None
    manual_evidence_stream: Soc2ManualEvidenceStream | None = None
    # Structural findings against the pinned mapping and pinned metadata.
    # Reported, never acted on: no finding changes a rating or a result.
    mapping_resolution_findings: list[dict[str, str]] = Field(default_factory=list)
