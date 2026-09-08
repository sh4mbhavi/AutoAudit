"""Pydantic schemas for compliance scans."""

from datetime import datetime
from decimal import Decimal
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

ResultStatus = Literal[
    "pending", "passed", "failed", "indeterminate", "error", "skipped", "not_assessable"
]


class ScanCreate(BaseModel):
    """Schema for creating a new scan."""

    m365_connection_id: int = Field(
        ..., description="ID of the M365 connection to scan"
    )
    framework: str = Field(
        ..., min_length=1, max_length=50, description="Framework (e.g., 'cis')"
    )
    benchmark: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Benchmark slug (e.g., 'microsoft-365-foundations')",
    )
    version: str = Field(
        ..., min_length=1, max_length=20, description="Version (e.g., 'v3.1.0')"
    )
    control_ids: list[str] | None = Field(
        None, description="Specific control IDs to scan (null = all)"
    )


class ScanResultRead(BaseModel):
    """Schema for reading scan result details."""

    id: int
    scan_id: int
    control_id: str
    status: ResultStatus
    selected: bool | None = None
    reason_code: str | None = None
    provenance: dict | None = None
    message: str | None
    evidence: dict | None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ScanRead(BaseModel):
    """Schema for reading scan details."""

    id: int
    user_id: int
    m365_connection_id: int | None
    connection_name: str | None = None
    azure_connection_id: int | None
    gcp_connection_id: int | None
    aws_connection_id: int | None
    framework: str
    benchmark: str
    version: str
    status: str
    started_at: datetime
    finished_at: datetime | None
    compliance_score: Decimal | None
    total_controls: int
    passed_count: int
    failed_count: int
    skipped_count: int
    error_count: int
    pending_count: int = 0
    indeterminate_count: int = 0
    not_assessable_count: int = 0
    selected_count: int | None = None
    coverage_score: Decimal | None = None
    semantics_version: str | None = None
    metadata_digest: str | None = None
    correlation_id: str | None = None
    dispatch_id: str | None = None
    dispatch_count: int = 0
    last_progress_at: datetime | None = None
    deadline_at: datetime | None = None
    lifecycle_version: str | None = None
    # Phase 7 pin. Scalars only: the metadata and mapping snapshots are large and
    # are reported through GET /scans/{id}/provenance and the SOC 2 report.
    mapping_id: str | None = None
    mapping_version: str | None = None
    mapping_digest: str | None = None
    policy_corpus_digest: str | None = None
    evidence_version: str | None = None
    notes: str | None
    results: list[ScanResultRead] | None = None

    model_config = ConfigDict(from_attributes=True)


class ScanListItem(BaseModel):
    """Schema for scan list items (abbreviated)."""

    id: int
    user_id: int
    m365_connection_id: int | None
    connection_name: str | None = None
    framework: str
    benchmark: str
    version: str
    status: str
    started_at: datetime
    finished_at: datetime | None
    compliance_score: Decimal | None
    total_controls: int
    passed_count: int
    failed_count: int
    skipped_count: int
    error_count: int
    pending_count: int = 0
    indeterminate_count: int = 0
    not_assessable_count: int = 0
    selected_count: int | None = None
    coverage_score: Decimal | None = None
    semantics_version: str | None = None
    metadata_digest: str | None = None
    correlation_id: str | None = None
    dispatch_id: str | None = None
    dispatch_count: int = 0
    last_progress_at: datetime | None = None
    deadline_at: datetime | None = None
    lifecycle_version: str | None = None
    # Phase 7 pin. Scalars only: the metadata and mapping snapshots are large and
    # are reported through GET /scans/{id}/provenance and the SOC 2 report.
    mapping_id: str | None = None
    mapping_version: str | None = None
    mapping_digest: str | None = None
    policy_corpus_digest: str | None = None
    evidence_version: str | None = None

    model_config = ConfigDict(from_attributes=True)


class ScanCreatedResponse(BaseModel):
    """Response schema for scan creation."""

    id: int
    status: str
    message: str


class ControlCategoryBreakdown(BaseModel):
    """Pass/fail counts grouped by control category prefix."""

    category: str
    total: int
    passed: int
    failed: int
    skipped: int
    error: int
    pending: int = 0
    indeterminate: int = 0
    not_assessable: int = 0


class ScanSummary(BaseModel):
    """Lightweight scan summary without full result detail."""

    id: int
    status: str
    framework: str
    benchmark: str
    version: str
    started_at: datetime
    finished_at: datetime | None
    compliance_score: Decimal | None
    total_controls: int
    passed_count: int
    failed_count: int
    skipped_count: int
    error_count: int
    pending_count: int = 0
    indeterminate_count: int = 0
    not_assessable_count: int = 0
    selected_count: int | None = None
    coverage_score: Decimal | None = None
    semantics_version: str | None = None
    metadata_digest: str | None = None
    correlation_id: str | None = None
    dispatch_id: str | None = None
    dispatch_count: int = 0
    last_progress_at: datetime | None = None
    deadline_at: datetime | None = None
    lifecycle_version: str | None = None
    # Phase 7 pin. Scalars only: the metadata and mapping snapshots are large and
    # are reported through GET /scans/{id}/provenance and the SOC 2 report.
    mapping_id: str | None = None
    mapping_version: str | None = None
    mapping_digest: str | None = None
    policy_corpus_digest: str | None = None
    evidence_version: str | None = None
    categories: list[ControlCategoryBreakdown]

    model_config = ConfigDict(from_attributes=True)


class ScanProvenanceRead(BaseModel):
    """Everything a scan froze at creation, minus the snapshots themselves.

    The metadata and mapping snapshots are far too large for a list response and
    are not returned here either. Their digests, presence and shape are, which
    is what a reader needs to decide whether two scans are comparable.
    """

    scan_id: int
    status: str
    framework: str
    benchmark: str
    version: str
    started_at: datetime
    finished_at: datetime | None = None

    semantics_version: str | None = None
    lifecycle_version: str | None = None
    evidence_version: str | None = None
    correlation_id: str | None = None
    dispatch_id: str | None = None
    selected_count: int | None = None
    total_controls: int = 0

    metadata_digest: str | None = None
    metadata_snapshot_present: bool = False
    metadata_control_count: int = 0
    policy_corpus_digest: str | None = None

    # Presence and field names only; no tenant or client identifier is returned.
    connection_snapshot_present: bool = False
    connection_snapshot_fields: list[str] = Field(default_factory=list)

    mapping_id: str | None = None
    mapping_version: str | None = None
    mapping_digest: str | None = None
    mapping_snapshot_present: bool = False
    mapping_status: str | None = None
    # Straight from the pinned mapping's approval block. Never inferred.
    mapping_approved: bool = False
    mapping_points_of_focus_count: int = 0
    soc2_projection_available: bool = False

    model_config = ConfigDict(from_attributes=True)


class ScanReadinessCheck(BaseModel):
    """Individual readiness check result."""

    key: str
    label: str
    status: str  # pass, fail, warn
    severity: str  # critical, warning
    message: str


class ScanReadinessResponse(BaseModel):
    """Pre-scan readiness result."""

    ready: bool
    summary: str
    required_permissions: list[str]
    missing_permissions: list[str]
    unverified_permissions: list[str]
    checks: list[ScanReadinessCheck]
