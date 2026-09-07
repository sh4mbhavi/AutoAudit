"""Pydantic contracts for the Phase 7 manual / inherited evidence workflow.

Two things are visible in the contract on purpose:

* ``assurance_stream`` and ``affects_automated_score`` are constants on every
  read model, so no consumer can mistake approved manual evidence for automated
  configuration coverage;
* there is no rating field anywhere. Ratings are human-owned GRC data and this
  API neither stores, infers nor promotes one.
"""

from datetime import datetime, timezone
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.models.manual_evidence import (
    MANUAL_EVIDENCE_TEXT_MAX,
    ManualEvidenceRecord,
)

EvidenceSource = Literal["manual", "inherited"]
Cadence = Literal["ad_hoc", "monthly", "quarterly", "semiannual", "annual"]
RecordStatus = Literal[
    "draft", "submitted", "approved", "rejected", "withdrawn", "expired"
]
RevisionAction = Literal[
    "created", "amended", "submitted", "approved", "rejected", "withdrawn", "expired"
]

MAX_ATTACHMENTS = 50
MAX_EXTERNAL_REFERENCES = 25


class ExternalReference(BaseModel):
    """Evidence held outside AutoAudit, pointed at rather than stored."""

    label: str = Field(min_length=1, max_length=200)
    uri: Optional[str] = Field(default=None, max_length=2000)
    note: Optional[str] = Field(default=None, max_length=MANUAL_EVIDENCE_TEXT_MAX)

    @field_validator("label", "uri", "note", mode="before")
    @classmethod
    def _strip(cls, value: Any) -> Any:
        if isinstance(value, str):
            stripped = value.strip()
            return stripped or None
        return value

    @field_validator("uri")
    @classmethod
    def _supported_uri(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        scheme, separator, remainder = value.partition("://")
        if not separator or scheme.lower() not in {"http", "https"}:
            raise ValueError("External reference URIs must be http or https")
        if "@" in remainder.split("/", 1)[0]:
            raise ValueError("External reference URIs must not embed credentials")
        return value


def _as_utc(value: Optional[datetime]) -> Optional[datetime]:
    """Assume UTC for a naive timestamp so comparisons are always possible."""
    if value is None:
        return None
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


class _EvidenceSetMixin(BaseModel):
    attachment_object_ids: list[str] = Field(
        default_factory=list, max_length=MAX_ATTACHMENTS
    )
    external_references: list[ExternalReference] = Field(
        default_factory=list, max_length=MAX_EXTERNAL_REFERENCES
    )

    @field_validator("attachment_object_ids")
    @classmethod
    def _opaque_object_ids(cls, value: list[str]) -> list[str]:
        for object_id in value:
            if not 8 <= len(object_id) <= 43 or not all(
                character.isalnum() or character in "-_" for character in object_id
            ):
                raise ValueError("Attachments are referenced by opaque object id")
        return value


class _PeriodMixin(BaseModel):
    collection_period_start: Optional[datetime] = None
    collection_period_end: Optional[datetime] = None

    @model_validator(mode="after")
    def _ordered_period(self):
        # Compare on one timeline: a mixed aware/naive pair would otherwise
        # raise TypeError, which Pydantic does not turn into a 422.
        start = _as_utc(self.collection_period_start)
        end = _as_utc(self.collection_period_end)
        if start and end and start > end:
            raise ValueError("The collection period ends before it starts")
        return self


class ManualEvidenceCreate(_EvidenceSetMixin, _PeriodMixin):
    """Open a draft against a scan result the caller owns."""

    scan_result_id: int
    evidence_source: EvidenceSource = "manual"
    control_owner: Optional[str] = Field(default=None, max_length=200)
    evidence_owner: Optional[str] = Field(default=None, max_length=200)
    expires_at: Optional[datetime] = None
    cadence: Optional[Cadence] = None
    comment: Optional[str] = Field(default=None, max_length=MANUAL_EVIDENCE_TEXT_MAX)


class ManualEvidenceAmend(_EvidenceSetMixin, _PeriodMixin):
    """Replace the working evidence set with a brand new revision."""

    control_owner: Optional[str] = Field(default=None, max_length=200)
    evidence_owner: Optional[str] = Field(default=None, max_length=200)
    expires_at: Optional[datetime] = None
    cadence: Optional[Cadence] = None
    comment: Optional[str] = Field(default=None, max_length=MANUAL_EVIDENCE_TEXT_MAX)


class ManualEvidenceComment(BaseModel):
    """Optional narrative attached to a transition."""

    comment: Optional[str] = Field(default=None, max_length=MANUAL_EVIDENCE_TEXT_MAX)


class ManualEvidenceReject(BaseModel):
    """A rejection must say why; the database enforces this too."""

    reason: str = Field(min_length=1, max_length=MANUAL_EVIDENCE_TEXT_MAX)
    comment: Optional[str] = Field(default=None, max_length=MANUAL_EVIDENCE_TEXT_MAX)

    @field_validator("reason")
    @classmethod
    def _non_blank(cls, value: str) -> str:
        reason = value.strip()
        if not reason:
            raise ValueError("A rejection must state a reason")
        return reason


class ManualEvidenceRevisionRead(BaseModel):
    """One immutable entry in the decision history."""

    id: int
    record_id: int
    revision_number: int
    action: RevisionAction
    status_after: RecordStatus
    actor_user_id: Optional[int]
    actor_role: str
    comment: Optional[str]
    rejection_reason: Optional[str]
    attachment_object_ids: list[str] = Field(default_factory=list)
    external_references: list[dict[str, Any]] = Field(default_factory=list)
    evidence_sha256: Optional[str]
    provenance: Optional[dict[str, Any]]
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

    @field_validator("attachment_object_ids", "external_references", mode="before")
    @classmethod
    def _null_is_empty(cls, value: Any) -> Any:
        return value if value is not None else []


class ManualEvidenceRead(BaseModel):
    """Current state of a record. Deliberately carries no rating and no result."""

    id: int
    scan_id: int
    scan_result_id: int
    control_id: str
    user_id: int
    control_owner: Optional[str]
    evidence_owner: Optional[str]
    evidence_source: EvidenceSource
    status: RecordStatus
    reviewer_user_id: Optional[int]
    reviewed_at: Optional[datetime]
    collection_period_start: Optional[datetime]
    collection_period_end: Optional[datetime]
    expires_at: Optional[datetime]
    cadence: Optional[str]
    retention_policy_version: str
    current_revision_number: int
    created_at: datetime
    updated_at: datetime

    # Constant, not derived: manual evidence is a separate residual stream and
    # approving it never moves an automated control or either score.
    assurance_stream: Literal["manual_residual"] = "manual_residual"
    affects_automated_score: Literal[False] = False

    model_config = ConfigDict(from_attributes=True)

    @classmethod
    def from_record(cls, record: ManualEvidenceRecord) -> "ManualEvidenceRead":
        return cls.model_validate(record)


class ManualEvidenceWithHistory(ManualEvidenceRead):
    """A record together with its full append-only history."""

    revisions: list[ManualEvidenceRevisionRead] = Field(default_factory=list)


class ManualControlTemplateRead(BaseModel):
    """Read-only auditor instructions shipped with a benchmark version."""

    framework: str
    benchmark: str
    version: str
    control_id: str
    title: Optional[str] = None
    severity: Optional[str] = None
    evidence_type: Optional[str] = None
    keywords: list[str] = Field(default_factory=list)
    instructions: Optional[str] = None

    @field_validator("keywords", mode="before")
    @classmethod
    def _keywords_list(cls, value: Any) -> Any:
        if value is None:
            return []
        if isinstance(value, list):
            return [str(item) for item in value]
        return [str(value)]
