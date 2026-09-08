"""Pydantic contracts for the Phase 8 configuration drift API.

Four things are visible in the contract on purpose, so that no consumer can read
drift as something it is not:

* every response that can carry events also carries ``no_events_means``, the
  fixed sentence that says what an empty event list does and does not prove;
* ``DriftRunRead`` carries ``is_real_time``, ``changes_ratings`` and
  ``counted_in_automated_coverage`` as constant ``False`` — drift is a periodic
  comparison of two completed scans, and it moves no rating, result or score;
* ``DriftEventRead.previous_value`` / ``current_value`` are a closed union of
  short scalars, never ``Any`` and never a mapping, so no route in this API has
  a field that could carry a raw tenant payload;
* there is no rating field anywhere.

The value union mirrors the database CHECKs on ``drift_event``: the schema is a
second, independent refusal rather than the only one.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal, Optional, Union

from pydantic import BaseModel, ConfigDict, Field

# The fixed sentence. It is deliberately a constant rather than per-route prose:
# an empty event list is the single most misreadable thing this API returns.
NO_EVENTS_SENTENCE: str = (
    "Zero events means the compared observations were identical for every "
    "comparable control. It never means the tenant was not changed between "
    "scans, and it never means a control passed."
)

# What drift is, stated once, for report and documentation consumers.
DRIFT_NOT_REAL_TIME: str = (
    "Drift is a periodic comparison of two completed scans against a pinned "
    "baseline. It is not real-time monitoring, not SIEM correlation, and it "
    "changes no rating, result or score."
)

# Longest string an event value may carry. The database rejects anything whose
# JSON text exceeds 120 characters; this is the tighter, earlier refusal.
EVENT_VALUE_MAX = 60

# The only shapes an event value may take. A dict or a list fails every member of
# the union, which is what keeps a raw tenant record out of a drift response.
DriftScalarValue = Union[
    bool, int, Annotated[str, Field(max_length=EVENT_VALUE_MAX)], None
]

# How a scan's drift position is described when it is asked for directly.
# "no_baseline" and "facts_unavailable" are explicit answers rather than an empty
# list, because "nothing to show" and "nothing changed" are not the same claim.
DriftScanStatusCode = Literal[
    "no_baseline",
    "facts_unavailable",
    "not_run",
    "completed",
    "not_comparable",
    "fingerprints_unavailable",
    "event_limit_exceeded",
]


class DriftBaselineCreate(BaseModel):
    """Pin one completed, fact-bearing scan as the comparison point."""

    scan_id: int = Field(ge=1)
    note: Optional[str] = Field(default=None, max_length=500)


class DriftBaselineRead(BaseModel):
    """A baseline and the comparability tuple it was established under.

    ``established_by_user_id`` is deliberately absent: the owning ``user_id`` is
    the field a caller can act on, and the acting account belongs in the audit
    record rather than in every read of the baseline.
    """

    id: int
    user_id: Optional[int] = None
    scan_id: int
    m365_connection_id: Optional[int] = None

    framework: str
    benchmark: str
    version: str

    metadata_digest: str
    policy_corpus_digest: str
    semantics_version: str
    connection_identity_digest: str

    configuration_key: str
    evaluation_key: str
    observation_digest: str

    control_count: int
    factprint_field_count: int

    status: str
    superseded_by_id: Optional[int] = None

    drift_version: str
    retention_policy_version: str
    note: Optional[str] = None

    established_at: datetime
    superseded_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class DriftRunRead(BaseModel):
    """One comparison, including both comparability axes and why."""

    id: int
    baseline_id: int
    baseline_scan_id: Optional[int] = None
    current_scan_id: Optional[int] = None
    user_id: Optional[int] = None

    framework: str
    benchmark: str
    version: str

    status: str
    trigger: str

    configuration_comparable: bool
    evaluation_comparable: bool
    axis_reasons: dict[str, Any]

    baseline_configuration_key: str
    current_configuration_key: str
    baseline_evaluation_key: str
    current_evaluation_key: str

    baseline_observation_digest: Optional[str] = None
    current_observation_digest: Optional[str] = None
    baseline_engine_source_digest: Optional[str] = None
    current_engine_source_digest: Optional[str] = None
    engine_changed: Optional[bool] = None

    controls_compared: int
    controls_skipped: dict[str, Any]

    event_count: int
    event_counts: dict[str, Any]
    event_set_digest: str

    key_id: Optional[str] = None
    drift_version: str
    retention_policy_version: str
    correlation_id: Optional[str] = None

    started_at: datetime
    completed_at: datetime

    # Constant, not derived. A drift run is a periodic comparison; it is not
    # monitoring, it moves no rating, and it is never automated coverage.
    is_real_time: Literal[False] = False
    changes_ratings: Literal[False] = False
    counted_in_automated_coverage: Literal[False] = False
    no_events_means: str = NO_EVENTS_SENTENCE

    model_config = ConfigDict(from_attributes=True)


class DriftEventRead(BaseModel):
    """One observed difference.

    The scan ids, the owning user, the correlation id and the version columns on
    ``drift_event`` are not published here: an event describes what moved, and
    the run it belongs to already carries the identity of the comparison.
    """

    id: int
    drift_run_id: int
    baseline_id: int

    control_id: str
    collector_id: Optional[str] = None

    event_class: str
    change_type: str

    fact_name: Optional[str] = None
    member_ref: Optional[str] = None

    previous_value: DriftScalarValue = None
    current_value: DriftScalarValue = None
    previous_digest: Optional[str] = None
    current_digest: Optional[str] = None

    severity: str
    severity_basis: str
    event_key: str

    detail: Optional[dict[str, Any]] = None
    occurred_at: datetime

    counted_in_automated_coverage: Literal[False] = False

    model_config = ConfigDict(from_attributes=True)


class DriftBaselineList(BaseModel):
    """One page of baselines. There is no total: this API issues no COUNT."""

    items: list[DriftBaselineRead]
    limit: int
    offset: int
    returned: int


class DriftRunList(BaseModel):
    """One page of runs."""

    items: list[DriftRunRead]
    limit: int
    offset: int
    returned: int


class DriftEventList(BaseModel):
    """One page of a run's events, with the run's own status alongside.

    ``run_status`` is carried here because an empty page means one thing on a
    completed run and something entirely different on a run that could not
    compare at all.
    """

    items: list[DriftEventRead]
    limit: int
    offset: int
    returned: int
    run_status: str
    no_events_means: str = NO_EVENTS_SENTENCE


class DriftRunRequest(BaseModel):
    """Ask for one baseline to be re-compared against one scan."""

    baseline_id: int = Field(ge=1)
    scan_id: int = Field(ge=1)


class DriftScanStatus(BaseModel):
    """Where one scan stands with respect to drift."""

    scan_id: int
    drift_available: bool
    status: DriftScanStatusCode
    run: Optional[DriftRunRead] = None
    message: str
    no_events_means: str = NO_EVENTS_SENTENCE


class DriftNotificationRevisionRead(BaseModel):
    """One immutable revision in a notification thread.

    Every field here is a code or a count. There is no control id, fact name,
    member ref, digest or observed value on this model, because there is none on
    the table it reads.
    """

    id: int
    thread_key: str
    scope: str
    revision_number: int
    action: str
    state_after: str
    severity: str
    summary_code: str
    summary_counts: dict[str, Any]
    routing_rule: str
    actor_user_id: Optional[int] = None
    verified_run_id: Optional[int] = None
    note: Optional[str] = None
    occurred_at: datetime

    model_config = ConfigDict(from_attributes=True)


class DriftNotificationThread(BaseModel):
    """The derived current state of one notification thread.

    ``state``, ``current_revision_number`` and ``remediation_evidenced`` are
    derived from the highest-revision row rather than stored, which is why the
    underlying table needs no mutable state column.
    """

    thread_key: str
    scope: str
    baseline_id: int
    drift_run_id: Optional[int] = None
    drift_event_id: Optional[int] = None
    user_id: Optional[int] = None
    severity: str
    summary_code: str
    summary_counts: dict[str, Any]
    routing_rule: str
    state: str
    current_revision_number: int
    remediation_evidenced: bool
    raised_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class DriftNotificationThreadWithHistory(DriftNotificationThread):
    """A thread together with its full append-only history."""

    revisions: list[DriftNotificationRevisionRead] = Field(default_factory=list)


class DriftNotificationAcknowledge(BaseModel):
    """Acknowledge a thread. The note is optional; acknowledging is not a claim."""

    note: Optional[str] = Field(default=None, max_length=1000)


class DriftNotificationRemediation(BaseModel):
    """Plan remediation, or accept the risk. Either way, say why."""

    state: Literal["remediation_planned", "accepted_risk"]
    note: str = Field(min_length=1, max_length=1000)


class DriftNotificationVerify(BaseModel):
    """Name the later scan whose run is offered as evidence of remediation."""

    scan_id: int = Field(ge=1)
