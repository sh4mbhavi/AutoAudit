"""Phase 8 drift ORM models and API schemas.

These assertions are deliberately structural. Every one of them fails if the
models stop mirroring migration a3f5c1d90b47, if a Phase 8 datetime column
quietly loses its timezone, if an evidence-bearing column appears on the
notification table, or if a drift response gains a field that could carry a raw
tenant payload.

Nothing here needs a database: the point is that the declarations themselves are
checkable.
"""

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

import pytest
import sqlalchemy as sa
from pydantic import ValidationError

import app.models as models
from app.models.drift import (
    BASELINE_STATUSES,
    COMPARABILITY_REASONS,
    CONFIGURATION_CHANGE_TYPES,
    EVALUATION_CHANGE_TYPES,
    EVENT_CLASSES,
    FIELD_KINDS,
    FORBIDDEN_NOTIFICATION_COLUMNS,
    NOTIFICATION_ACTIONS,
    NOTIFICATION_STATES,
    ROUTING_RULES,
    RUN_STATUSES,
    RUN_TRIGGERS,
    SEVERITIES,
    SEVERITY_BASES,
    DriftBaseline,
    DriftEvent,
    DriftNotification,
    DriftRun,
)
from app.models.scan_result_factprint import ScanResultFactprint
from app.schemas.drift import (
    DRIFT_NOT_REAL_TIME,
    NO_EVENTS_SENTENCE,
    DriftEventList,
    DriftEventRead,
    DriftRunRead,
    DriftScanStatus,
)

BACKEND = Path(__file__).resolve().parents[1]
MIGRATION_PATH = (
    BACKEND
    / "alembic"
    / "versions"
    / "a3f5c1d90b47_phase8_drift_and_compliance_binding.py"
)

PHASE8_MODELS = (
    ScanResultFactprint,
    DriftBaseline,
    DriftRun,
    DriftEvent,
    DriftNotification,
)

PHASE8_MODEL_NAMES = (
    "ScanResultFactprint",
    "DriftBaseline",
    "DriftRun",
    "DriftEvent",
    "DriftNotification",
)

# The sentence, written out once here as an independent literal. If the schema
# constant is ever reflowed into something that reads the same but is not the
# same bytes, this is what catches it.
EXPECTED_NO_EVENTS_SENTENCE = "Zero events means the compared observations were identical for every comparable control. It never means the tenant was not changed between scans, and it never means a control passed."  # noqa: E501

EXPECTED_NOT_REAL_TIME = "Drift is a periodic comparison of two completed scans against a pinned baseline. It is not real-time monitoring, not SIEM correlation, and it changes no rating, result or score."  # noqa: E501

# Every Phase 8 datetime column, listed rather than discovered, so a column that
# quietly loses its timezone cannot also quietly leave the list.
EXPECTED_DATETIME_COLUMNS = {
    ("scan_result_factprint", "recorded_at"),
    ("drift_baseline", "established_at"),
    ("drift_baseline", "superseded_at"),
    ("drift_run", "started_at"),
    ("drift_run", "completed_at"),
    ("drift_event", "occurred_at"),
    ("drift_notification", "occurred_at"),
}

OCCURRED = datetime(2026, 9, 6, 12, 0, tzinfo=timezone.utc)


def _event_payload(**overrides):
    """A complete, valid DriftEventRead payload, so a case tests one field."""
    payload = {
        "id": 1,
        "drift_run_id": 2,
        "baseline_id": 3,
        "control_id": "3.2.2",
        "collector_id": "compliance.dlp.policies",
        "event_class": "configuration",
        "change_type": "changed",
        "fact_name": "teams_policy_enabled",
        "member_ref": None,
        "previous_value": False,
        "current_value": True,
        "previous_digest": None,
        "current_digest": None,
        "severity": "high",
        "severity_basis": "benchmark_severity",
        "event_key": "0" * 64,
        "detail": {"facts_identical": False},
        "occurred_at": OCCURRED,
    }
    payload.update(overrides)
    return payload


def _run_payload(**overrides):
    """A complete, valid DriftRunRead payload."""
    payload = {
        "id": 5,
        "baseline_id": 3,
        "baseline_scan_id": 301,
        "current_scan_id": 302,
        "user_id": 101,
        "framework": "cis",
        "benchmark": "microsoft-365-foundations",
        "version": "v6.0.0",
        "status": "completed",
        "trigger": "scan_finalised",
        "configuration_comparable": True,
        "evaluation_comparable": True,
        "axis_reasons": {"configuration": [], "evaluation": []},
        "baseline_configuration_key": "1" * 64,
        "current_configuration_key": "1" * 64,
        "baseline_evaluation_key": "2" * 64,
        "current_evaluation_key": "2" * 64,
        "baseline_observation_digest": "3" * 64,
        "current_observation_digest": "4" * 64,
        "baseline_engine_source_digest": None,
        "current_engine_source_digest": None,
        "engine_changed": None,
        "controls_compared": 44,
        "controls_skipped": {},
        "event_count": 0,
        "event_counts": {"configuration": {}, "evaluation": {}},
        "event_set_digest": "5" * 64,
        "key_id": "k0000000",
        "drift_version": "phase8-drift-v1",
        "retention_policy_version": "phase8-draft-1",
        "correlation_id": None,
        "started_at": OCCURRED,
        "completed_at": OCCURRED,
    }
    payload.update(overrides)
    return payload


def test_models_are_registered():
    """alembic/env.py sees Phase 8 tables only through `import app.models`."""
    for name, model in zip(PHASE8_MODEL_NAMES, PHASE8_MODELS):
        assert name in models.__all__, name
        assert getattr(models, name) is model, name


def test_every_phase8_datetime_column_declares_timezone():
    """No Phase 8 column repeats the Phase 6 naive-timestamp defect."""
    seen = set()
    for model in PHASE8_MODELS:
        table = model.__table__
        for column in table.columns:
            if isinstance(column.type, sa.DateTime):
                seen.add((table.name, column.name))
                assert column.type.timezone is True, f"{table.name}.{column.name}"
    assert seen == EXPECTED_DATETIME_COLUMNS


def test_notification_model_has_no_evidence_column():
    """The no-leak guarantee is the table's shape, not a review."""
    columns = set(DriftNotification.__table__.columns.keys())
    assert columns & set(FORBIDDEN_NOTIFICATION_COLUMNS) == set()
    # The guard is only meaningful while it names columns that exist elsewhere.
    event_columns = set(DriftEvent.__table__.columns.keys())
    assert event_columns & set(FORBIDDEN_NOTIFICATION_COLUMNS)


def _migration_text():
    return MIGRATION_PATH.read_text(encoding="utf-8")


def _declared_check_names():
    names = set()
    for model in PHASE8_MODELS:
        for constraint in model.__table__.constraints:
            if isinstance(constraint, sa.CheckConstraint) and constraint.name:
                names.add(constraint.name)
    return names


def _declared_index_names():
    names = set()
    for model in PHASE8_MODELS:
        for index in model.__table__.indexes:
            names.add(index.name)
    return names


def test_check_constraint_names_match_the_migration():
    """Both directions.

    A model constraint the migration never created would never be enforced; a
    migration constraint the models do not declare makes a future autogenerate
    diff propose dropping it.
    """
    migration = _migration_text()
    declared = _declared_check_names()
    assert declared, "no ck_ names were declared on the Phase 8 models"
    in_migration = set(re.findall(r'name="(ck_[a-z0-9_]+)"', migration))
    assert declared == in_migration

    # The uq_ names are created as unique indexes rather than constraints, so
    # they are checked here too rather than falling between the two tests.
    unique_indexes = {
        name for name in _declared_index_names() if name.startswith("uq_")
    }
    assert unique_indexes
    for name in unique_indexes:
        assert f'"{name}"' in migration, name


def test_index_names_match_the_migration():
    """Same argument for the plain indexes: a model-only index is a fiction."""
    migration = _migration_text()
    declared = _declared_index_names()
    in_migration = set(re.findall(r'op\.create_index\(\s*"([a-z0-9_]+)"', migration))
    assert declared == in_migration


def test_drift_event_read_rejects_object_values():
    """No drift response field can carry a raw tenant payload."""
    for field in ("previous_value", "current_value"):
        for rejected in ({"a": 1}, [1], {"policy": {"name": "x"}}):
            with pytest.raises(ValidationError) as error:
                DriftEventRead(**_event_payload(**{field: rejected}))
            assert field in str(error.value)


def test_drift_event_read_bounds_string_values():
    """The schema refuses before the database CHECK ever has to."""
    accepted = DriftEventRead(**_event_payload(previous_value="a" * 60))
    assert accepted.previous_value == "a" * 60
    with pytest.raises(ValidationError):
        DriftEventRead(**_event_payload(previous_value="a" * 61))


def test_drift_event_read_accepts_the_declared_scalars():
    """bool, int, str and None are the whole vocabulary."""
    for value in (True, False, 0, 7, "Enable", None):
        event = DriftEventRead(**_event_payload(current_value=value))
        assert event.current_value == value
        assert event.counted_in_automated_coverage is False


def test_no_events_sentence_is_the_fixed_string():
    """Byte-exact, on the constant and on every default that publishes it."""
    assert NO_EVENTS_SENTENCE == EXPECTED_NO_EVENTS_SENTENCE
    assert DRIFT_NOT_REAL_TIME == EXPECTED_NOT_REAL_TIME
    for model in (DriftRunRead, DriftEventList, DriftScanStatus):
        default = model.model_fields["no_events_means"].default
        assert default == EXPECTED_NO_EVENTS_SENTENCE, model.__name__

    run = DriftRunRead(**_run_payload())
    assert run.no_events_means == EXPECTED_NO_EVENTS_SENTENCE
    assert run.is_real_time is False
    assert run.changes_ratings is False
    assert run.counted_in_automated_coverage is False

    events = DriftEventList(
        items=[], limit=50, offset=0, returned=0, run_status="completed"
    )
    assert events.no_events_means == EXPECTED_NO_EVENTS_SENTENCE

    status = DriftScanStatus(
        scan_id=302,
        drift_available=True,
        status="completed",
        run=run,
        message="Compared against the active baseline.",
    )
    assert status.no_events_means == EXPECTED_NO_EVENTS_SENTENCE


def test_vocabularies_are_declared_once_with_the_agreed_tokens():
    """B4 and B6 read these tuples rather than restating the vocabulary."""
    assert BASELINE_STATUSES == ("active", "superseded", "revoked")
    assert RUN_STATUSES == (
        "completed",
        "not_comparable",
        "fingerprints_unavailable",
        "event_limit_exceeded",
    )
    assert RUN_TRIGGERS == ("scan_finalised", "api_request")
    assert EVENT_CLASSES == ("configuration", "evaluation")
    assert CONFIGURATION_CHANGE_TYPES == ("added", "removed", "changed")
    assert EVALUATION_CHANGE_TYPES == (
        "status_changed",
        "coverage_lost",
        "coverage_gained",
    )
    assert SEVERITIES == ("critical", "high", "medium", "low", "informational")
    assert SEVERITY_BASES == (
        "benchmark_severity",
        "evaluation_transition",
        "coverage_loss",
        "observability_change",
        "severity_unavailable",
    )
    assert NOTIFICATION_ACTIONS == (
        "raised",
        "acknowledged",
        "remediation_planned",
        "remediation_verified",
        "accepted_risk",
        "superseded",
    )
    assert NOTIFICATION_STATES == (
        "open",
        "acknowledged",
        "remediation_planned",
        "remediation_verified",
        "accepted_risk",
        "superseded",
    )
    assert ROUTING_RULES == (
        "owner_high_or_above",
        "owner_coverage_loss",
        "owner_not_comparable",
        "owner_fingerprints_unavailable",
        "owner_action",
    )
    assert FIELD_KINDS == ("bool", "int", "enum", "enum_set")
    assert COMPARABILITY_REASONS == (
        "baseline_not_active",
        "scan_not_completed",
        "scan_not_owned",
        "scan_predates_baseline",
        "configuration_key_mismatch",
        "evaluation_key_mismatch",
        "semantics_version_mismatch",
        "fingerprints_unavailable",
        "baseline_facts_absent",
        "current_facts_absent",
        "drift_version_mismatch",
        # A rotated fingerprint key changes every value_digest, so the
        # configuration axis cannot compare across it. Recorded as a reason
        # rather than reported as drift against an untouched tenant.
        "fingerprint_key_rotated",
    )


def test_every_vocabulary_token_is_named_by_the_migration_checks():
    """A tuple that drifts from its CHECK constraint would be a silent lie."""
    migration = MIGRATION_PATH.read_text(encoding="utf-8")
    constrained = (
        BASELINE_STATUSES
        + RUN_STATUSES
        + RUN_TRIGGERS
        + EVENT_CLASSES
        + CONFIGURATION_CHANGE_TYPES
        + EVALUATION_CHANGE_TYPES
        + SEVERITIES
        + SEVERITY_BASES
        + NOTIFICATION_ACTIONS
        + NOTIFICATION_STATES
        + ROUTING_RULES
        + FIELD_KINDS
    )
    for token in constrained:
        assert f"'{token}'" in migration, token


def test_no_drift_schema_carries_a_rating_or_a_score():
    """Drift reports. It never creates, promotes, infers or alters a rating.

    The three constant disclaimer fields are the only ones allowed to mention a
    rating or coverage, and they are checked here to be immovably ``False``
    rather than merely named.
    """
    import app.schemas.drift as drift_schemas

    disclaimers = {
        "is_real_time",
        "changes_ratings",
        "counted_in_automated_coverage",
    }
    forbidden = ("rating", "score", "compliant", "pass_", "passed")
    for name in dir(drift_schemas):
        candidate = getattr(drift_schemas, name)
        fields = getattr(candidate, "model_fields", None)
        if not isinstance(fields, dict):
            continue
        for field_name, field in fields.items():
            if field_name in disclaimers:
                assert field.annotation is Literal[False], f"{name}.{field_name}"
                assert field.default is False, f"{name}.{field_name}"
                continue
            assert not any(
                token in field_name for token in forbidden
            ), f"{name}.{field_name}"
