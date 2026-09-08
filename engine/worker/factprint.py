"""Declared scalar projections of collector output, canonicalised and keyed.

What this module persists is a DECLARED PROJECTION of a collector's output, never
the raw collector payload. ``FACT_PROJECTIONS`` names, per collector, a small set
of bool / int / enum / enum_set fields. Every declared field name is a top-level
key that the collector's existing Phase 4 contract fixture already produces
(``engine/tests/test_phase4_collector_contracts.py``), so no persisted field name
is guessed, and ``test_every_declared_field_exists_in_the_phase4_contract_fixture``
keeps that true.

Digesting a whole top-level key is FORBIDDEN and ``FORBIDDEN_SOURCE_KEYS`` is
checked against the declared field names at import time. Several collectors return
the raw provider object alongside the scalars they derive from it
(``organization_config.py:51``, ``sharepoint/pnp/tenant.py:41``); a digest of such
a key changes on every unrelated tenant edit and produces pure noise rather than
drift.

THE KEY IS THE GATE. There is no boolean feature flag. ``fingerprint_key()``
returns ``None`` when ``DRIFT_FACT_HMAC_KEY`` is absent, undecodable, or shorter
than 32 bytes once decoded, and ``project_facts()`` then returns ``None`` so that
ZERO rows are written. There is never a fallback to an unkeyed digest: an unkeyed
digest of a low-entropy value — a boolean, a small enum, a display name, a domain
— is a lookup table, not a pseudonym. For the same reason the member_ref is
included in the preimage of every enum_set value digest, so guessing a
configuration value does not confirm it without the key.

COLLECTOR-CONTRACT OBLIGATION (canonicalisation discards ordering).
``canonical_sorted`` sorts lists at EVERY depth, unlike
``provenance.canonical_digest`` which sorts dict keys but preserves list order.
That is deliberate: Graph returns collections in a non-deterministic order and
preserving it would report false drift on every scan. The cost is real and is
stated here rather than glossed: LIST ORDER IS DISCARDED. A collector must never
encode meaning in list position; if it does, it must not declare a projection.
No projection in v1 declares a list-valued field, so no collector is relying on
ordering today.
"""

import base64
import binascii
import hashlib
import hmac
import json
import logging
import re
from dataclasses import dataclass

from sqlalchemy import text
from sqlalchemy.orm import Session

from worker.config import settings

logger = logging.getLogger(__name__)

FACTPRINT_SCHEMA = "phase8-factprint-v1"
RETENTION_POLICY_VERSION = "phase8-draft-1"

# Domain separation strings. \x1f is the ASCII unit separator; every part is UTF-8.
MEMBER_DOMAIN = b"autoaudit.factmember.v1"
VALUE_DOMAIN = b"autoaudit.factprint.v1"
KEY_ID_DOMAIN = b"autoaudit.factprint.keyid.v1"
# Every digest is produced under a per-tenant subkey derived from the configured
# key. Without this, two tenants holding the same configuration produce the same
# digest under a server-wide key, so anyone holding the store could bucket tenants
# by configuration and -- controlling one tenant -- confirm another's values. That
# is the confirmation oracle this module exists to prevent.
TENANT_KEY_DOMAIN = b"autoaudit.factprint.tenant.v1"
UNIT = b"\x1f"

MINIMUM_KEY_BYTES = 32
FIELD_KINDS = ("bool", "int", "enum", "enum_set")
# An enum token the declared vocabulary does not contain. Never invented, never
# dropped: an unrecognised token is evidence that the tenant returned something
# the licensed procedure does not name.
UNRECOGNISED = "unrecognised"
# observed_value is stored as JSON text bounded at 40 characters by
# ck_factprint_value_length; a quoted token therefore fits in 38.
MAX_ENUM_TOKEN_LENGTH = 38

# ck_factprint_field_name in the Phase 8 migration.
FIELD_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,39}$")
HEX_KEY_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")

# Top-level collector keys that carry the raw provider object. No projection may
# name one of these; enforced below against every declared field name.
FORBIDDEN_SOURCE_KEYS = frozenset(
    {
        "organization_config",
        "tenant",
        "teams_protection_policy",
        "atp_policy",
        "transport_config",
        "external_in_outlook_settings",
        "safe_links_policies",
        "anti_phish_policies",
    }
)


@dataclass(frozen=True)
class FieldSpec:
    """One declared scalar field of a collector's output."""

    name: str
    kind: str
    vocabulary: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.kind not in FIELD_KINDS:
            raise ValueError("Unsupported factprint field kind")
        if not FIELD_NAME_PATTERN.fullmatch(self.name):
            raise ValueError("Factprint field name violates the column constraint")
        if self.name in FORBIDDEN_SOURCE_KEYS:
            raise ValueError("A raw collector object key may not be projected")
        if self.kind in {"bool", "int"} and self.vocabulary:
            raise ValueError("Only enum kinds carry a vocabulary")
        if self.kind in {"enum", "enum_set"} and not self.vocabulary:
            raise ValueError("An enum kind requires a declared vocabulary")
        for token in self.vocabulary:
            if not token or token != token.lower() or token == UNRECOGNISED:
                raise ValueError("Vocabulary tokens are lowercase and not reserved")
            # ck_factprint_value_length bounds observed_value's JSON text at 40
            # characters; keeping tokens shorter makes that constraint unreachable
            # rather than a runtime surprise on some tenant's return value.
            if len(token) > MAX_ENUM_TOKEN_LENGTH:
                raise ValueError("Vocabulary token exceeds the column constraint")


@dataclass(frozen=True)
class Projection:
    """The declared projection of a single collector."""

    projection_id: str
    fields: tuple[FieldSpec, ...]

    def __post_init__(self) -> None:
        names = [spec.name for spec in self.fields]
        if not names or len(names) != len(set(names)):
            raise ValueError("A projection declares distinct fields")


def _projection(collector_id: str, *fields: FieldSpec) -> tuple[str, Projection]:
    return collector_id, Projection(f"{collector_id}/v1", fields)


# v1. No compliance.* projection ships: 3.2.1 / 3.2.2 / 3.3.1 stay blocked and are
# never dispatched, so this module has zero coupling to Wave A. No enum or enum_set
# field ships either; both kinds are fully implemented and are exercised against a
# synthetic Projection declared inside the test module.
FACT_PROJECTIONS: dict[str, Projection] = dict(
    (
        _projection(
            "entra.roles.cloud_only_admins",
            FieldSpec("cloud_only_admin_count", "int"),
        ),
        _projection(
            "entra.roles.privileged_roles",
            FieldSpec("global_admin_count", "int"),
        ),
        _projection(
            "entra.groups.groups",
            FieldSpec("public_groups_count", "int"),
        ),
        _projection(
            "entra.domains.password_policy",
            FieldSpec("managed_domains_count", "int"),
        ),
        _projection(
            "entra.applications.apps_and_services_settings",
            FieldSpec("user_owned_apps_enabled", "bool"),
        ),
        _projection(
            "entra.devices.enrollment_restrictions",
            FieldSpec("total_configurations", "int"),
        ),
        _projection(
            "entra.policies.authorization_policy",
            FieldSpec("allowed_to_create_apps", "bool"),
        ),
        _projection(
            "entra.policies.admin_consent_request_policy",
            FieldSpec("is_enabled", "bool"),
        ),
        _projection(
            "entra.policies.b2b_policy",
            FieldSpec("partners_count", "int"),
        ),
        _projection(
            "entra.conditional_access.legacy_auth_block",
            FieldSpec("total_policies", "int"),
        ),
        _projection(
            "entra.authentication.mfa_fatigue_protection",
            FieldSpec("number_matching_enabled", "bool"),
        ),
        _projection(
            "entra.authentication.password_protection",
            FieldSpec("banned_password_list_enabled", "bool"),
        ),
        _projection(
            "entra.authentication.mfa_registration_report",
            FieldSpec("mfa_capable_count", "int"),
        ),
        _projection(
            "entra.authentication.authentication_methods",
            FieldSpec("sms_enabled", "bool"),
        ),
        _projection(
            "exchange.organization.organization_config",
            FieldSpec("audit_disabled", "bool"),
            FieldSpec("oauth_enabled", "bool"),
        ),
        _projection(
            "exchange.organization.transport_config",
            FieldSpec("smtp_client_authentication_disabled", "bool"),
        ),
        _projection(
            "exchange.protection.teams_protection_policy",
            FieldSpec("zap_enabled", "bool"),
        ),
        _projection(
            "exchange.protection.atp_policy_o365",
            FieldSpec("enable_atp_for_spo_teams_odb", "bool"),
            FieldSpec("enable_safe_docs", "bool"),
            FieldSpec("allow_safe_docs_open", "bool"),
        ),
        _projection(
            "exchange.transport.external_in_outlook",
            FieldSpec("enabled", "bool"),
        ),
    )
)


def canonical_json(value: object) -> str:
    """Deterministic JSON text; the sort key for canonical_sorted and every preimage."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def canonical_sorted(value: object) -> object:
    """Sort lists at every depth so provider ordering can never look like drift.

    Elements are ordered by their own canonical JSON text, which is total and
    deterministic even for a mixed-type list. See the module docstring for the
    collector-contract obligation this creates.
    """
    if isinstance(value, dict):
        return {key: canonical_sorted(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return sorted((canonical_sorted(item) for item in value), key=canonical_json)
    return value


def _decode_key_material(material: str) -> bytes | None:
    """Accept 64-character hex or base64url with repairable padding; else None."""
    if HEX_KEY_PATTERN.fullmatch(material):
        return bytes.fromhex(material)
    padded = material + "=" * (-len(material) % 4)
    try:
        return base64.b64decode(
            padded.replace("-", "+").replace("_", "/"), validate=True
        )
    except (binascii.Error, ValueError):
        return None


def fingerprint_key() -> bytes | None:
    """The configured HMAC key, or None when it is unusable.

    None is the whole feature gate: no key, a malformed key, or fewer than 32
    decoded bytes all mean no factprint row is written anywhere. There is no
    unkeyed fallback.
    """
    material = (settings.DRIFT_FACT_HMAC_KEY or "").strip()
    if not material:
        return None
    key = _decode_key_material(material)
    if key is None or len(key) < MINIMUM_KEY_BYTES:
        return None
    return key


def key_id(key: bytes) -> str:
    """Stable non-reversible label for the key a row was produced under.

    Derived from the CONFIGURED key, not from a tenant subkey, so one rotation is
    one visible key_id change across every tenant.
    """
    return hashlib.sha256(KEY_ID_DOMAIN + key).hexdigest()[:16]


def tenant_key(key: bytes, tenant_id: str) -> bytes:
    """Per-tenant subkey. Stable for a tenant, unrelated across tenants.

    Stable because drift compares a tenant against its own earlier scans, and a
    subkey that moved between scans would report every fact as changed.
    """
    return hmac.new(
        key, TENANT_KEY_DOMAIN + UNIT + tenant_id.encode(), hashlib.sha256
    ).digest()


def _member_digest(key: bytes, projection_id: str, field_name: str, token: str) -> str:
    return hmac.new(
        key,
        MEMBER_DOMAIN
        + UNIT
        + projection_id.encode()
        + UNIT
        + field_name.encode()
        + UNIT
        + canonical_json(token).encode(),
        hashlib.sha256,
    ).hexdigest()


def _value_digest(
    key: bytes,
    projection_id: str,
    field_name: str,
    field_kind: str,
    digest_input: object,
) -> str:
    return hmac.new(
        key,
        VALUE_DOMAIN
        + UNIT
        + projection_id.encode()
        + UNIT
        + field_name.encode()
        + UNIT
        + field_kind.encode()
        + UNIT
        + canonical_json(canonical_sorted(digest_input)).encode(),
        hashlib.sha256,
    ).hexdigest()


class _Dropped:
    """Sentinel: the observed value did not match the declared kind."""


_DROPPED = _Dropped()


def _normalise(spec: FieldSpec, value: object, limit: int) -> object:
    """Normalise one observed value, or return _DROPPED. Never coerces."""
    if spec.kind == "bool":
        if value is None or isinstance(value, bool):
            return value
        return _DROPPED
    if spec.kind == "int":
        # A bool is an int in Python; here it is a kind mismatch, not a 0 or a 1.
        if value is None:
            return None
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            return _DROPPED
        return value
    if spec.kind == "enum":
        if value is None:
            return None
        if not isinstance(value, str):
            return _DROPPED
        token = value.lower()
        return token if token in spec.vocabulary else UNRECOGNISED
    # enum_set. A single element of an unrecognised SHAPE drops the WHOLE field:
    # never drop an element silently, because a shrunken set reads as tenant drift.
    if not isinstance(value, list):
        return _DROPPED
    if any(not isinstance(element, str) for element in value):
        return _DROPPED
    tokens = set()
    for element in value:
        token = element.lower()
        tokens.add(token if token in spec.vocabulary else UNRECOGNISED)
    ordered = sorted(tokens)
    if len(ordered) > limit:
        # Truncation would store a partial set that is indistinguishable from a
        # smaller real one, so the field is dropped instead.
        return _DROPPED
    return ordered


def project_facts(
    collector_id: str, collected: object, tenant_id: str | None = None
) -> list[dict] | None:
    """Project one collector's output into declared, keyed scalar facts.

    Returns None when no usable key is configured, when no tenant is identified,
    when the collector declares no projection, or when the collector did not
    return an object. A missing key in the collector output yields no entry at
    all: absence is never rendered as false and never as an empty set.

    ``tenant_id`` scopes every digest to one tenant. It is required: without it
    the digests would be comparable across tenants, which is the confirmation
    oracle TENANT_KEY_DOMAIN exists to close. An unidentified tenant writes no
    row rather than writing a cross-tenant-comparable one.
    """
    configured = fingerprint_key()
    if configured is None:
        return None
    if not isinstance(tenant_id, str) or not tenant_id.strip():
        return None
    key = tenant_key(configured, tenant_id.strip())
    projection = FACT_PROJECTIONS.get(collector_id)
    if projection is None:
        return None
    if not isinstance(collected, dict):
        return None

    limit = settings.DRIFT_MAX_SET_MEMBERS
    identifier = key_id(configured)
    entries: list[dict] = []
    dropped: list[str] = []
    for spec in projection.fields:
        if spec.name not in collected:
            continue
        normalized = _normalise(spec, collected[spec.name], limit)
        if isinstance(normalized, _Dropped):
            dropped.append(spec.name)
            continue
        if spec.kind == "enum_set":
            # PARALLEL BY CONSTRUCTION: member_digests[i] is the digest of
            # member_tokens[i], because both arrays are built from one iteration
            # of the same normalised token list. drift._member_tokens zips the
            # two stored arrays to name the member that entered or left a set,
            # so sorting them independently would make an evidence row name the
            # wrong configuration value as added or removed.
            # The value digest is unaffected and stays order-independent:
            # _value_digest canonicalises its input and canonical_sorted sorts
            # lists at every depth, so the member digests enter the preimage in
            # sorted order however this array is ordered.
            member_tokens = list(normalized)
            member_digests = [
                _member_digest(key, projection.projection_id, spec.name, token)
                for token in member_tokens
            ]
            digest_input: object = member_digests
            observed_value = None
        else:
            member_tokens = None
            member_digests = None
            digest_input = normalized
            observed_value = normalized
        entries.append(
            {
                "projection_id": projection.projection_id,
                "field_name": spec.name,
                "field_kind": spec.kind,
                "value_digest": _value_digest(
                    key,
                    projection.projection_id,
                    spec.name,
                    spec.kind,
                    digest_input,
                ),
                "member_digests": member_digests,
                "member_tokens": member_tokens,
                "observed_value": observed_value,
                "key_id": identifier,
            }
        )
    if dropped:
        # Declared field names only; an observed tenant value is never logged.
        logger.warning(
            "field_kind_mismatch collector=%s dropped=%d fields=%s",
            collector_id,
            len(dropped),
            ",".join(sorted(dropped)),
        )
    return entries


# recorded_at is timestamptz, so a bare now() is correct here. Do NOT "fix" this
# toward `now() AT TIME ZONE 'UTC'`: that expression exists to repair the naive
# timestamp columns Phase 6 left behind, and applying it to a timestamptz column
# would re-interpret a correct UTC instant as local time.
INSERT_FACTPRINT = text(
    """
    INSERT INTO scan_result_factprint (
        scan_id, control_id, collector_id, projection_id, field_name, field_kind,
        value_digest, member_digests, member_tokens, observed_value,
        factprint_schema, key_id, retention_policy_version, recorded_at
    )
    VALUES (
        :scan_id, :control_id, :collector_id, :projection_id, :field_name,
        :field_kind, :value_digest, CAST(:member_digests AS jsonb),
        CAST(:member_tokens AS jsonb), CAST(:observed_value AS jsonb),
        'phase8-factprint-v1', :key_id, 'phase8-draft-1', now()
    )
    ON CONFLICT (scan_id, control_id, field_name) DO NOTHING
    """
)


def persist_factprint(
    session: Session,
    *,
    scan_id: int,
    control_id: str,
    collector_id: str,
    fields: list[dict],
) -> int:
    """Write declared facts once per (scan, control, field); return rows inserted.

    ON CONFLICT DO NOTHING plus the rowcount discipline db.py already uses means a
    redelivered Celery message cannot write a second row and cannot overwrite the
    first observation.
    """
    inserted = 0
    for entry in fields:
        observed = entry["observed_value"]
        result = session.execute(
            INSERT_FACTPRINT,
            {
                "scan_id": scan_id,
                "control_id": control_id,
                "collector_id": collector_id,
                "projection_id": entry["projection_id"],
                "field_name": entry["field_name"],
                "field_kind": entry["field_kind"],
                "value_digest": entry["value_digest"],
                "member_digests": (
                    None
                    if entry["member_digests"] is None
                    else json.dumps(entry["member_digests"])
                ),
                "member_tokens": (
                    None
                    if entry["member_tokens"] is None
                    else json.dumps(entry["member_tokens"])
                ),
                "observed_value": None if observed is None else json.dumps(observed),
                "key_id": entry["key_id"],
            },
        )
        inserted += result.rowcount
    return inserted


_declared = {spec.name for p in FACT_PROJECTIONS.values() for spec in p.fields}
if _declared & FORBIDDEN_SOURCE_KEYS:  # pragma: no cover - import-time guard
    raise ValueError("A projection names a raw collector object key")
