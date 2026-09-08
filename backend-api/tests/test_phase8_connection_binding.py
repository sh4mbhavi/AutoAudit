"""Phase 8 Purview connection binding (WA-6).

Connect-IPPSSession needs two values the M365 connection has never held: a
server-side certificate alias and the tenant primary ``.onmicrosoft.com``
domain it passes to ``-Organization``. The domain is deliberately a column of
its own rather than a reuse of ``tenant_id``, which is commonly the tenant
GUID; these tests pin that separation, the all-or-nothing binding rule, and the
grammar of both values.

The snapshot test reads the literal key tuple out of ``app/api/v1/scans.py``
rather than a running scan, because what a scan freezes at creation is the
audit input: if a key is added, removed or reordered there, the worker's
identity freeze silently stops covering it.
"""

import ast
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.api.v1 import m365_connections
from app.models.m365_connection import M365Connection
from app.schemas.m365_connection import (
    M365ConnectionCreate,
    M365ConnectionRead,
    M365ConnectionUpdate,
)

SCANS_SOURCE = Path(__file__).resolve().parents[1] / "app" / "api" / "v1" / "scans.py"

BASE = dict(  # nosec B106 # synthetic schema validation fixture
    name="Synthetic",
    tenant_id="00000000-0000-4000-8000-000000000001",
    client_id="00000000-0000-4000-8000-000000000002",
    client_secret="synthetic",  # pragma: allowlist secret - synthetic fixture or migration revision
)


def test_purview_binding_is_all_or_nothing():
    """Half a binding is unusable: the connect call needs both values."""
    assert M365ConnectionCreate(**BASE).compliance_certificate_alias is None
    both = M365ConnectionCreate(
        **BASE,
        compliance_certificate_alias="ipps",
        compliance_organization="contoso.onmicrosoft.com",
    )
    assert both.compliance_certificate_alias == "ipps"
    assert both.compliance_organization == "contoso.onmicrosoft.com"
    with pytest.raises(ValidationError):
        M365ConnectionCreate(**BASE, compliance_certificate_alias="ipps")
    with pytest.raises(ValidationError):
        M365ConnectionCreate(**BASE, compliance_organization="contoso.onmicrosoft.com")


def test_guid_organization_is_rejected_by_name():
    """A tenant GUID here is the most likely mistake, so it is named."""
    with pytest.raises(ValidationError) as error:
        M365ConnectionCreate(
            **BASE,
            compliance_certificate_alias="ipps",
            compliance_organization="00000000-0000-4000-8000-000000000001",
        )
    message = str(error.value)
    assert ".onmicrosoft.com" in message
    assert "GUID" in message


@pytest.mark.parametrize(
    "organization",
    [
        "contoso.com",
        "contoso.onmicrosoft.com.evil.invalid",
        "https://contoso.onmicrosoft.com",
        "-contoso.onmicrosoft.com",
        "a" * 64 + ".onmicrosoft.com",
        "",
    ],
)
def test_organization_grammar(organization):
    """Only the primary domain form passes, and it normalises to lowercase."""
    accepted = M365ConnectionCreate(
        **BASE,
        compliance_certificate_alias="ipps",
        compliance_organization="  Contoso.OnMicrosoft.Com  ",
    )
    assert accepted.compliance_organization == "contoso.onmicrosoft.com"
    with pytest.raises(ValidationError):
        M365ConnectionCreate(
            **BASE,
            compliance_certificate_alias="ipps",
            compliance_organization=organization,
        )


@pytest.mark.parametrize("alias", ["ipps/1", "_ipps", "../../cert", "a" * 65, ""])
def test_alias_grammar(alias):
    """The alias names a server-side certificate; it is never a path."""
    accepted = M365ConnectionCreate(
        **BASE,
        compliance_certificate_alias="ipps-1",
        compliance_organization="contoso.onmicrosoft.com",
    )
    assert accepted.compliance_certificate_alias == "ipps-1"
    with pytest.raises(ValidationError):
        M365ConnectionCreate(
            **BASE,
            compliance_certificate_alias=alias,
            compliance_organization="contoso.onmicrosoft.com",
        )


def test_purview_binding_does_not_require_tenant_match():
    """The organization is a domain; tenant_id is a GUID. They cannot agree."""
    model = M365ConnectionCreate(
        **BASE,
        compliance_certificate_alias="ipps",
        compliance_organization="fabrikam.onmicrosoft.com",
    )
    assert model.tenant_id == "00000000-0000-4000-8000-000000000001"
    assert model.compliance_organization == "fabrikam.onmicrosoft.com"
    update = M365ConnectionUpdate(
        compliance_certificate_alias="ipps",
        compliance_organization="Fabrikam.onmicrosoft.com",
    )
    assert update.compliance_organization == "fabrikam.onmicrosoft.com"


def test_read_schema_exposes_no_secret():
    """Neither new field is a secret, and the read schema still holds none."""
    fields = set(M365ConnectionRead.model_fields)
    assert {"compliance_certificate_alias", "compliance_organization"} <= fields
    assert "client_secret" not in fields
    assert "encrypted_client_secret" not in fields


def test_connection_snapshot_tuple_is_seven_keys():
    """The frozen snapshot key tuple, read from the creating route's source."""
    tree = ast.parse(SCANS_SOURCE.read_text(encoding="utf-8"))
    tuples = [
        node.value.generators[0].iter
        for node in ast.walk(tree)
        if isinstance(node, ast.keyword)
        and node.arg == "connection_snapshot"
        and isinstance(node.value, ast.DictComp)
    ]
    assert len(tuples) == 1
    keys = [element.value for element in tuples[0].elts]
    assert keys == [
        "tenant_id",
        "client_id",
        "sharepoint_admin_url",
        "sharepoint_tenant_id",
        "sharepoint_certificate_alias",
        "compliance_certificate_alias",
        "compliance_organization",
    ]


# --- HTTP round-trip -------------------------------------------------------
#
# The schema tests above prove the two values survive validation. They cannot
# prove the route ever writes them: Phase 8 added the columns, the schemas, the
# snapshot tuple, the worker identity fields and the executor branch, and the
# create/update handlers persisted neither, so the whole binding was
# unreachable through the product. These exercise the real handlers.

ORGANIZATION = "contoso.onmicrosoft.com"
STORED_SECRET = "enc:synthetic"  # nosec B105 # pragma: allowlist secret - synthetic fixture


def _stored_connection(**overrides):
    row = M365Connection(
        id=7,
        user_id=7,
        name="Existing",
        tenant_id=BASE["tenant_id"],
        client_id=BASE["client_id"],
        encrypted_client_secret=STORED_SECRET,
        is_active=True,
        created_at=datetime(2026, 1, 1),
        updated_at=datetime(2026, 1, 1),
    )
    for key, value in overrides.items():
        setattr(row, key, value)
    return row


@pytest.fixture
def api(monkeypatch):
    """The real routes over a mocked session; no network, no database."""
    monkeypatch.setattr(m365_connections, "encrypt", lambda value: f"enc:{value}")
    monkeypatch.setattr(m365_connections, "decrypt", lambda value: value[4:])
    monkeypatch.setattr(
        m365_connections,
        "validate_m365_connection",
        AsyncMock(return_value=SimpleNamespace()),
    )
    stored = _stored_connection()
    db = MagicMock()
    found = MagicMock()
    found.scalar_one_or_none.return_value = stored
    db.execute = AsyncMock(return_value=found)

    async def commit():
        for call in db.add.call_args_list:
            created = call.args[0]
            created.id = 11
            created.user_id = 7
            created.is_active = True
            created.created_at = datetime(2026, 1, 1)
            created.updated_at = datetime(2026, 1, 1)

    db.commit = AsyncMock(side_effect=commit)
    db.refresh = AsyncMock()
    app = FastAPI()
    app.include_router(m365_connections.router)
    app.dependency_overrides[m365_connections.get_current_user] = (
        lambda: SimpleNamespace(id=7)
    )
    app.dependency_overrides[m365_connections.get_async_session] = lambda: db
    return SimpleNamespace(client=TestClient(app), db=db, stored=stored)


def _created(api):
    rows = [call.args[0] for call in api.db.add.call_args_list]
    return next(row for row in rows if isinstance(row, M365Connection))


def test_create_persists_the_purview_binding(api):
    """POST must write both columns, not silently drop validated input."""
    response = api.client.post(
        "/m365-connections/",
        json={
            **BASE,
            "compliance_certificate_alias": "ipps",
            "compliance_organization": "Contoso.OnMicrosoft.Com",
        },
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["compliance_certificate_alias"] == "ipps"
    assert body["compliance_organization"] == ORGANIZATION
    created = _created(api)
    assert created.compliance_certificate_alias == "ipps"
    assert created.compliance_organization == ORGANIZATION


def test_create_without_the_binding_leaves_both_columns_null(api):
    """The binding stays optional; absence must not become a half row."""
    response = api.client.post("/m365-connections/", json=dict(BASE))
    assert response.status_code == 201, response.text
    created = _created(api)
    assert created.compliance_certificate_alias is None
    assert created.compliance_organization is None


@pytest.mark.parametrize(
    "half",
    [
        {"compliance_certificate_alias": "ipps"},
        {"compliance_organization": ORGANIZATION},
    ],
)
def test_create_rejects_half_a_binding(api, half):
    """All-or-nothing is enforced before anything is added to the session."""
    response = api.client.post("/m365-connections/", json={**BASE, **half})
    assert response.status_code == 422
    api.db.add.assert_not_called()
    api.db.commit.assert_not_awaited()


def test_update_persists_the_purview_binding(api):
    """PUT must write both columns onto the existing row."""
    response = api.client.put(
        "/m365-connections/7",
        json={
            "compliance_certificate_alias": "purview-audit",
            "compliance_organization": "Contoso.OnMicrosoft.Com",
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["compliance_certificate_alias"] == "purview-audit"
    assert body["compliance_organization"] == ORGANIZATION
    assert api.stored.compliance_certificate_alias == "purview-audit"
    assert api.stored.compliance_organization == ORGANIZATION


def test_update_keeps_the_stored_half_it_was_not_asked_to_change(api):
    """A partial PUT rotates the alias without dropping the organization."""
    api.stored.compliance_certificate_alias = "ipps"
    api.stored.compliance_organization = ORGANIZATION
    response = api.client.put(
        "/m365-connections/7", json={"compliance_certificate_alias": "ipps-2"}
    )
    assert response.status_code == 200, response.text
    assert api.stored.compliance_certificate_alias == "ipps-2"
    assert api.stored.compliance_organization == ORGANIZATION


@pytest.mark.parametrize(
    "half",
    [
        {"compliance_certificate_alias": "ipps"},
        {"compliance_organization": ORGANIZATION},
    ],
)
def test_update_rejects_half_a_binding(api, half):
    """M365ConnectionUpdate has no model validator; the route is the guard."""
    response = api.client.put("/m365-connections/7", json=half)
    assert response.status_code == 422
    assert "required together" in response.json()["detail"]
    assert api.stored.compliance_certificate_alias is None
    assert api.stored.compliance_organization is None
    api.db.commit.assert_not_awaited()


@pytest.mark.parametrize(
    "half",
    [
        {"compliance_certificate_alias": None},
        {"compliance_organization": None},
    ],
)
def test_update_rejects_clearing_only_one_half(api, half):
    """Half-clearing a complete binding is the same broken row, reversed."""
    api.stored.compliance_certificate_alias = "ipps"
    api.stored.compliance_organization = ORGANIZATION
    response = api.client.put("/m365-connections/7", json=half)
    assert response.status_code == 422
    assert api.stored.compliance_certificate_alias == "ipps"
    assert api.stored.compliance_organization == ORGANIZATION
    api.db.commit.assert_not_awaited()


def test_update_clears_the_binding_as_a_pair(api):
    """Unbinding is legal, as a pair."""
    api.stored.compliance_certificate_alias = "ipps"
    api.stored.compliance_organization = ORGANIZATION
    response = api.client.put(
        "/m365-connections/7",
        json={
            "compliance_certificate_alias": None,
            "compliance_organization": None,
        },
    )
    assert response.status_code == 200, response.text
    assert api.stored.compliance_certificate_alias is None
    assert api.stored.compliance_organization is None


def test_update_of_an_unrelated_field_does_not_disturb_the_binding(api):
    """Renaming must neither clear the binding nor trip its validation."""
    api.stored.compliance_certificate_alias = "ipps"
    api.stored.compliance_organization = ORGANIZATION
    response = api.client.put("/m365-connections/7", json={"name": "Renamed"})
    assert response.status_code == 200, response.text
    assert api.stored.name == "Renamed"
    assert api.stored.compliance_certificate_alias == "ipps"
    assert api.stored.compliance_organization == ORGANIZATION
