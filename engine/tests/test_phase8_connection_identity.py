"""Phase 8 worker identity freeze over the Purview binding (WA-6).

``get_execution_credentials`` refuses to execute a scan whose live connection no
longer matches the snapshot frozen at creation. The two Purview columns join
that tuple, so rebinding a compliance certificate mid-scan is an identity
change exactly as rebinding a SharePoint certificate already is.

The session is stubbed rather than migrated: what is under test is the identity
comparison and the returned projection, and a stub lets a legacy snapshot that
predates the columns be expressed directly.
"""

from unittest.mock import MagicMock

import pytest

from worker import db

IDENTITY = {
    "tenant_id": "tenant-a",
    "client_id": "client-a",
    "sharepoint_admin_url": "https://synthetic-admin.sharepoint.com",
    "sharepoint_tenant_id": "tenant-a",
    "sharepoint_certificate_alias": "synthetic-sharepoint",
    "compliance_certificate_alias": "synthetic-compliance",
    "compliance_organization": "contoso.onmicrosoft.com",
}


def _row(**overrides):
    row = {
        **IDENTITY,
        "connection_snapshot": IDENTITY.copy(),
        "is_active": True,
        "encrypted_client_secret": "synthetic-ciphertext",  # pragma: allowlist secret - synthetic fixture or migration revision
    }
    row.update(overrides)
    return row


def _session(row):
    session = MagicMock()
    session.execute.return_value.mappings.return_value.first.return_value = row
    return session


@pytest.fixture
def decrypted(monkeypatch):
    monkeypatch.setattr(db, "decrypt", lambda value: "plaintext-" + value)


def test_credentials_include_compliance_binding(decrypted):
    session = _session(_row())
    credentials = db.get_execution_credentials(session, 1, 3)
    assert credentials["compliance_certificate_alias"] == "synthetic-compliance"
    assert credentials["compliance_organization"] == "contoso.onmicrosoft.com"
    query = str(session.execute.call_args.args[0])
    assert "c.compliance_certificate_alias" in query
    assert "c.compliance_organization" in query


def test_snapshot_mismatch_on_compliance_alias_raises(monkeypatch):
    decrypt = MagicMock()
    monkeypatch.setattr(db, "decrypt", decrypt)
    row = _row(compliance_certificate_alias="b")
    row["connection_snapshot"]["compliance_certificate_alias"] = "a"
    with pytest.raises(ValueError, match="Scan connection identity changed"):
        db.get_execution_credentials(_session(row), 1, 3)
    decrypt.assert_not_called()


def test_snapshot_mismatch_on_compliance_organization_raises(monkeypatch):
    decrypt = MagicMock()
    monkeypatch.setattr(db, "decrypt", decrypt)
    row = _row(compliance_organization="fabrikam.onmicrosoft.com")
    row["connection_snapshot"]["compliance_organization"] = "contoso.onmicrosoft.com"
    with pytest.raises(ValueError, match="Scan connection identity changed"):
        db.get_execution_credentials(_session(row), 1, 3)
    decrypt.assert_not_called()


def test_legacy_snapshot_without_the_keys_still_resolves(decrypted):
    """A scan frozen before the columns existed compares None to NULL."""
    legacy = {
        key: value
        for key, value in IDENTITY.items()
        if not key.startswith("compliance_")
    }
    row = _row(
        connection_snapshot=legacy,
        compliance_certificate_alias=None,
        compliance_organization=None,
    )
    credentials = db.get_execution_credentials(_session(row), 1, 3)
    assert credentials["compliance_certificate_alias"] is None
    assert credentials["compliance_organization"] is None
    assert credentials["sharepoint_certificate_alias"] == "synthetic-sharepoint"


def test_identity_fields_slice_still_returns_non_identity_values(decrypted):
    """tenant_id and client_id are returned directly; the rest ride the slice."""
    credentials = db.get_execution_credentials(_session(_row()), 1, 3)
    assert set(credentials) == {
        "tenant_id",
        "client_id",
        "client_secret",
        "sharepoint_admin_url",
        "sharepoint_tenant_id",
        "sharepoint_certificate_alias",
        "compliance_certificate_alias",
        "compliance_organization",
    }
    assert (
        credentials["client_secret"]  # pragma: allowlist secret - synthetic fixture
        == "plaintext-synthetic-ciphertext"
    )
    unsnapshotted = db.get_execution_credentials(
        _session(_row(connection_snapshot=None)), 1, 3
    )
    assert unsnapshotted["compliance_organization"] is None
    assert unsnapshotted["sharepoint_admin_url"] is None
    assert unsnapshotted["tenant_id"] == "tenant-a"
