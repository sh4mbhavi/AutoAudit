"""Manual verification routes run in-process without live API credentials."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1 import manual_verification as routes


@pytest.fixture
def api():
    db = MagicMock()
    db.execute = AsyncMock(return_value=MagicMock())
    db.execute.return_value.scalar_one_or_none.return_value = None
    db.commit = AsyncMock()
    db.delete = AsyncMock()
    app = FastAPI()
    app.include_router(routes.router)
    app.dependency_overrides[routes.get_current_user] = lambda: SimpleNamespace(id=7)
    app.dependency_overrides[routes.get_async_session] = lambda: db
    with TestClient(app) as client:
        yield client, db


@pytest.mark.parametrize(
    "method,path,payload",
    [
        ("GET", "/99999", None),
        ("PATCH", "/99999", {"comment": "Synthetic review"}),
        ("DELETE", "/99999", None),
        ("GET", "/by-scan-result/99999", None),
        ("POST", "/", {"scan_result_id": 99999, "comment": "Synthetic review"}),
    ],
)
def test_nonexistent_returns_404(api, method, path, payload):
    client, db = api
    response = client.request(method, "/manual-verification" + path, json=payload)
    assert response.status_code == 404, response.text
    db.commit.assert_not_awaited()
    db.delete.assert_not_awaited()


@pytest.mark.parametrize(
    "method,path,payload",
    [
        ("GET", "/1", None),
        ("PATCH", "/1", {"comment": "Synthetic review"}),
        ("DELETE", "/1", None),
        ("GET", "/by-scan-result/1", None),
    ],
)
def test_other_owners_record_is_not_disclosed(api, method, path, payload):
    """Phase 7: another tenant's record answers 404, not 403.

    The old 403 differed from the 404 a missing record returns, which made these
    reads an existence oracle for other tenants' scan results.
    """
    client, db = api
    db.execute.return_value.scalar_one_or_none.return_value = SimpleNamespace(
        id=1, user_id=8
    )
    response = client.request(method, "/manual-verification" + path, json=payload)
    assert response.status_code == 404, response.text
    db.commit.assert_not_awaited()
    db.delete.assert_not_awaited()


def test_authentication_required():
    app = FastAPI()
    app.include_router(routes.router)
    with TestClient(app) as client:
        assert client.get("/manual-verification/1").status_code == 401
