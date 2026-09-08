"""Session transport, CSRF, rotation, and credential disposal regressions."""

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient


@pytest.mark.parametrize(
    "path", ["/v1/auth/login", "/v1/auth/logout", "/v1/auth/register"]
)
def test_auth_mutations_reject_missing_csrf_before_processing(path):
    from app.main import create_app

    client = TestClient(create_app())
    assert (
        client.post(path, headers={"Origin": "http://localhost:3000"}).status_code
        == 403
    )


def test_auth_backend_uses_only_httponly_cookie_transport():
    from app.core.users import auth_backend
    from fastapi_users.authentication import CookieTransport

    assert isinstance(auth_backend.transport, CookieTransport)
    assert auth_backend.transport.cookie_httponly is True


def test_oauth_callback_never_persists_provider_credentials():
    source = (Path(__file__).parents[1] / "app/api/v1/auth.py").read_text()
    assert "access_token=google_access_token" not in source
    assert "refresh_token=token.get(" not in source
    assert '{"access_token": autoaudit_token' not in source


@pytest.fixture(scope="module")
def auth_database():
    from tests import test_migrations as helpers

    generator = helpers.database_url.__wrapped__()
    url = next(generator)
    helpers._alembic(url, "upgrade", "head")
    yield url
    try:
        next(generator)
    except StopIteration:
        pass


@pytest.fixture
def client(auth_database):
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
    from sqlalchemy.pool import NullPool
    from app.main import create_app
    from app.db.session import get_async_session

    engine = create_async_engine(
        auth_database.replace("postgresql://", "postgresql+asyncpg://"),
        poolclass=NullPool,
    )
    maker = async_sessionmaker(engine, expire_on_commit=False)

    async def session():
        async with maker() as db:
            yield db

    app = create_app()
    app.dependency_overrides[get_async_session] = session
    with TestClient(app) as result:
        result.db_url = auth_database
        result.maker = maker
        yield result
    asyncio.run(engine.dispose())


def csrf(client, origin="http://localhost:3000"):
    response = client.get("/v1/auth/csrf", headers={"Origin": origin})
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    return {"Origin": origin, "X-CSRF-Token": response.json()["csrf_token"]}


def sign_in(client, password=None):
    import secrets

    email = f"{secrets.token_hex(8)}@example.com"
    password = password or secrets.token_urlsafe(32)
    registered = client.post(
        "/v1/auth/register",
        json={
            "email": email,
            "password": password,
            "first_name": "Auth",
            "last_name": "Test",
            "organization_name": "Synthetic",
        },
        headers=csrf(client),
    )
    assert registered.status_code == 201, registered.text
    response = client.post(
        "/v1/auth/login",
        data={"username": email, "password": password},
        headers=csrf(client),
    )
    assert response.status_code == 204, response.text
    return response, registered.json()["id"]


def test_login_protected_request_refresh_logout_and_replay(client):
    from app.core.sessions import SESSION_COOKIE, token_hash
    from tests.test_migrations import _query

    response, user_id = sign_in(client)
    token = client.cookies[SESSION_COOKIE]
    cookie = response.headers["set-cookie"]
    assert (
        "HttpOnly" in cookie
        and "SameSite=lax" in cookie
        and "Path=/" in cookie
        and "Max-Age=1800" in cookie
    )
    assert response.content == b"" and response.headers["cache-control"] == "no-store"
    assert client.get("/v1/auth/users/me").json()["id"] == user_id
    rows = asyncio.run(
        _query(
            client.db_url,
            "SELECT token_hash FROM auth_session WHERE user_id=$1",
            parameters=(user_id,),
        )
    )
    assert rows == [{"token_hash": token_hash(token)}]
    headers_before_refresh = csrf(client)
    refreshed = client.post("/v1/auth/refresh", headers=headers_before_refresh)
    assert refreshed.status_code == 204
    replacement = client.cookies[SESSION_COOKIE]
    assert replacement != token
    client.cookies.set(SESSION_COOKIE, token, domain="testserver.local", path="/")
    assert client.get("/v1/auth/users/me").status_code == 401
    client.cookies.set(SESSION_COOKIE, replacement, domain="testserver.local", path="/")
    assert (
        client.post("/v1/auth/logout", headers=headers_before_refresh).status_code
        == 403
    )
    assert client.post("/v1/auth/logout", headers=csrf(client)).status_code == 204
    assert SESSION_COOKIE not in client.cookies
    client.cookies.set(SESSION_COOKIE, replacement, domain="testserver.local", path="/")
    assert client.get("/v1/auth/users/me").status_code == 401


@pytest.mark.parametrize(
    "method,path",
    [
        ("POST", "/v1/auth/login"),
        ("POST", "/v1/auth/logout"),
        ("POST", "/v1/auth/register"),
        ("PATCH", "/v1/auth/users/me"),
        ("DELETE", "/v1/scans/1"),
        ("POST", "/v1/evidence/scan"),
    ],
)
@pytest.mark.parametrize(
    "attack", ["missing", "mismatch", "cross_origin", "null_origin", "forged"]
)
def test_csrf_rejects_every_unsafe_route_before_side_effects(
    client, method, path, attack
):
    headers = csrf(client)
    if attack == "missing":
        headers.pop("X-CSRF-Token")
    if attack == "mismatch":
        headers["X-CSRF-Token"] = "wrong"
    if attack == "cross_origin":
        headers["Origin"] = "https://attacker.example"
    if attack == "null_origin":
        headers["Origin"] = "null"
    if attack == "forged":
        headers["X-CSRF-Token"] = "forged"
        client.cookies.set(
            "autoaudit_csrf", "forged", domain="testserver.local", path="/"
        )
    assert client.request(method, path, headers=headers).status_code == 403


def test_bearer_header_cannot_authenticate(client):
    from app.core.sessions import SESSION_COOKIE

    sign_in(client)
    token = client.cookies[SESSION_COOKIE]
    client.cookies.clear()
    assert (
        client.get(
            "/v1/auth/users/me", headers={"Authorization": f"Bearer {token}"}
        ).status_code
        == 401
    )


def test_expired_session_cannot_refresh(client):
    from tests.test_migrations import _query

    _, user_id = sign_in(client)
    asyncio.run(
        _query(
            client.db_url,
            "UPDATE auth_session SET expires_at=now()-interval '1 second' WHERE user_id=$1",
            parameters=(user_id,),
            execute=True,
        )
    )
    assert client.get("/v1/auth/users/me").status_code == 401
    assert client.post("/v1/auth/refresh", headers=csrf(client)).status_code == 401


def test_refresh_absolute_lifetime_and_logout_race(client):
    from app.core.sessions import SESSION_COOKIE, SessionStrategy
    from app.core.users import UserManager
    from fastapi_users.db import SQLAlchemyUserDatabase
    from app.models.user import User
    from app.models.oauth_account import OAuthAccount
    from tests.test_migrations import _query

    _, user_id = sign_in(client)
    old_token = client.cookies[SESSION_COOKIE]
    asyncio.run(
        _query(
            client.db_url,
            "UPDATE auth_session SET absolute_expires_at=now()+interval '60 seconds' WHERE user_id=$1",
            parameters=(user_id,),
            execute=True,
        )
    )

    async def race():
        async with client.maker() as logout_db, client.maker() as refresh_db:
            logout_strategy = SessionStrategy(logout_db)
            manager = UserManager(SQLAlchemyUserDatabase(logout_db, User, OAuthAccount))
            user = await logout_strategy.read_token(old_token, manager)
            refresh_strategy = SessionStrategy(refresh_db)
            replacement, remaining = await refresh_strategy.rotate(old_token, user)
            assert 1 <= remaining <= 60
            with pytest.raises(Exception) as rejected:
                await refresh_strategy.rotate(old_token, user)
            assert rejected.value.status_code == 401
            await logout_strategy.destroy_token(old_token, user)
            assert await refresh_strategy.read_token(replacement, manager) is None

    asyncio.run(race())


def test_exact_credentialed_cors_and_csrf_origin(client):
    accepted = client.options(
        "/v1/auth/login",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "X-CSRF-Token,Content-Type",
        },
    )
    assert accepted.status_code == 200
    assert accepted.headers["access-control-allow-origin"] == "http://localhost:3000"
    assert accepted.headers["access-control-allow-credentials"] == "true"
    denied = client.options(
        "/v1/auth/login",
        headers={
            "Origin": "https://attacker.example",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert (
        denied.status_code == 400
        and "access-control-allow-origin" not in denied.headers
    )
    assert (
        client.get(
            "/v1/auth/csrf", headers={"Origin": "https://attacker.example"}
        ).status_code
        == 403
    )


def test_google_purge_migration_preserves_identity_links():
    from tests import test_migrations as helpers

    generator = helpers.database_url.__wrapped__()
    url = next(generator)
    try:
        helpers._alembic(url, "upgrade", "c4e91a73b620")
        helpers._seed(url, helpers.PRIOR_HEADS)
        before = asyncio.run(helpers._snapshot(url))
        helpers._alembic(url, "upgrade", "head")
        after = asyncio.run(helpers._snapshot(url))
        for record in before["oauth_account"]:
            record.update(
                {"access_token": "", "refresh_token": None, "expires_at": None}
            )
        helpers._assert_preserved(before, after)
        assert helpers._versions(url) == {
            "e6a13c95d842"  # pragma: allowlist secret
        }  # pragma: allowlist secret - synthetic fixture or migration revision
        helpers._alembic(url, "upgrade", "head")
        assert asyncio.run(helpers._snapshot(url)) == after
    finally:
        try:
            next(generator)
        except StopIteration:
            pass


@pytest.mark.parametrize(
    "value",
    [
        "²." + "a" * 43 + "." + "b" * 64,
        "0." + "a" * 43 + ".é",
        "١." + "a" * 43 + "." + "b" * 64,
    ],
)
def test_malformed_csrf_never_raises(value):
    from app.core.sessions import valid_csrf

    assert valid_csrf(value, "") is False


def test_google_callback_sets_cookie_and_retains_only_identity_link(
    client, monkeypatch
):
    from app.api.v1 import auth
    from app.core.sessions import SESSION_COOKIE
    import httpx
    from tests.test_migrations import _query

    provider = AsyncMock()
    provider.get_access_token.return_value = {
        "access_token": "provider-access-secret",
        "refresh_token": "provider-refresh-secret",
        "expires_at": 9999999999,
    }
    monkeypatch.setattr(auth, "_google_oauth_client", lambda: provider)
    original = httpx.AsyncClient
    profile = {
        "email": "google-auth@example.com",
        "email_verified": True,
        "sub": "stable-google-subject",
    }
    monkeypatch.setattr(
        auth.httpx,
        "AsyncClient",
        lambda **kwargs: original(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(200, json=profile)
            ),
            **kwargs,
        ),
    )
    for attempt in range(2):
        client.cookies.set(
            auth.GOOGLE_OAUTH_STATE_COOKIE,
            "synthetic-state",
            domain="testserver.local",
            path="/v1/auth/google/callback",
        )
        response = client.get(
            "/v1/auth/google/callback?code=synthetic-code&state=synthetic-state",
            follow_redirects=False,
        )
        assert response.status_code == 302
        assert (
            response.headers["location"] == "http://localhost:3000/auth/google/callback"
        )
        assert SESSION_COOKIE in client.cookies
        assert (
            "HttpOnly" in response.headers["set-cookie"]
            and "SameSite=lax" in response.headers["set-cookie"]
        )
        assert "provider-" not in response.text + response.headers["location"]
        assert client.get("/v1/auth/users/me").status_code == 200
    rows = asyncio.run(
        _query(
            client.db_url,
            "SELECT account_id, access_token, refresh_token, expires_at FROM oauth_account WHERE account_id='stable-google-subject'",
        )
    )
    assert rows == [
        {
            "account_id": "stable-google-subject",
            "access_token": "",
            "refresh_token": None,
            "expires_at": None,
        }
    ]


def test_oauth_state_mismatch_rejected_before_provider_access(client, monkeypatch):
    from app.api.v1 import auth

    provider = AsyncMock()
    monkeypatch.setattr(auth, "_google_oauth_client", lambda: provider)
    response = client.get(
        "/v1/auth/google/callback?code=synthetic-code&state=unmatched",
        follow_redirects=False,
    )
    assert "error=invalid_state" in response.headers["location"]
    provider.get_access_token.assert_not_called()


def test_secure_cookie_flags_match_login_refresh_logout_and_csrf(monkeypatch):
    from app.core import sessions
    from app.core.config import Settings
    from starlette.requests import Request

    settings = Settings(
        _env_file=None,
        BACKEND_PUBLIC_URL="https://api.example.com",
        FRONTEND_URL="https://app.example.com",
    )
    monkeypatch.setattr(sessions, "get_settings", lambda: settings)
    transport = sessions.session_transport()
    login = asyncio.run(transport.get_login_response("synthetic-session"))
    logout = asyncio.run(transport.get_logout_response())
    csrf_response = sessions.csrf_response(
        Request(
            {"type": "http", "headers": [], "method": "GET", "path": "/v1/auth/csrf"}
        )
    )
    for response in [login, logout, csrf_response]:
        header = response.headers["set-cookie"]
        assert (
            "Secure" in header
            and "HttpOnly" in header
            and "SameSite=lax" in header
            and "Path=/" in header
        )
        assert "Domain=" not in header
    assert "Max-Age=0" in logout.headers["set-cookie"]


def test_password_change_revokes_all_sessions_and_clears_cookie(client):
    import secrets
    from app.core.sessions import SESSION_COOKIE

    current_password = secrets.token_urlsafe(32)
    sign_in(client, current_password)
    token = client.cookies[SESSION_COOKIE]
    response = client.post(
        "/v1/auth/users/me/change-password",
        headers=csrf(client),
        json={
            "current_password": current_password,
            "new_password": secrets.token_urlsafe(32),
        },
    )
    assert response.status_code == 204, response.text
    assert SESSION_COOKIE not in client.cookies
    client.cookies.set(SESSION_COOKIE, token, domain="testserver.local", path="/")
    assert client.get("/v1/auth/users/me").status_code == 401


def test_invalid_login_diagnostics_do_not_echo_password(client):
    response = client.post(
        "/v1/auth/login", json={"password": "diagnostic-secret"}, headers=csrf(client)
    )
    assert response.status_code == 422
    assert "diagnostic-secret" not in response.text


def test_concurrent_refresh_has_one_winner_and_old_token_cannot_replay(client):
    from types import SimpleNamespace
    from app.core.sessions import SESSION_COOKIE, SessionStrategy

    _, user_id = sign_in(client)
    token = client.cookies[SESSION_COOKIE]

    async def concurrent():
        async with client.maker() as first_db, client.maker() as second_db:
            outcomes = await asyncio.gather(
                SessionStrategy(first_db).rotate(token, SimpleNamespace(id=user_id)),
                SessionStrategy(second_db).rotate(token, SimpleNamespace(id=user_id)),
                return_exceptions=True,
            )
            assert len([value for value in outcomes if isinstance(value, tuple)]) == 1
            failures = [value for value in outcomes if isinstance(value, Exception)]
            assert len(failures) == 1 and failures[0].status_code == 401

    asyncio.run(concurrent())
    assert client.get("/v1/auth/users/me").status_code == 401
