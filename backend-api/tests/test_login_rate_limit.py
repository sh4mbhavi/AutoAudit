"""`POST /v1/auth/login` had no rate limiting, throttling or lockout.

It is the one place in the product where an unauthenticated caller can test a
guess against a real credential, and it answered as fast as the database could
hash a password. Nothing counted attempts, nothing locked an account, and
nothing recorded that a source address had tried a thousand times.

These run against the middleware directly rather than the whole application, so
they assert the throttle's behaviour without depending on a database, a user
fixture or the password hasher's cost.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.core.middleware import LoginRateLimitMiddleware


def _app(*, status_code: int = 400, max_failures: int = 3, window: int = 300):
    application = FastAPI()
    application.add_middleware(
        LoginRateLimitMiddleware,
        path_suffix="/v1/auth/login",
        max_failures=max_failures,
        window_seconds=window,
    )

    outcome = {"status": status_code}

    @application.post("/v1/auth/login")
    async def login():  # pragma: no cover - exercised through the client
        from fastapi.responses import JSONResponse

        return JSONResponse(status_code=outcome["status"], content={"detail": "x"})

    @application.post("/v1/other")
    async def other():  # pragma: no cover - exercised through the client
        from fastapi.responses import JSONResponse

        return JSONResponse(status_code=400, content={"detail": "x"})

    return application, outcome


def test_failed_attempts_are_refused_once_the_window_is_full():
    application, _ = _app(max_failures=3)
    with TestClient(application) as client:
        for _ in range(3):
            assert client.post("/v1/auth/login").status_code == 400
        refused = client.post("/v1/auth/login")
        assert refused.status_code == 429
        assert refused.json()["detail"] == "Too many failed sign-in attempts"
        assert int(refused.headers["Retry-After"]) > 0


def test_the_refusal_says_nothing_about_the_account():
    """A throttle that distinguishes real accounts is an enumeration oracle."""
    application, _ = _app(max_failures=1)
    with TestClient(application) as client:
        client.post("/v1/auth/login", data={"username": "someone@example.invalid"})
        refused = client.post(
            "/v1/auth/login", data={"username": "someone@example.invalid"}
        )
        assert refused.status_code == 429
        assert refused.json() == {"detail": "Too many failed sign-in attempts"}


def test_a_success_clears_the_window():
    """A busy shared address that keeps signing in is not the traffic to stop."""
    application, outcome = _app(max_failures=3)
    with TestClient(application) as client:
        for _ in range(2):
            assert client.post("/v1/auth/login").status_code == 400
        outcome["status"] = 204
        assert client.post("/v1/auth/login").status_code == 204
        outcome["status"] = 400
        for _ in range(3):
            assert client.post("/v1/auth/login").status_code == 400
        assert client.post("/v1/auth/login").status_code == 429


def test_successful_logins_are_never_counted():
    application, outcome = _app(max_failures=2)
    outcome["status"] = 204
    with TestClient(application) as client:
        for _ in range(20):
            assert client.post("/v1/auth/login").status_code == 204


def test_other_routes_are_untouched():
    application, _ = _app(max_failures=1)
    with TestClient(application) as client:
        for _ in range(10):
            assert client.post("/v1/other").status_code == 400


def test_the_window_expires():
    application, _ = _app(max_failures=1, window=0)
    with TestClient(application) as client:
        assert client.post("/v1/auth/login").status_code == 400
        # A zero-length window means every prior failure is already outside it.
        assert client.post("/v1/auth/login").status_code == 400


def test_the_application_wires_the_limiter_onto_the_login_path():
    """The middleware existing is not the same as it being mounted."""
    from app.core.config import get_settings
    from app.main import create_app

    application = create_app()
    mounted = [
        middleware
        for middleware in application.user_middleware
        if middleware.cls is LoginRateLimitMiddleware
    ]
    assert mounted, "LoginRateLimitMiddleware is not installed on the application"
    options = mounted[0].kwargs
    assert options["path_suffix"] == f"{get_settings().API_PREFIX}/auth/login"
    assert options["max_failures"] >= 1
    assert options["window_seconds"] >= 1
