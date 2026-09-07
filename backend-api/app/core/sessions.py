"""Opaque database-backed sessions and session-bound CSRF protection."""

import hashlib
import hmac
import re
import secrets
import time
from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException
from fastapi_users import exceptions
from fastapi_users.authentication import CookieTransport
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.core.config import get_settings
from app.core.metrics import CSRF_REJECTED_ROUTE, observe_request
from app.db.session import get_async_session
from app.models.auth_session import AuthSession

SESSION_COOKIE = "autoaudit_session"
CSRF_COOKIE = "autoaudit_csrf"
CSRF_SECONDS = 600
TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_-]{43}")


def now():
    return datetime.now(timezone.utc)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class SessionStrategy:
    def __init__(self, session: AsyncSession):
        self.session = session
        self.authenticated_session_id = None
        settings = get_settings()
        self.lifetime = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        self.absolute_lifetime = settings.SESSION_ABSOLUTE_SECONDS

    async def read_token(self, token, user_manager):
        if not isinstance(token, str) or not TOKEN_PATTERN.fullmatch(token):
            return None
        row = await self.session.scalar(
            select(AuthSession).where(
                AuthSession.token_hash == token_hash(token),
                AuthSession.expires_at > now(),
                AuthSession.absolute_expires_at > now(),
            )
        )
        if row is None:
            return None
        self.authenticated_session_id = row.id
        try:
            return await user_manager.get(row.user_id)
        except exceptions.UserNotExists:
            return None

    async def write_token(self, user):
        token = secrets.token_urlsafe(32)
        instant = now()
        # Opportunistically clear expired sessions without retaining raw secrets.
        await self.session.execute(
            delete(AuthSession).where(AuthSession.expires_at <= instant)
        )
        self.session.add(
            AuthSession(
                token_hash=token_hash(token),
                user_id=user.id,
                expires_at=instant + timedelta(seconds=self.lifetime),
                absolute_expires_at=instant + timedelta(seconds=self.absolute_lifetime),
            )
        )
        await self.session.commit()
        return token

    async def destroy_token(self, token, user):
        selector = (
            AuthSession.id == self.authenticated_session_id
            if self.authenticated_session_id is not None
            else AuthSession.token_hash == token_hash(token)
        )
        await self.session.execute(
            delete(AuthSession).where(selector, AuthSession.user_id == user.id)
        )
        await self.session.commit()

    async def rotate(self, token, user):
        instant = now()
        replacement = secrets.token_urlsafe(32)
        # Row lock serializes refresh, logout, and replay attempts. A concurrent
        # request with the old hash cannot mint a second replacement session.
        row = await self.session.scalar(
            select(AuthSession)
            .where(
                AuthSession.token_hash == token_hash(token),
                AuthSession.user_id == user.id,
                AuthSession.expires_at > instant,
                AuthSession.absolute_expires_at > instant,
            )
            .with_for_update()
        )
        if row is None:
            raise HTTPException(
                status_code=401, detail="Session expired; sign in again"
            )
        row.token_hash = token_hash(replacement)
        row.expires_at = min(
            instant + timedelta(seconds=self.lifetime), row.absolute_expires_at
        )
        remaining = max(1, int((row.expires_at - instant).total_seconds()))
        await self.session.commit()
        return replacement, remaining


async def get_session_strategy(session: AsyncSession = Depends(get_async_session)):
    return SessionStrategy(session)


def session_transport():
    settings = get_settings()
    return CookieTransport(
        cookie_name=SESSION_COOKIE,
        cookie_max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        cookie_secure=settings.BACKEND_PUBLIC_URL.startswith("https://"),
        cookie_httponly=True,
        cookie_samesite="lax",
        cookie_path="/",
    )


def csrf_signature(payload: str, session_token: str) -> str:
    return hmac.new(
        get_settings().SECRET_KEY.encode(),
        f"{session_token}:{payload}".encode(),
        hashlib.sha256,
    ).hexdigest()


def valid_csrf(token: str, session_token: str) -> bool:
    if not isinstance(token, str) or len(token) > 200:
        return False
    parts = token.split(".")
    if (
        len(parts) != 3
        or not re.fullmatch(r"[0-9]{1,12}", parts[0])
        or not TOKEN_PATTERN.fullmatch(parts[1])
    ):
        return False
    if not 0 <= int(time.time()) - int(parts[0]) <= CSRF_SECONDS:
        return False
    if not re.fullmatch(r"[0-9a-f]{64}", parts[2]):
        return False
    return hmac.compare_digest(
        csrf_signature(".".join(parts[:2]), session_token), parts[2]
    )


def csrf_response(request):
    settings = get_settings()
    origin = request.headers.get("origin")
    if origin is not None and origin != settings.FRONTEND_URL.rstrip("/"):
        raise HTTPException(status_code=403, detail="Invalid request origin")
    session_token = request.cookies.get(SESSION_COOKIE, "")
    token = request.cookies.get(CSRF_COOKIE, "")
    if not valid_csrf(token, session_token):
        payload = f"{int(time.time())}.{secrets.token_urlsafe(32)}"
        token = f"{payload}.{csrf_signature(payload, session_token)}"
    response = JSONResponse(
        {"csrf_token": token}, headers={"Cache-Control": "no-store"}
    )
    response.set_cookie(
        CSRF_COOKIE,
        token,
        httponly=True,
        secure=settings.BACKEND_PUBLIC_URL.startswith("https://"),
        samesite="lax",
        path="/",
        max_age=CSRF_SECONDS,
    )
    return response


class CSRFMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            settings = get_settings()
            cookie = request.cookies.get(CSRF_COOKIE, "")
            header = request.headers.get("x-csrf-token", "")
            if (
                request.headers.get("origin") != settings.FRONTEND_URL.rstrip("/")
                or not cookie
                or not hmac.compare_digest(cookie.encode(), header.encode())
                or not valid_csrf(cookie, request.cookies.get(SESSION_COOKIE, ""))
            ):
                # Observed HERE, not in RequestLoggingMiddleware.
                #
                # add_middleware prepends, so the stack is
                # CORS -> CSRF -> RequestLogging -> router, and this path returns
                # without calling call_next. RequestLoggingMiddleware is
                # therefore never reached, and every CSRF rejection was invisible
                # to autoaudit_api_errors_total -- a 403 storm from a broken
                # client build or a stale FRONTEND_URL produced no signal at all.
                # Found by the review pass.
                #
                # Recorded here rather than by reordering the stack: the ordering
                # is load-bearing for Phase 9's conditional-poll 304, and a
                # targeted observation is the smaller change.
                observe_request(
                    method=request.method,
                    route=CSRF_REJECTED_ROUTE,
                    status=403,
                    duration=0.0,
                )
                return JSONResponse(
                    {"detail": "CSRF validation failed; reload and try again"},
                    status_code=403,
                    headers={"Cache-Control": "no-store"},
                )
        response = await call_next(request)
        if request.url.path.startswith(f"{get_settings().API_PREFIX}/auth"):
            response.headers["Cache-Control"] = "no-store"
        return response
