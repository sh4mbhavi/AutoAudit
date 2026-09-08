"""
FastAPI Users configuration for authentication.

This file follows the official FastAPI Users setup pattern for SQLAlchemy with async support.
Official documentation: https://fastapi-users.github.io/fastapi-users/

Key components:
- UserManager: Handles user lifecycle events (registration, password reset, etc.)
- Authentication backend: Database-backed authentication with HttpOnly session cookies
- Dependencies: get_user_db, get_user_manager for dependency injection
"""

import logging
from typing import Optional
from fastapi import Depends, Request
from fastapi_users import BaseUserManager, FastAPIUsers, IntegerIDMixin
from fastapi_users.authentication import (
    AuthenticationBackend,
)
from fastapi_users.db import SQLAlchemyUserDatabase
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.sessions import get_session_strategy, session_transport
from app.db.session import get_async_session
from app.models.user import User
from app.models.oauth_account import OAuthAccount

logger = logging.getLogger(__name__)
settings = get_settings()


class UserManager(IntegerIDMixin, BaseUserManager[User, int]):
    """User manager for handling user operations."""

    reset_password_token_secret = settings.SECRET_KEY
    verification_token_secret = settings.SECRET_KEY

    async def on_after_register(self, user: User, request: Optional[Request] = None):
        """Called after user registration."""
        logger.info("User %s registered.", user.id)

    async def on_after_forgot_password(
        self, user: User, token: str, request: Optional[Request] = None
    ):
        """Called after forgot password request."""
        logger.info("Password reset requested for user %s.", user.id)

    async def on_after_request_verify(
        self, user: User, token: str, request: Optional[Request] = None
    ):
        """Called after verification request."""
        logger.info("Verification requested for user %s.", user.id)


async def get_user_db(session: AsyncSession = Depends(get_async_session)):  # noqa: B008 - FastAPI dependency
    """Dependency for getting the user database."""
    yield SQLAlchemyUserDatabase(session, User, OAuthAccount)


async def get_user_manager(user_db: SQLAlchemyUserDatabase = Depends(get_user_db)):  # noqa: B008 - FastAPI dependency
    """Dependency for getting the user manager."""
    yield UserManager(user_db)


# Only the HttpOnly cookie transport can authenticate a browser session.
cookie_transport = session_transport()
auth_backend = AuthenticationBackend(
    name="session",
    transport=cookie_transport,
    get_strategy=get_session_strategy,
)

# FastAPI Users instance
fastapi_users = FastAPIUsers[User, int](
    get_user_manager,
    [auth_backend],
)

# Dependencies for getting current user
current_active_user = fastapi_users.current_user(active=True)
