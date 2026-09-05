"""Explicit local-development administrator bootstrap: python -m app.db.init_db.

Requires APP_ENV=dev, DEV_ADMIN_SEED_ENABLED=true and caller-supplied credentials.
Container startup does not invoke this command. Existing accounts are never changed.
"""

import asyncio
import logging

from app.core.config import get_settings
from app.db.session import async_session_maker
from app.models.user import Role, User
from fastapi_users.password import PasswordHelper
from sqlalchemy import select

logger = logging.getLogger(__name__)


async def init_db():
    settings = get_settings()
    if settings.APP_ENV != "dev" or not settings.DEV_ADMIN_SEED_ENABLED:
        logger.info("Development administrator bootstrap is disabled.")
        return

    if not settings.DEV_ADMIN_EMAIL or not settings.DEV_ADMIN_PASSWORD:
        raise ValueError(
            "DEV_ADMIN_EMAIL and DEV_ADMIN_PASSWORD must be explicitly set"
        )
    password = settings.DEV_ADMIN_PASSWORD.get_secret_value()
    if len(password) < 16:
        raise ValueError("DEV_ADMIN_PASSWORD must contain at least 16 characters")

    async with async_session_maker() as session:
        result = await session.execute(
            select(User).where(User.email == settings.DEV_ADMIN_EMAIL)
        )
        if result.unique().scalar_one_or_none() is not None:
            logger.info(
                "Development administrator bootstrap skipped: account already exists."
            )
            return

        session.add(
            User(
                email=settings.DEV_ADMIN_EMAIL,
                hashed_password=PasswordHelper().hash(password),
                role=Role.ADMIN.value,
                is_active=True,
                is_superuser=True,
                is_verified=True,
            )
        )
        await session.commit()
        logger.info("Development administrator created.")


if __name__ == "__main__":
    asyncio.run(init_db())
