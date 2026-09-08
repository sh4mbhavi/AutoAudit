"""Durable identifier-only scan dispatch intent, committed with scan data."""

from datetime import datetime

from sqlalchemy import ForeignKey, String, Index, text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from app.db.base import Base


class ScanDispatch(Base):
    __tablename__ = "scan_dispatch"
    __table_args__ = (Index("ix_scan_dispatch_available", "available_at"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scan.id", ondelete="CASCADE"))
    result_id: Mapped[int | None] = mapped_column(
        ForeignKey("scan_result.id", ondelete="CASCADE"), nullable=True
    )
    task_name: Mapped[str] = mapped_column(String(100))
    attempts: Mapped[int] = mapped_column(default=0, server_default="0")
    # Stamped in UTC, not with a bare now(): this column is compared against
    # (now() AT TIME ZONE 'UTC') in the dispatcher, and now() is timestamptz, so a
    # bare default converts using the server TimeZone and on a non-UTC server
    # stamps every new row ahead of the clock it is compared against.
    available_at: Mapped[datetime] = mapped_column(
        server_default=text("(now() AT TIME ZONE 'UTC')")
    )
    dispatched_at: Mapped[datetime | None] = mapped_column(nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(100), nullable=True)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
