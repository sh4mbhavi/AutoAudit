"""Per-execution correlation context; never put evidence or credentials in events."""

from contextvars import ContextVar
import logging
import re

request_id = ContextVar("autoaudit_request_id", default=None)


def safe_request_id(value):
    return (
        value
        if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", value)
        else None
    )


def headers():
    value = safe_request_id(request_id.get())
    return {"X-Request-ID": value} if value else {}


def event(name):
    value = safe_request_id(request_id.get())
    logging.getLogger("autoaudit.execution").info(
        "%s correlation_id=%s", name, value, extra={"correlation_id": value}
    )
