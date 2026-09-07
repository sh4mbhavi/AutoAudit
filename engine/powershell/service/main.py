"""Authenticated service for fixed, read-only M365 collection operations."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from functools import partial
import hmac
import logging
import os
import re
from uuid import uuid4
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

if __package__:
    from .schemas import (
        ExecuteBatchRequest,
        ExecuteBatchResponse,
        ExecuteRequest,
        ExecuteResponse,
        HealthResponse,
    )
    from .executor import execute_batch, execute_operation, PowerShellExecutionError
else:
    from schemas import (
        ExecuteBatchRequest,
        ExecuteBatchResponse,
        ExecuteRequest,
        ExecuteResponse,
        HealthResponse,
    )
    from executor import execute_batch, execute_operation, PowerShellExecutionError

logger = logging.getLogger(__name__)


def _max_concurrency() -> int:
    """How many pwsh children may run at once. Explicit, small and bounded.

    Before Phase 9 the handler was a plain ``def``, so Starlette ran it on its
    shared 40-slot threadpool: the blocking work was off the event loop, but the
    bound was a framework default that also serves every other threadpool user,
    and each slot could hold a 120-second pwsh subprocess. The offload is now
    explicit and the pool is this service's own.
    """
    raw = os.environ.get("POWERSHELL_MAX_CONCURRENCY", "4")
    try:
        value = int(raw)
    except ValueError:
        raise RuntimeError(
            "POWERSHELL_MAX_CONCURRENCY must be an integer between 1 and 32"
        ) from None
    if not 1 <= value <= 32:
        raise RuntimeError(
            "POWERSHELL_MAX_CONCURRENCY must be an integer between 1 and 32"
        )
    return value


# PEP 604 syntax cannot be used here. This module is a module-level annotation
# away from the image's interpreter: engine/powershell/Dockerfile installs
# Mariner's `python3`, which is 3.9, and pyproject.toml declares
# requires-python = ">=3.9". A module-level `X | None` is evaluated at import,
# so it raises TypeError before uvicorn ever binds. tools/tests/
# test_powershell_service_python_floor.py holds this to the declared floor.
_EXECUTION_POOL: Optional[ThreadPoolExecutor] = None


def execution_pool() -> ThreadPoolExecutor:
    global _EXECUTION_POOL
    if _EXECUTION_POOL is None:
        _EXECUTION_POOL = ThreadPoolExecutor(
            max_workers=_max_concurrency(), thread_name_prefix="pwsh"
        )
    return _EXECUTION_POOL


async def _offload(function, /, **kwargs):
    """Run one blocking pwsh execution on the service's own bounded pool."""
    return await asyncio.get_running_loop().run_in_executor(
        execution_pool(), partial(function, **kwargs)
    )


def service_secret() -> str:
    secret = os.environ.get("POWERSHELL_SERVICE_SECRET", "")
    if (
        len(secret) < 32
        or not secret.isascii()
        or any(char.isspace() for char in secret)
    ):
        raise RuntimeError(
            "POWERSHELL_SERVICE_SECRET must be configured with at least 32 non-whitespace ASCII characters"
        )
    return secret


@asynccontextmanager
async def lifespan(app: FastAPI):
    service_secret()  # Fail startup closed in every environment; there is no development bypass.
    _max_concurrency()  # Fail startup closed on a misconfigured bound, not at first request.
    yield
    global _EXECUTION_POOL
    pool, _EXECUTION_POOL = _EXECUTION_POOL, None
    if pool is not None:
        pool.shutdown(wait=False, cancel_futures=True)


app = FastAPI(title="PowerShell Service", version="2.0.0", lifespan=lifespan)


@app.exception_handler(RequestValidationError)
async def invalid_request(request, exc):
    # Pydantic model-level errors include the full input, including access tokens.
    return JSONResponse(
        status_code=422, content={"detail": "Invalid PowerShell operation request"}
    )


def authenticate_service(
    x_service_secret: Optional[str] = Header(default=None),
) -> None:
    expected = service_secret()
    if x_service_secret is None or not hmac.compare_digest(
        x_service_secret.encode("utf-8"), expected.encode("ascii")
    ):
        raise HTTPException(status_code=401, detail="Invalid service credentials")


@app.get("/health", response_model=HealthResponse)
def health_check():
    return HealthResponse(status="ok")


def _correlation(x_request_id: Optional[str]) -> str:
    return (
        x_request_id
        if isinstance(x_request_id, str)
        and re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", x_request_id)
        else str(uuid4())
    )


@app.post(
    "/execute",
    response_model=ExecuteResponse,
    dependencies=[Depends(authenticate_service)],
)
async def execute(
    request: ExecuteRequest, x_request_id: Optional[str] = Header(default=None)
):
    correlation = _correlation(x_request_id)
    logger.info(
        "powershell_operation_started correlation_id=%s",
        correlation,
        extra={"correlation_id": correlation},
    )
    try:
        result = await _offload(execute_operation, **request.model_dump())
        logger.info(
            "powershell_operation_completed correlation_id=%s",
            correlation,
            extra={"correlation_id": correlation},
        )
        return ExecuteResponse(success=True, data=result)
    except ValueError:
        # Do not echo request values, filesystem paths or credentials in diagnostics.
        raise HTTPException(
            status_code=400, detail="Invalid PowerShell operation configuration"
        ) from None
    except PowerShellExecutionError:
        return ExecuteResponse(success=False, error="PowerShell operation failed")
    except Exception:
        logger.error("PowerShell operation failed unexpectedly")
        return ExecuteResponse(success=False, error="PowerShell operation failed")


@app.post(
    "/execute-batch",
    response_model=ExecuteBatchResponse,
    dependencies=[Depends(authenticate_service)],
)
async def execute_many(
    request: ExecuteBatchRequest, x_request_id: Optional[str] = Header(default=None)
):
    """Several reviewed operations of one module, in one remote session.

    Same authentication, same redaction and same failure envelope as /execute.
    A batch either returns every operation's result in request order or fails as
    a whole; there is no partial batch, because a partial collection is not the
    tenant's configuration.
    """
    correlation = _correlation(x_request_id)
    payload = request.model_dump()
    operations = payload.pop("operations")
    logger.info(
        "powershell_batch_started correlation_id=%s operations=%s",
        correlation,
        len(operations),
        extra={"correlation_id": correlation},
    )
    try:
        result = await _offload(execute_batch, operations=operations, **payload)
        logger.info(
            "powershell_batch_completed correlation_id=%s",
            correlation,
            extra={"correlation_id": correlation},
        )
        return ExecuteBatchResponse(success=True, data=result)
    except ValueError:
        raise HTTPException(
            status_code=400, detail="Invalid PowerShell operation configuration"
        ) from None
    except PowerShellExecutionError:
        return ExecuteBatchResponse(success=False, error="PowerShell operation failed")
    except Exception:
        logger.error("PowerShell operation failed unexpectedly")
        return ExecuteBatchResponse(success=False, error="PowerShell operation failed")
