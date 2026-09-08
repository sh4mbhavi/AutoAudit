"""Authenticated service for fixed, read-only M365 collection operations."""

from contextlib import asynccontextmanager
import hmac
import logging
import os
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

if __package__:
    from .schemas import ExecuteRequest, ExecuteResponse, HealthResponse
    from .executor import execute_operation, PowerShellExecutionError
else:
    from schemas import ExecuteRequest, ExecuteResponse, HealthResponse
    from executor import execute_operation, PowerShellExecutionError

logger = logging.getLogger(__name__)


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
    yield


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


@app.post(
    "/execute",
    response_model=ExecuteResponse,
    dependencies=[Depends(authenticate_service)],
)
def execute(request: ExecuteRequest):
    try:
        result = execute_operation(**request.model_dump())
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
