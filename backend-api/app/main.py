from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from app.core.sessions import CSRFMiddleware
from fastapi.middleware.cors import CORSMiddleware
from app.core.logging import setup_logging
from app.api.v1.router import api_router
from app.core.config import get_settings
from app.core.middleware import RequestLoggingMiddleware
from app.core.errors import not_found_handler, NotFound

settings = get_settings()


def create_app() -> FastAPI:
    setup_logging()
    app = FastAPI(title="AutoAudit API", version="0.1.0")

    # RequestLoggingMiddleware must be added before CORSMiddleware
    # (middleware executes in reverse order - last added runs first)
    app.add_middleware(RequestLoggingMiddleware)
    app.add_middleware(CSRFMiddleware)

    # Allow frontend (localhost:3000 and others) to call the API during development.
    # CORS must be added last so it runs first and wraps all responses including errors.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[settings.FRONTEND_URL.rstrip("/")],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["Content-Type", "X-CSRF-Token"],
        expose_headers=["X-Request-ID"],
    )
    app.include_router(api_router, prefix=settings.API_PREFIX)

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request, exc):
        return JSONResponse(status_code=422, content={"detail": "Invalid request"})

    # error handler
    app.add_exception_handler(NotFound, not_found_handler)

    @app.get("/")
    def root():
        return {"status": "ok", "message": "AutoAudit API running"}

    @app.get("/liveness")
    def health_check():
        return {
            "status": "healthy",
        }

    return app


app = create_app()
