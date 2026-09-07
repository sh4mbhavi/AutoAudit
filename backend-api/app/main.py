from fastapi import FastAPI, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from app.core.sessions import CSRFMiddleware
from fastapi.middleware.cors import CORSMiddleware
from app.core.logging import setup_logging
from app.api.v1.router import api_router
from app.core.config import get_settings
from app.core.health import readiness_report
from app.core.metrics import exposition
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
        # If-None-Match is required for the Phase 9 conditional scan poll; without
        # it the browser cannot send the validator and every poll is a full body.
        allow_headers=["Content-Type", "X-CSRF-Token", "If-None-Match"],
        # ETag must be exposed for the same reason: a response header the browser
        # cannot read is a header the client cannot echo back.
        expose_headers=["X-Request-ID", "ETag", "X-Total-Count"],
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

    # Registered on the app rather than on api_router: a container probe and a
    # Prometheus scrape both arrive without a session cookie, and everything
    # under the v1 prefix sits behind CSRF and, for most routers, authentication.
    #
    # Both are GET, so CSRFMiddleware (which only guards unsafe methods) lets
    # them through without needing an exemption mechanism it does not have.
    @app.get("/readiness", include_in_schema=False)
    async def readiness():
        """Whether this replica can actually serve, not merely whether it is up.

        `/liveness` answers "the process is running" and must keep doing exactly
        that -- a liveness probe that fails on a dependency outage restarts a
        healthy container and turns a database blip into a crash loop. This
        endpoint is the other half: a replica that cannot reach its database
        should stop receiving traffic without being killed.
        """
        checks, healthy = await readiness_report()
        return JSONResponse(
            status_code=200 if healthy else 503,
            content={"status": "ready" if healthy else "not_ready", "checks": checks},
        )

    @app.get("/metrics", include_in_schema=False)
    def metrics():
        body, content_type = exposition()
        return Response(content=body, media_type=content_type)

    return app


app = create_app()
