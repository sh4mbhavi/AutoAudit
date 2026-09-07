import logging
import re
import time
from collections import defaultdict, deque
from uuid import uuid4

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.core.metrics import observe_request, route_label

# pylint: disable-next=no-member
logger = logging.getLogger("api")  # type: ignore[attr-defined]

REQUEST_ID_HEADER = "X-Request-ID"
MAX_REQUEST_ID_LENGTH = 128


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        start_time = time.perf_counter()

        supplied_request_id = request.headers.get(REQUEST_ID_HEADER)

        if supplied_request_id and re.fullmatch(
            r"[A-Za-z0-9._:-]{1,128}", supplied_request_id
        ):
            request_id = supplied_request_id
        else:
            request_id = str(uuid4())

        request.state.request_id = request_id

        try:
            response = await call_next(request)
        except Exception:  # pylint: disable=broad-exception-caught
            duration = round(time.perf_counter() - start_time, 3)

            # An unhandled exception still reaches the client as a 500, so it is
            # still a request the error rate has to count. Recording it only on
            # the success path would make the one failure mode an operator most
            # needs to see the one the metric cannot show.
            observe_request(
                method=request.method,
                route=route_label(request),
                status=500,
                duration=duration,
            )

            logger.exception(
                {
                    "request_id": request_id,
                    "method": request.method,
                    "path": request.url.path,
                    "status_code": 500,
                    "duration": duration,
                }
            )

            raise

        duration = round(time.perf_counter() - start_time, 3)

        response.headers[REQUEST_ID_HEADER] = request_id

        # Read the route from the scope only after the router has run; before
        # that no route is matched and every request would report __unmatched__.
        observe_request(
            method=request.method,
            route=route_label(request),
            status=response.status_code,
            duration=duration,
        )

        logger.info(
            {
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "duration": duration,
            }
        )

        return response


class LoginRateLimitMiddleware(BaseHTTPMiddleware):
    """Throttle repeated failed logins from one source address.

    ``POST /v1/auth/login`` had no rate limiting, throttling or lockout of any
    kind. The endpoint is the one place in the product where an unauthenticated
    caller can test a guess against a real credential, and it would answer as
    fast as the database could hash.

    Only **failures** are counted. A shared office address logging people in
    successfully is not the traffic this exists to stop, and counting successes
    would turn a busy morning into an outage. A refusal answers 429 with
    ``Retry-After``, and never says whether the account exists.

    **This is a per-process window.** It is a real and material increase in the
    cost of online guessing, and it is not a substitute for a shared counter:
    with more than one API replica the effective limit multiplies by the replica
    count, and a restart clears it. A deployment that runs more than one replica
    needs this backed by the broker or the database, which is a decision about
    an operational dependency on the request path and is recorded as such rather
    than assumed here.
    """

    def __init__(
        self,
        app,
        *,
        path_suffix: str = "/auth/login",
        max_failures: int = 10,
        window_seconds: int = 300,
    ) -> None:
        super().__init__(app)
        self._path_suffix = path_suffix
        self._max_failures = max_failures
        self._window_seconds = window_seconds
        self._failures: dict[str, deque[float]] = defaultdict(deque)

    def _client(self, request: Request) -> str:
        # request.client.host, not a forwarded header: an untrusted
        # X-Forwarded-For would let a caller pick a fresh bucket per attempt.
        # A deployment behind a proxy must configure the proxy headers
        # middleware, which rewrites request.client for every middleware.
        return request.client.host if request.client else "unknown"

    def _prune(self, bucket: "deque[float]", now: float) -> None:
        cutoff = now - self._window_seconds
        while bucket and bucket[0] < cutoff:
            bucket.popleft()

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        if request.method != "POST" or not request.url.path.endswith(self._path_suffix):
            return await call_next(request)

        key = self._client(request)
        now = time.monotonic()
        bucket = self._failures[key]
        self._prune(bucket, now)

        if len(bucket) >= self._max_failures:
            retry_after = int(self._window_seconds - (now - bucket[0])) + 1
            logger.warning(
                {
                    "event": "login_rate_limited",
                    "request_id": getattr(request.state, "request_id", None),
                    "failures_in_window": len(bucket),
                }
            )
            return JSONResponse(
                status_code=429,
                content={"detail": "Too many failed sign-in attempts"},
                headers={"Retry-After": str(max(retry_after, 1))},
            )

        response = await call_next(request)
        # 400 is what fastapi-users answers for bad credentials; 401 and 403 are
        # counted too so a future change of shape cannot silently stop counting.
        if response.status_code in {400, 401, 403}:
            bucket.append(time.monotonic())
        elif response.status_code < 400:
            # A success clears the window for that source: the address has just
            # proved it belongs to someone who knows a password.
            bucket.clear()
        return response
