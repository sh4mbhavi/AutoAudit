import logging
import re
import time
from uuid import uuid4

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

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
