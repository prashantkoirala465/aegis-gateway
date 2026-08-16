import time
from collections.abc import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from aegis_gateway.core.metrics import http_request_duration_seconds, http_requests_total


class PrometheusMiddleware(BaseHTTPMiddleware):
    """Records request count + duration for every route. Uses the matched route's
    path *template* (e.g. "/v1/chat/completions"), never the raw request path — a
    raw path would let path parameters (or arbitrary 404 probes) blow up label
    cardinality. Requests that don't match any route (pure 404s) are labeled
    route="unmatched" so they're still counted without introducing arbitrary paths
    as labels.
    """

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        start = time.monotonic()
        response = await call_next(request)
        duration = time.monotonic() - start

        route = request.scope.get("route")
        route_path = route.path if route is not None else "unmatched"

        http_requests_total.labels(
            method=request.method, route=route_path, status=str(response.status_code)
        ).inc()
        http_request_duration_seconds.labels(method=request.method, route=route_path).observe(
            duration
        )
        return response
