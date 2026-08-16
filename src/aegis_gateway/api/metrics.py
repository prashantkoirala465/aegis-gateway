from fastapi import APIRouter
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from starlette.responses import Response

router = APIRouter(tags=["metrics"])


@router.get("/metrics")
async def metrics() -> Response:
    """Unauthenticated, like /healthz — Prometheus scrapes typically aren't
    credentialed, and are expected to be reachable only from inside the deployment
    network in a real environment, not exposed publicly. Noted as an accepted
    limitation for a single-instance deployment, not an oversight."""
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
