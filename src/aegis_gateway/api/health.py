from fastapi import APIRouter, Request
from sqlalchemy import text
from starlette.responses import JSONResponse

router = APIRouter(tags=["health"])


@router.get("/healthz")
async def healthz(request: Request) -> JSONResponse:
    """Liveness + dependency check. Unauthenticated by design (load balancer / k8s probe)."""
    checks: dict[str, str] = {}

    try:
        async with request.app.state.sessionmaker() as session:
            await session.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception as exc:  # noqa: BLE001 - health check must never raise, only report
        checks["database"] = f"error: {exc}"

    try:
        await request.app.state.redis.ping()
        checks["redis"] = "ok"
    except Exception as exc:  # noqa: BLE001
        checks["redis"] = f"error: {exc}"

    healthy = all(v == "ok" for v in checks.values())
    return JSONResponse(
        status_code=200 if healthy else 503,
        content={"status": "ok" if healthy else "degraded", "checks": checks},
    )
