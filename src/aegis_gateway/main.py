from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.exception_handlers import http_exception_handler as default_http_exception_handler
from starlette.responses import JSONResponse, Response

from aegis_gateway.api.admin import router as admin_router
from aegis_gateway.api.health import router as health_router
from aegis_gateway.api.proxy import router as proxy_router
from aegis_gateway.core.config import get_settings
from aegis_gateway.core.logging import configure_logging, get_logger
from aegis_gateway.db.redis import build_redis_client, build_redis_pool
from aegis_gateway.db.session import build_engine, build_sessionmaker
from aegis_gateway.middleware.request_id import CorrelationIdMiddleware
from aegis_gateway.providers.registry import build_provider_registry

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Owns the process-lifetime resources: DB engine, Redis pool.

    Graceful shutdown: FastAPI/uvicorn stop accepting new connections on SIGTERM and
    wait for in-flight requests (including SSE streams) to drain before this generator
    resumes past `yield`, so closing the pools here happens only after that drain.
    """
    settings = get_settings()
    configure_logging(settings)

    engine = build_engine(settings)
    sessionmaker = build_sessionmaker(engine)
    redis_pool = build_redis_pool(settings)
    redis_client = build_redis_client(redis_pool)

    # Single shared client (and connection-pool limits) across every provider call in
    # the process — bounds total upstream concurrency instead of letting each request
    # open its own connection, which is what actually protects the process under load.
    provider_http_client = httpx.AsyncClient(
        limits=httpx.Limits(
            max_connections=settings.provider_max_connections,
            max_keepalive_connections=settings.provider_max_keepalive_connections,
        )
    )
    providers = build_provider_registry(settings, client=provider_http_client)

    app.state.settings = settings
    app.state.engine = engine
    app.state.sessionmaker = sessionmaker
    app.state.redis = redis_client
    app.state.providers = providers

    logger.info("startup.complete", environment=settings.environment)
    try:
        yield
    finally:
        logger.info("shutdown.begin")
        await provider_http_client.aclose()
        await redis_client.aclose()
        await redis_pool.disconnect()
        await engine.dispose()
        logger.info("shutdown.complete")


def create_app() -> FastAPI:
    app = FastAPI(
        title="Aegis Gateway",
        description=(
            "Multi-tenant security gateway for LLM providers: auth, rate limiting, "
            "prompt-injection & PII filtering, caching, cost tracking, audit logging."
        ),
        version="0.1.0",
        lifespan=lifespan,
    )
    app.add_middleware(CorrelationIdMiddleware)
    app.include_router(health_router)
    app.include_router(admin_router)
    app.include_router(proxy_router)
    app.add_exception_handler(HTTPException, openai_style_http_exception_handler)
    return app


async def openai_style_http_exception_handler(request: Request, exc: Exception) -> Response:
    """Errors raised via schemas.errors (UnauthorizedError etc.) already carry an
    OpenAI-shaped {"error": {...}} detail — pass those through verbatim so any OpenAI
    SDK pointed at this gateway parses them correctly. Anything else falls back to
    FastAPI's default {"detail": ...} envelope."""
    assert isinstance(exc, HTTPException)  # narrowed by add_exception_handler registration
    if isinstance(exc.detail, dict) and "error" in exc.detail:
        return JSONResponse(status_code=exc.status_code, content=exc.detail, headers=exc.headers)
    return await default_http_exception_handler(request, exc)


app = create_app()
