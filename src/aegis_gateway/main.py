import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.exception_handlers import http_exception_handler as default_http_exception_handler
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from starlette.responses import JSONResponse, Response

from aegis_gateway.api.admin import router as admin_router
from aegis_gateway.api.health import router as health_router
from aegis_gateway.api.metrics import router as metrics_router
from aegis_gateway.api.proxy import router as proxy_router
from aegis_gateway.core.config import get_settings
from aegis_gateway.core.logging import configure_logging, get_logger
from aegis_gateway.core.tracing import configure_tracing
from aegis_gateway.db.redis import build_redis_client, build_redis_pool
from aegis_gateway.db.session import build_engine, build_sessionmaker
from aegis_gateway.detectors.pii import PiiRedactor
from aegis_gateway.detectors.prompt_injection import PromptInjectionDetector
from aegis_gateway.middleware.metrics import PrometheusMiddleware
from aegis_gateway.middleware.request_id import CorrelationIdMiddleware
from aegis_gateway.providers.registry import build_provider_registry
from aegis_gateway.services.rate_limiter import register_rate_limit_scripts

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
    token_bucket_script, budget_script = register_rate_limit_scripts(redis_client)

    # PiiRedactor() loads a spaCy model — CPU-bound and slow enough (hundreds of ms)
    # to run off the event loop even at startup, not just per-request.
    pii_redactor = await asyncio.to_thread(PiiRedactor)
    injection_detector = PromptInjectionDetector(
        http_client=provider_http_client, api_key=settings.openai_api_key
    )
    await injection_detector.warm_up()

    app.state.settings = settings
    app.state.engine = engine
    app.state.sessionmaker = sessionmaker
    app.state.redis = redis_client
    app.state.providers = providers
    app.state.token_bucket_script = token_bucket_script
    app.state.budget_script = budget_script
    app.state.pii_redactor = pii_redactor
    app.state.injection_detector = injection_detector

    logger.info("startup.complete", environment=settings.environment)
    try:
        yield
    finally:
        logger.info("shutdown.begin")
        app.state.tracer_provider.shutdown()  # flushes any batched spans before exit
        await provider_http_client.aclose()
        await redis_client.aclose()
        await redis_pool.disconnect()
        await engine.dispose()
        logger.info("shutdown.complete")


def create_app() -> FastAPI:
    settings = get_settings()
    tracer_provider = configure_tracing(settings)

    app = FastAPI(
        title="Aegis Gateway",
        description=(
            "Multi-tenant security gateway for LLM providers: auth, rate limiting, "
            "prompt-injection & PII filtering, caching, cost tracking, audit logging."
        ),
        version="0.1.0",
        lifespan=lifespan,
    )
    app.state.tracer_provider = tracer_provider
    # Middleware added later wraps those added earlier, so Prometheus (added second)
    # sits outermost and times the *entire* request, correlation-ID setup included.
    app.add_middleware(CorrelationIdMiddleware)
    app.add_middleware(PrometheusMiddleware)
    app.include_router(health_router)
    app.include_router(metrics_router)
    app.include_router(admin_router)
    app.include_router(proxy_router)
    app.add_exception_handler(HTTPException, openai_style_http_exception_handler)
    FastAPIInstrumentor.instrument_app(app)
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
