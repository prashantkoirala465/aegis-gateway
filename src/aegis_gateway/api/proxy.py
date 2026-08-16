import json
import time
import uuid
from collections.abc import AsyncIterator

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from redis.asyncio import Redis
from redis.commands.core import AsyncScript
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.responses import Response, StreamingResponse

from aegis_gateway.api.deps import (
    get_budget_script,
    get_db_session,
    get_injection_detector,
    get_pii_redactor,
    get_provider_registry,
    get_redis,
    get_settings_dep,
    get_token_bucket_script,
)
from aegis_gateway.core.config import Settings
from aegis_gateway.core.logging import get_logger
from aegis_gateway.detectors.pii import PiiRedactor, redact_messages
from aegis_gateway.detectors.prompt_injection import PromptInjectionDetector
from aegis_gateway.middleware.auth import get_current_tenant
from aegis_gateway.providers.base import Provider
from aegis_gateway.providers.errors import ProviderError, provider_error_to_http_exception
from aegis_gateway.providers.registry import ProviderRegistry, UnknownProviderError
from aegis_gateway.schemas.auth import TenantContext
from aegis_gateway.schemas.chat import ChatCompletionRequest, ChatCompletionResponse, Usage
from aegis_gateway.schemas.errors import openai_error
from aegis_gateway.services.audit import write_audit_event
from aegis_gateway.services.cache import (
    compute_cache_key,
    get_cached_completion,
    store_cached_completion,
)
from aegis_gateway.services.idempotency import (
    get_cached_response,
    release_lock,
    store_response,
    try_acquire_lock,
)
from aegis_gateway.services.rate_limiter import (
    RateLimitExceeded,
    acquire_concurrency_slot,
    enforce_request_limits,
    release_concurrency_slot,
)
from aegis_gateway.services.token_counter import count_prompt_tokens, count_text_tokens
from aegis_gateway.services.usage import record_usage

router = APIRouter(prefix="/v1", tags=["proxy"])
logger = get_logger(__name__)


@router.get("/ping")
async def ping(tenant: TenantContext = Depends(get_current_tenant)) -> dict[str, str]:
    """Auth smoke-test endpoint from the Week-1 milestone, kept around as a cheap
    liveness check for the tenant-facing auth path specifically (vs. /healthz, which
    checks infra, not auth)."""
    return {"status": "ok", "tenant": tenant.tenant_name, "api_key_id": tenant.api_key_id}


def _completion_text(choices: list[dict[str, object]]) -> str:
    parts: list[str] = []
    for choice in choices:
        message = choice.get("message")
        if isinstance(message, dict):
            content = message.get("content")
            if isinstance(content, str):
                parts.append(content)
    return "".join(parts)


def _rate_limit_http_exception(exc: RateLimitExceeded) -> HTTPException:
    headers = {"Retry-After": str(exc.retry_after_seconds)} if exc.retry_after_seconds else None
    return HTTPException(
        status_code=429,
        detail=openai_error(str(exc), error_type="rate_limit_error", code=exc.code),
        headers=headers,
    )


async def _run_security_pipeline(
    *,
    body: ChatCompletionRequest,
    tenant: TenantContext,
    session: AsyncSession,
    correlation_id: str | None,
    pii_redactor: PiiRedactor,
    injection_detector: PromptInjectionDetector,
) -> ChatCompletionRequest:
    """Runs after rate limiting/concurrency (see chat_completions) so an obviously
    abusive request rate can't burn PII/injection-detection compute — that ordering
    is deliberate, see docs/THREAT_MODEL.md. Returns a copy of `body` with PII-
    redacted message content (what actually gets sent upstream, and cached — see
    services/cache.py); raises HTTPException(403) if prompt injection is flagged and
    the tenant's mode is "block". A "log" verdict is recorded but the request
    proceeds.
    """
    messages = body.messages

    if tenant.pii_redaction_enabled:
        messages, entity_types = await redact_messages(pii_redactor, messages)
        if entity_types:
            await write_audit_event(
                session,
                tenant_id=tenant.tenant_id,
                event_type="pii.redacted",
                correlation_id=correlation_id,
                detail={"entity_types": list(entity_types)},
            )

    if tenant.injection_detection_enabled:
        user_text = "\n".join(
            m.content for m in messages if m.role == "user" and isinstance(m.content, str)
        )
        verdict = await injection_detector.detect(user_text)
        if verdict.score >= tenant.injection_detection_threshold:
            blocked = tenant.injection_detection_mode == "block"
            await write_audit_event(
                session,
                tenant_id=tenant.tenant_id,
                event_type="injection.blocked" if blocked else "injection.detected",
                correlation_id=correlation_id,
                detail={
                    "score": round(verdict.score, 3),
                    "matched_heuristic": verdict.matched_heuristic,
                    "matched_embedding": verdict.matched_embedding,
                    "mode": tenant.injection_detection_mode,
                },
            )
            if blocked:
                raise HTTPException(
                    status_code=403,
                    detail=openai_error(
                        "Request flagged as a likely prompt injection attempt.",
                        error_type="invalid_request_error",
                        code="prompt_injection_detected",
                    ),
                )

    return body.model_copy(update={"messages": messages})


@router.post("/chat/completions")
async def chat_completions(
    request: Request,
    body: ChatCompletionRequest,
    tenant: TenantContext = Depends(get_current_tenant),
    session: AsyncSession = Depends(get_db_session),
    redis: Redis = Depends(get_redis),
    registry: ProviderRegistry = Depends(get_provider_registry),
    settings: Settings = Depends(get_settings_dep),
    token_bucket_script: AsyncScript = Depends(get_token_bucket_script),
    budget_script: AsyncScript = Depends(get_budget_script),
    pii_redactor: PiiRedactor = Depends(get_pii_redactor),
    injection_detector: PromptInjectionDetector = Depends(get_injection_detector),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> Response:
    """OpenAI-compatible chat completions.

    Enforcement order: idempotency replay/lock (cheapest — a pure cache hit skips
    everything below) -> rate limits (RPM/TPM/budget, gates the expensive stuff) ->
    concurrency slot (held for the full call/stream duration) -> PII redaction +
    prompt-injection detection (CPU/latency-costly, deliberately gated behind rate
    limiting) -> response cache lookup (on the redacted body — what would actually be
    sent) -> the actual provider call.

    Budget is reserved before the cache lookup, so a cache hit still counts against
    monthly budget even though no real provider cost was incurred — conservative
    (never undercounts), not exact; Phase 6 reconciles against real provider-reported
    usage.
    """
    correlation_id = getattr(request.state, "correlation_id", None)

    if idempotency_key and not body.stream:
        cached = await get_cached_response(redis, tenant.tenant_id, idempotency_key)
        if cached is not None:
            return Response(
                content=cached,
                media_type="application/json",
                headers={"Idempotency-Replayed": "true"},
            )

    if idempotency_key:
        acquired = await try_acquire_lock(redis, tenant.tenant_id, idempotency_key)
        if not acquired:
            raise HTTPException(
                status_code=409,
                detail=openai_error(
                    "A request with this Idempotency-Key is already in progress.",
                    error_type="invalid_request_error",
                    code="idempotency_key_in_use",
                ),
            )

    try:
        provider = registry.resolve(body.model)
    except UnknownProviderError as exc:
        if idempotency_key:
            await release_lock(redis, tenant.tenant_id, idempotency_key)
        raise HTTPException(
            status_code=400,
            detail=openai_error(
                str(exc), error_type="invalid_request_error", code="model_not_found"
            ),
        ) from exc

    prompt_tokens = count_prompt_tokens(body.messages, body.model)

    try:
        await enforce_request_limits(
            redis=redis,
            token_bucket_script=token_bucket_script,
            budget_script=budget_script,
            tenant=tenant,
            provider_name=provider.name,
            model=body.model,
            prompt_tokens=prompt_tokens,
        )
    except RateLimitExceeded as exc:
        if idempotency_key:
            await release_lock(redis, tenant.tenant_id, idempotency_key)
        raise _rate_limit_http_exception(exc) from exc

    if not await acquire_concurrency_slot(
        redis, tenant_id=tenant.tenant_id, limit=tenant.max_concurrent_requests
    ):
        if idempotency_key:
            await release_lock(redis, tenant.tenant_id, idempotency_key)
        raise HTTPException(
            status_code=429,
            detail=openai_error(
                f"Too many concurrent requests (limit {tenant.max_concurrent_requests}).",
                error_type="rate_limit_error",
                code="concurrency_limit_exceeded",
            ),
            headers={"Retry-After": "1"},
        )

    try:
        body = await _run_security_pipeline(
            body=body,
            tenant=tenant,
            session=session,
            correlation_id=correlation_id,
            pii_redactor=pii_redactor,
            injection_detector=injection_detector,
        )
    except HTTPException:
        await release_concurrency_slot(redis, tenant_id=tenant.tenant_id)
        if idempotency_key:
            await release_lock(redis, tenant.tenant_id, idempotency_key)
        raise

    cache_key = compute_cache_key(tenant.tenant_id, body) if tenant.cache_enabled else None
    if cache_key is not None:
        cached_response = await get_cached_completion(redis, cache_key)
        if cached_response is not None:
            await release_concurrency_slot(redis, tenant_id=tenant.tenant_id)
            logger.info(
                "chat.completion.cache_hit",
                tenant_id=str(tenant.tenant_id),
                provider=provider.name,
                model=body.model,
            )
            if body.stream:
                return StreamingResponse(
                    _stream_cached_completion(
                        cached_response,
                        tenant=tenant,
                        provider=provider,
                        session=session,
                        correlation_id=correlation_id,
                        idempotency_key=idempotency_key,
                        redis=redis,
                    ),
                    media_type="text/event-stream",
                )
            if cached_response.usage is not None:
                await record_usage(
                    session,
                    tenant_id=tenant.tenant_id,
                    api_key_id=tenant.api_key_id,
                    provider_name=provider.name,
                    model=body.model,
                    prompt_tokens=cached_response.usage.prompt_tokens,
                    completion_tokens=cached_response.usage.completion_tokens,
                    cache_hit=True,
                    correlation_id=correlation_id,
                )
            response_json = cached_response.model_dump_json()
            if idempotency_key:
                await store_response(redis, tenant.tenant_id, idempotency_key, response_json)
                await release_lock(redis, tenant.tenant_id, idempotency_key)
            return Response(
                content=response_json,
                media_type="application/json",
                headers={"X-Cache": "hit"},
            )

    if body.stream:
        return StreamingResponse(
            _stream_chat_completion(
                provider=provider,
                body=body,
                tenant=tenant,
                session=session,
                prompt_tokens=prompt_tokens,
                idempotency_key=idempotency_key,
                redis=redis,
                cache_key=cache_key,
                cache_ttl_seconds=settings.cache_ttl_seconds,
                correlation_id=correlation_id,
            ),
            media_type="text/event-stream",
        )

    try:
        response = await provider.chat_completion(body)
    except ProviderError as exc:
        if idempotency_key:
            await release_lock(redis, tenant.tenant_id, idempotency_key)
        raise provider_error_to_http_exception(exc) from exc
    finally:
        await release_concurrency_slot(redis, tenant_id=tenant.tenant_id)

    if response.usage is None:
        completion_tokens = count_text_tokens(_completion_text(response.choices), body.model)
        response.usage = Usage(
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=prompt_tokens + completion_tokens,
        )

    logger.info(
        "chat.completion",
        tenant_id=str(tenant.tenant_id),
        provider=provider.name,
        model=body.model,
        prompt_tokens=response.usage.prompt_tokens,
        completion_tokens=response.usage.completion_tokens,
    )

    if cache_key is not None:
        await store_cached_completion(
            redis, cache_key, response, ttl_seconds=settings.cache_ttl_seconds
        )

    await record_usage(
        session,
        tenant_id=tenant.tenant_id,
        api_key_id=tenant.api_key_id,
        provider_name=provider.name,
        model=body.model,
        prompt_tokens=response.usage.prompt_tokens,
        completion_tokens=response.usage.completion_tokens,
        cache_hit=False,
        correlation_id=correlation_id,
    )

    response_json = response.model_dump_json()
    if idempotency_key:
        await store_response(redis, tenant.tenant_id, idempotency_key, response_json)
        await release_lock(redis, tenant.tenant_id, idempotency_key)

    return Response(
        content=response_json, media_type="application/json", headers={"X-Cache": "miss"}
    )


async def _stream_cached_completion(
    response: ChatCompletionResponse,
    *,
    tenant: TenantContext,
    provider: Provider,
    session: AsyncSession,
    correlation_id: str | None,
    idempotency_key: str | None,
    redis: Redis,
) -> AsyncIterator[bytes]:
    """A cache hit still has to satisfy a streaming client. Rather than storing and
    replaying the original SSE frame sequence (materially more complex, and the same
    tradeoff idempotency's streaming path already makes — see _stream_chat_completion),
    this synthesizes a single chunk carrying the full cached content."""
    chunk = {
        "id": response.id,
        "object": "chat.completion.chunk",
        "created": response.created,
        "model": response.model,
        "choices": [
            {
                "index": 0,
                "delta": {"role": "assistant", "content": _completion_text(response.choices)},
                "finish_reason": "stop",
            }
        ],
    }
    try:
        yield f"data: {json.dumps(chunk)}\n\n".encode()
        yield b"data: [DONE]\n\n"
    finally:
        if response.usage is not None:
            await record_usage(
                session,
                tenant_id=tenant.tenant_id,
                api_key_id=tenant.api_key_id,
                provider_name=provider.name,
                model=response.model,
                prompt_tokens=response.usage.prompt_tokens,
                completion_tokens=response.usage.completion_tokens,
                cache_hit=True,
                correlation_id=correlation_id,
            )
        if idempotency_key:
            await release_lock(redis, tenant.tenant_id, idempotency_key)


async def _stream_chat_completion(
    *,
    provider: Provider,
    body: ChatCompletionRequest,
    tenant: TenantContext,
    session: AsyncSession,
    prompt_tokens: int,
    idempotency_key: str | None,
    redis: Redis,
    cache_key: str | None,
    cache_ttl_seconds: int,
    correlation_id: str | None,
) -> AsyncIterator[bytes]:
    """SSE re-framing: upstream chunks are already OpenAI-shaped dicts (see
    Provider.stream_chat_completion), so this only has to re-serialize them, not
    transform them. Idempotency for streaming requests only guards against a
    concurrent duplicate submission (the lock) — there is deliberately no replay
    cache here, since replaying a stored SSE stream byte-for-byte is materially more
    complex than replaying one cached JSON body and isn't worth it for this project's
    scope. A retried streaming request just runs again. The concurrency slot acquired
    by the caller is held for this entire generator's lifetime and released here,
    since that's the actual duration the tenant occupies an upstream connection.

    On a successful stream, the accumulated content is stored under `cache_key` (if
    caching is enabled) as an ordinary non-streaming-shaped response — a future
    streaming *or* non-streaming request with the same cache key gets it back via
    _stream_cached_completion or the plain JSON path respectively. Nothing is cached
    if the stream errors partway through.
    """
    completion_parts: list[str] = []
    succeeded = True
    try:
        async for chunk in provider.stream_chat_completion(body):
            for choice in chunk.get("choices") or []:
                delta = choice.get("delta") if isinstance(choice, dict) else None
                if isinstance(delta, dict):
                    content = delta.get("content")
                    if isinstance(content, str):
                        completion_parts.append(content)
            yield f"data: {json.dumps(chunk)}\n\n".encode()
        yield b"data: [DONE]\n\n"
    except ProviderError as exc:
        succeeded = False
        error_payload = openai_error(str(exc), error_type="upstream_error", code="provider_error")
        yield f"data: {json.dumps(error_payload)}\n\n".encode()
    finally:
        completion_text = "".join(completion_parts)
        completion_tokens = count_text_tokens(completion_text, body.model)
        logger.info(
            "chat.completion.streamed",
            tenant_id=str(tenant.tenant_id),
            provider=provider.name,
            model=body.model,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
        )
        if succeeded:
            await record_usage(
                session,
                tenant_id=tenant.tenant_id,
                api_key_id=tenant.api_key_id,
                provider_name=provider.name,
                model=body.model,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                cache_hit=False,
                correlation_id=correlation_id,
            )
        if succeeded and cache_key is not None and completion_text:
            cacheable = ChatCompletionResponse(
                id=f"chatcmpl-cache-{uuid.uuid4().hex}",
                created=int(time.time()),
                model=body.model,
                choices=[
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": completion_text},
                        "finish_reason": "stop",
                    }
                ],
                usage=Usage(
                    prompt_tokens=prompt_tokens,
                    completion_tokens=completion_tokens,
                    total_tokens=prompt_tokens + completion_tokens,
                ),
            )
            await store_cached_completion(
                redis, cache_key, cacheable, ttl_seconds=cache_ttl_seconds
            )
        await release_concurrency_slot(redis, tenant_id=tenant.tenant_id)
        if idempotency_key:
            await release_lock(redis, tenant.tenant_id, idempotency_key)
