import json
from collections.abc import AsyncIterator

from fastapi import APIRouter, Depends, Header, HTTPException
from redis.asyncio import Redis
from redis.commands.core import AsyncScript
from starlette.responses import Response, StreamingResponse

from aegis_gateway.api.deps import (
    get_budget_script,
    get_provider_registry,
    get_redis,
    get_token_bucket_script,
)
from aegis_gateway.core.logging import get_logger
from aegis_gateway.middleware.auth import get_current_tenant
from aegis_gateway.providers.base import Provider
from aegis_gateway.providers.errors import ProviderError, provider_error_to_http_exception
from aegis_gateway.providers.registry import ProviderRegistry, UnknownProviderError
from aegis_gateway.schemas.auth import TenantContext
from aegis_gateway.schemas.chat import ChatCompletionRequest, Usage
from aegis_gateway.schemas.errors import openai_error
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


@router.post("/chat/completions")
async def chat_completions(
    body: ChatCompletionRequest,
    tenant: TenantContext = Depends(get_current_tenant),
    redis: Redis = Depends(get_redis),
    registry: ProviderRegistry = Depends(get_provider_registry),
    token_bucket_script: AsyncScript = Depends(get_token_bucket_script),
    budget_script: AsyncScript = Depends(get_budget_script),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> Response:
    """OpenAI-compatible chat completions. The PII/prompt-injection security pipeline
    lands in Phase 4, wrapping this same core: auth, rate limiting, idempotency,
    routing, retries/circuit-breaker (in the provider adapter), streaming, and
    approximate token counting.

    Enforcement order: idempotency replay/lock (cheapest — a pure cache hit skips
    everything below) -> rate limits (RPM/TPM/budget, gates the expensive stuff) ->
    concurrency slot (held for the full call/stream duration) -> the actual provider
    call. See services/rate_limiter.py for why RPM/TPM/budget need one atomic Lua
    round trip each but concurrency doesn't.
    """
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

    if body.stream:
        return StreamingResponse(
            _stream_chat_completion(
                provider=provider,
                body=body,
                tenant=tenant,
                prompt_tokens=prompt_tokens,
                idempotency_key=idempotency_key,
                redis=redis,
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

    response_json = response.model_dump_json()
    if idempotency_key:
        await store_response(redis, tenant.tenant_id, idempotency_key, response_json)
        await release_lock(redis, tenant.tenant_id, idempotency_key)

    return Response(content=response_json, media_type="application/json")


async def _stream_chat_completion(
    *,
    provider: Provider,
    body: ChatCompletionRequest,
    tenant: TenantContext,
    prompt_tokens: int,
    idempotency_key: str | None,
    redis: Redis,
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
    """
    completion_parts: list[str] = []
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
        error_payload = openai_error(str(exc), error_type="upstream_error", code="provider_error")
        yield f"data: {json.dumps(error_payload)}\n\n".encode()
    finally:
        completion_tokens = count_text_tokens("".join(completion_parts), body.model)
        logger.info(
            "chat.completion.streamed",
            tenant_id=str(tenant.tenant_id),
            provider=provider.name,
            model=body.model,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
        )
        await release_concurrency_slot(redis, tenant_id=tenant.tenant_id)
        if idempotency_key:
            await release_lock(redis, tenant.tenant_id, idempotency_key)
