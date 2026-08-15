import json
from collections.abc import AsyncIterator

from fastapi import APIRouter, Depends, Header, HTTPException
from redis.asyncio import Redis
from starlette.responses import Response, StreamingResponse

from aegis_gateway.api.deps import get_provider_registry, get_redis
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


@router.post("/chat/completions")
async def chat_completions(
    body: ChatCompletionRequest,
    tenant: TenantContext = Depends(get_current_tenant),
    redis: Redis = Depends(get_redis),
    registry: ProviderRegistry = Depends(get_provider_registry),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> Response:
    """OpenAI-compatible chat completions. Rate limiting and the PII/prompt-injection
    security pipeline land in Phase 3/4 — this endpoint is the provider-proxying core
    they'll wrap: auth, idempotency, routing, retries/circuit-breaker (in the provider
    adapter), streaming, and approximate token counting.
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
    scope. A retried streaming request just runs again.
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
        if idempotency_key:
            await release_lock(redis, tenant.tenant_id, idempotency_key)
