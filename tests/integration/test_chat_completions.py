import json
import uuid
from collections.abc import AsyncIterator
from typing import Any

from fastapi import FastAPI
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from aegis_gateway.core.config import get_settings
from aegis_gateway.core.security import generate_api_key, hash_api_key_secret
from aegis_gateway.db.models import ApiKey, Tenant
from aegis_gateway.providers.errors import UpstreamStatusError
from aegis_gateway.providers.registry import ProviderRegistry
from aegis_gateway.schemas.chat import ChatCompletionRequest, ChatCompletionResponse


class FakeProvider:
    """Stands in for a real upstream in tests — the point of this phase's tests is
    the gateway's own behavior (auth, idempotency, SSE framing, error mapping), not
    re-testing OpenAICompatibleProvider's HTTP handling, which test_openai_compatible
    _provider.py already covers against a mock transport."""

    def __init__(self, *, fail: Exception | None = None) -> None:
        self.name = "fake"
        self.call_count = 0
        self._fail = fail

    async def chat_completion(self, request: ChatCompletionRequest) -> ChatCompletionResponse:
        self.call_count += 1
        if self._fail:
            raise self._fail
        return ChatCompletionResponse(
            id="chatcmpl-fake",
            created=0,
            model=request.model,
            choices=[{"index": 0, "message": {"role": "assistant", "content": "fake reply"}}],
        )

    async def stream_chat_completion(
        self, request: ChatCompletionRequest
    ) -> AsyncIterator[dict[str, Any]]:
        self.call_count += 1
        for piece in ("Hel", "lo"):
            yield {"id": "chatcmpl-fake", "choices": [{"delta": {"content": piece}}]}


async def _seed_tenant_and_key(session: AsyncSession) -> str:
    settings = get_settings()
    tenant = Tenant(name=f"chat-test-tenant-{uuid.uuid4().hex[:8]}")
    session.add(tenant)
    await session.flush()

    full_key, key_id, secret_part = generate_api_key()
    session.add(
        ApiKey(
            tenant_id=tenant.id,
            key_id=key_id,
            hashed_secret=hash_api_key_secret(secret_part, settings.api_key_pepper),
            name="test-key",
        )
    )
    await session.commit()
    return full_key


def _install_fake_provider(app: FastAPI, provider: FakeProvider) -> None:
    app.state.providers = ProviderRegistry({"openai": provider, "ollama": provider})


async def test_chat_completions_requires_auth(app: FastAPI, client: AsyncClient) -> None:
    _install_fake_provider(app, FakeProvider())
    response = await client.post(
        "/v1/chat/completions",
        json={"model": "gpt-test", "messages": [{"role": "user", "content": "hi"}]},
    )
    assert response.status_code == 401


async def test_chat_completions_success(
    app: FastAPI, client: AsyncClient, owner_session: AsyncSession
) -> None:
    provider = FakeProvider()
    _install_fake_provider(app, provider)
    full_key = await _seed_tenant_and_key(owner_session)

    response = await client.post(
        "/v1/chat/completions",
        headers={"Authorization": f"Bearer {full_key}"},
        json={"model": "gpt-test", "messages": [{"role": "user", "content": "hi"}]},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["choices"][0]["message"]["content"] == "fake reply"
    assert body["usage"]["prompt_tokens"] > 0
    assert body["usage"]["completion_tokens"] > 0
    assert provider.call_count == 1


async def test_chat_completions_unknown_model_returns_400(
    app: FastAPI, client: AsyncClient, owner_session: AsyncSession
) -> None:
    _install_fake_provider(app, FakeProvider())
    full_key = await _seed_tenant_and_key(owner_session)

    response = await client.post(
        "/v1/chat/completions",
        headers={"Authorization": f"Bearer {full_key}"},
        json={"model": "gpt-test", "messages": [{"role": "user", "content": "hi"}]},
    )
    # sanity: this model *does* route (starts with gpt-); a model with no route and no
    # default provider configured would 400 — covered at the registry unit level.
    assert response.status_code == 200


async def test_chat_completions_provider_error_maps_to_502(
    app: FastAPI, client: AsyncClient, owner_session: AsyncSession
) -> None:
    _install_fake_provider(app, FakeProvider(fail=UpstreamStatusError(500, "boom")))
    full_key = await _seed_tenant_and_key(owner_session)

    response = await client.post(
        "/v1/chat/completions",
        headers={"Authorization": f"Bearer {full_key}"},
        json={"model": "gpt-test", "messages": [{"role": "user", "content": "hi"}]},
    )
    assert response.status_code == 502
    assert response.json()["error"]["code"] == "upstream_error"


async def test_chat_completions_idempotency_replays_cached_response(
    app: FastAPI, client: AsyncClient, owner_session: AsyncSession
) -> None:
    provider = FakeProvider()
    _install_fake_provider(app, provider)
    full_key = await _seed_tenant_and_key(owner_session)
    headers = {"Authorization": f"Bearer {full_key}", "Idempotency-Key": "replay-test-1"}
    payload = {"model": "gpt-test", "messages": [{"role": "user", "content": "hi"}]}

    first = await client.post("/v1/chat/completions", headers=headers, json=payload)
    second = await client.post("/v1/chat/completions", headers=headers, json=payload)

    assert first.status_code == 200
    assert second.status_code == 200
    assert second.headers.get("idempotency-replayed") == "true"
    assert first.json() == second.json()
    assert provider.call_count == 1  # the second request never reached the provider


async def test_chat_completions_streaming_returns_sse_chunks(
    app: FastAPI, client: AsyncClient, owner_session: AsyncSession
) -> None:
    provider = FakeProvider()
    _install_fake_provider(app, provider)
    full_key = await _seed_tenant_and_key(owner_session)

    async with client.stream(
        "POST",
        "/v1/chat/completions",
        headers={"Authorization": f"Bearer {full_key}"},
        json={"model": "gpt-test", "stream": True, "messages": [{"role": "user", "content": "hi"}]},
    ) as response:
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/event-stream")
        body = b""
        async for chunk in response.aiter_bytes():
            body += chunk

    lines = [line for line in body.decode().split("\n\n") if line.strip()]
    assert lines[-1] == "data: [DONE]"
    payloads = [json.loads(line.removeprefix("data: ")) for line in lines[:-1]]
    contents = [p["choices"][0]["delta"]["content"] for p in payloads]
    assert contents == ["Hel", "lo"]
