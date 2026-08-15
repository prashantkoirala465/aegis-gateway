from collections.abc import Callable

import httpx
import pytest

from aegis_gateway.providers.circuit_breaker import CircuitBreaker, CircuitState
from aegis_gateway.providers.errors import CircuitOpenError, UpstreamStatusError
from aegis_gateway.providers.openai_compatible import OpenAICompatibleProvider
from aegis_gateway.schemas.chat import ChatCompletionRequest, ChatMessage

REQUEST = ChatCompletionRequest(model="gpt-test", messages=[ChatMessage(role="user", content="hi")])


def _client_with_handler(handler: Callable[[httpx.Request], httpx.Response]) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _completion_body(content: str = "hello") -> dict:
    return {
        "id": "chatcmpl-1",
        "object": "chat.completion",
        "created": 0,
        "model": "gpt-test",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": content}}],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
    }


async def test_chat_completion_success() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json=_completion_body())

    provider = OpenAICompatibleProvider(
        name="test", base_url="https://example.test/v1", client=_client_with_handler(handler)
    )
    response = await provider.chat_completion(REQUEST)
    assert response.choices[0]["message"]["content"] == "hello"
    assert calls == 1


async def test_chat_completion_retries_transient_failure_then_succeeds() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls < 3:
            return httpx.Response(503, text="temporarily unavailable")
        return httpx.Response(200, json=_completion_body())

    provider = OpenAICompatibleProvider(
        name="test",
        base_url="https://example.test/v1",
        client=_client_with_handler(handler),
        max_attempts=5,
    )
    response = await provider.chat_completion(REQUEST)
    assert response.id == "chatcmpl-1"
    assert calls == 3


async def test_chat_completion_does_not_retry_client_error() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(400, text="bad request")

    provider = OpenAICompatibleProvider(
        name="test",
        base_url="https://example.test/v1",
        client=_client_with_handler(handler),
        max_attempts=5,
    )
    with pytest.raises(UpstreamStatusError) as exc_info:
        await provider.chat_completion(REQUEST)
    assert exc_info.value.status_code == 400
    assert calls == 1


async def test_circuit_opens_after_threshold_and_stops_calling_transport() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(500, text="server error")

    breaker = CircuitBreaker(name="test", failure_threshold=2, recovery_timeout=30)
    provider = OpenAICompatibleProvider(
        name="test",
        base_url="https://example.test/v1",
        client=_client_with_handler(handler),
        max_attempts=1,  # isolate breaker behavior from retry behavior
        circuit_breaker=breaker,
    )

    with pytest.raises(UpstreamStatusError):
        await provider.chat_completion(REQUEST)
    with pytest.raises(UpstreamStatusError):
        await provider.chat_completion(REQUEST)
    assert breaker.state == CircuitState.OPEN
    assert calls == 2

    with pytest.raises(CircuitOpenError):
        await provider.chat_completion(REQUEST)
    assert calls == 2  # circuit failed fast — no third transport call


async def test_stream_chat_completion_yields_parsed_chunks() -> None:
    sse_body = (
        b'data: {"id":"1","choices":[{"delta":{"content":"Hel"}}]}\n\n'
        b'data: {"id":"1","choices":[{"delta":{"content":"lo"}}]}\n\n'
        b"data: [DONE]\n\n"
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=sse_body, headers={"content-type": "text/event-stream"})

    provider = OpenAICompatibleProvider(
        name="test", base_url="https://example.test/v1", client=_client_with_handler(handler)
    )
    chunks = [chunk async for chunk in provider.stream_chat_completion(REQUEST)]
    assert [c["choices"][0]["delta"]["content"] for c in chunks] == ["Hel", "lo"]
