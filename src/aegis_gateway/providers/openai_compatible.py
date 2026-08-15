import json
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any

import httpx

from aegis_gateway.providers.circuit_breaker import CircuitBreaker
from aegis_gateway.providers.errors import (
    ProviderError,
    UpstreamConnectionError,
    UpstreamStatusError,
    UpstreamTimeoutError,
)
from aegis_gateway.providers.retry import RETRYABLE_STATUS_CODES, call_with_retry
from aegis_gateway.schemas.chat import ChatCompletionRequest, ChatCompletionResponse


def _is_retryable(exc: Exception) -> bool:
    if isinstance(exc, httpx.TimeoutException | httpx.ConnectError):
        return True
    if isinstance(exc, UpstreamStatusError):
        return exc.status_code in RETRYABLE_STATUS_CODES
    return False


class OpenAICompatibleProvider:
    """Adapter for any upstream speaking OpenAI's chat-completions wire format —
    covers both OpenAI itself and Ollama (which implements an OpenAI-compatible
    `/v1/chat/completions` endpoint), so one implementation serves both rather than
    duplicating request/response handling per provider.

    `base_url` is a fixed, server-side setting (never tenant-supplied) — an
    attacker-controlled upstream URL would be an SSRF vector into internal
    infrastructure, so that surface deliberately does not exist yet.
    """

    def __init__(
        self,
        *,
        name: str,
        base_url: str,
        client: httpx.AsyncClient,
        api_key: str | None = None,
        timeout: float = 30.0,
        max_attempts: int = 3,
        circuit_breaker: CircuitBreaker | None = None,
    ) -> None:
        self.name = name
        self._base_url = base_url.rstrip("/")
        self._client = client
        self._api_key = api_key
        self._timeout = timeout
        self._max_attempts = max_attempts
        self._breaker = circuit_breaker or CircuitBreaker(name=name)

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        return headers

    async def _run_with_breaker[T](self, coro_factory: Callable[[], Awaitable[T]]) -> T:
        await self._breaker.before_call()
        try:
            result = await call_with_retry(
                coro_factory, is_retryable=_is_retryable, max_attempts=self._max_attempts
            )
        except httpx.TimeoutException as exc:
            await self._breaker.record_failure()
            raise UpstreamTimeoutError(str(exc)) from exc
        except httpx.ConnectError as exc:
            await self._breaker.record_failure()
            raise UpstreamConnectionError(str(exc)) from exc
        except UpstreamStatusError:
            await self._breaker.record_failure()
            raise
        else:
            await self._breaker.record_success()
            return result

    async def _post_once(self, payload: dict[str, Any]) -> dict[str, Any]:
        response = await self._client.post(
            f"{self._base_url}/chat/completions",
            json=payload,
            headers=self._headers(),
            timeout=self._timeout,
        )
        if response.status_code >= 400:
            raise UpstreamStatusError(response.status_code, response.text)
        result: dict[str, Any] = response.json()
        return result

    async def chat_completion(self, request: ChatCompletionRequest) -> ChatCompletionResponse:
        payload = request.model_dump(exclude_none=True)
        payload["stream"] = False
        raw = await self._run_with_breaker(lambda: self._post_once(payload))
        return ChatCompletionResponse.model_validate(raw)

    async def _open_stream(self, payload: dict[str, Any]) -> httpx.Response:
        """Retried/breaker-guarded connect phase only — once headers come back clean,
        the caller owns the response and must close it. Retrying mid-stream would mean
        re-sending a request whose partial output the client may already have seen, so
        deliberately out of scope: a dropped stream after the first chunk surfaces as
        an error to the caller instead of a silent, possibly duplicated retry."""
        request = self._client.build_request(
            "POST",
            f"{self._base_url}/chat/completions",
            json=payload,
            headers=self._headers(),
            timeout=self._timeout,
        )
        response = await self._client.send(request, stream=True)
        if response.status_code >= 400:
            body = await response.aread()
            await response.aclose()
            raise UpstreamStatusError(response.status_code, body.decode(errors="replace"))
        return response

    async def stream_chat_completion(
        self, request: ChatCompletionRequest
    ) -> AsyncIterator[dict[str, Any]]:
        payload = request.model_dump(exclude_none=True)
        payload["stream"] = True

        response = await self._run_with_breaker(lambda: self._open_stream(payload))
        try:
            async for line in response.aiter_lines():
                if not line.startswith("data:"):
                    continue
                data = line.removeprefix("data:").strip()
                if not data or data == "[DONE]":
                    break
                try:
                    yield json.loads(data)
                except json.JSONDecodeError as exc:
                    raise ProviderError(
                        f"malformed SSE chunk from {self.name}: {data[:200]}"
                    ) from exc
        finally:
            await response.aclose()
