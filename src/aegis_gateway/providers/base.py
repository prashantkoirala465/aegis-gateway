from collections.abc import AsyncIterator
from typing import Any, Protocol

from aegis_gateway.schemas.chat import ChatCompletionRequest, ChatCompletionResponse


class Provider(Protocol):
    """Every upstream adapter (OpenAI, Ollama, Anthropic once added) implements this.
    Retry, timeout, and circuit-breaker behavior are the implementation's
    responsibility, not something callers opt into per-request — a provider that
    can't uphold that contract shouldn't be wired into the registry."""

    name: str

    async def chat_completion(self, request: ChatCompletionRequest) -> ChatCompletionResponse: ...

    def stream_chat_completion(
        self, request: ChatCompletionRequest
    ) -> AsyncIterator[dict[str, Any]]:
        """Yields already-parsed OpenAI-shaped chunk dicts (one per SSE `data:` line
        from upstream), stopping at `[DONE]` — never raw bytes, so callers don't
        re-implement SSE framing."""
        ...
