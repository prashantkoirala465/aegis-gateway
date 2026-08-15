import httpx

from aegis_gateway.core.config import Settings
from aegis_gateway.providers.base import Provider
from aegis_gateway.providers.circuit_breaker import CircuitBreaker
from aegis_gateway.providers.openai_compatible import OpenAICompatibleProvider

OPENAI_BASE_URL = "https://api.openai.com/v1"

# Fixed, server-side model -> provider routing. A generic per-tenant routing config is
# explicitly out of scope (see ADR-0003-style reasoning: a rules engine is its own
# project) — this is a small typed table, not a DSL, extended by editing this file.
_MODEL_PREFIX_ROUTES: tuple[tuple[str, str], ...] = (
    ("gpt-", "openai"),
    ("o1", "openai"),
    ("o3", "openai"),
    ("o4", "openai"),
)
_DEFAULT_PROVIDER = "ollama"


class UnknownProviderError(Exception):
    pass


class ProviderRegistry:
    def __init__(self, providers: dict[str, Provider]) -> None:
        self._providers = providers

    def resolve(self, model: str) -> Provider:
        for prefix, provider_name in _MODEL_PREFIX_ROUTES:
            if model.startswith(prefix):
                provider = self._providers.get(provider_name)
                if provider is not None:
                    return provider
        provider = self._providers.get(_DEFAULT_PROVIDER)
        if provider is None:
            raise UnknownProviderError(
                f"no provider configured to handle model '{model}' "
                f"(known: {sorted(self._providers)})"
            )
        return provider


def build_provider_registry(settings: Settings, *, client: httpx.AsyncClient) -> ProviderRegistry:
    def breaker(name: str) -> CircuitBreaker:
        return CircuitBreaker(
            name=name,
            failure_threshold=settings.circuit_breaker_failure_threshold,
            recovery_timeout=settings.circuit_breaker_recovery_seconds,
        )

    providers: dict[str, Provider] = {
        "openai": OpenAICompatibleProvider(
            name="openai",
            base_url=OPENAI_BASE_URL,
            client=client,
            api_key=settings.openai_api_key or None,
            timeout=settings.provider_timeout_seconds,
            max_attempts=settings.provider_max_attempts,
            circuit_breaker=breaker("openai"),
        ),
        "ollama": OpenAICompatibleProvider(
            name="ollama",
            base_url=f"{settings.ollama_base_url.rstrip('/')}/v1",
            client=client,
            api_key=None,
            timeout=settings.provider_timeout_seconds,
            max_attempts=settings.provider_max_attempts,
            circuit_breaker=breaker("ollama"),
        ),
    }
    return ProviderRegistry(providers)
