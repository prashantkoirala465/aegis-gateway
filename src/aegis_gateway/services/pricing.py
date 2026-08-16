"""Static pricing, USD per 1,000,000 tokens (matching how providers actually publish
rates), as (prompt_price, completion_price) — the two differ significantly for real
models (e.g. gpt-4o: $2.50/1M input vs $10/1M output), so a single blended rate would
misprice anything with an atypical prompt:completion ratio.

Two consumers, two different jobs:
- estimate_prompt_cost_usd: prompt-only, used pre-flight by the Redis budget
  guardrail (services/rate_limiter.py) before a completion exists to cost.
- calculate_cost_usd: prompt + completion, used post-response for the durable,
  exact usage_records row (services/usage.py, Phase 6) — this is the real number;
  the guardrail's pre-flight estimate is deliberately conservative and approximate.
"""

_PRICE_PER_1M_TOKENS_USD: dict[str, tuple[float, float]] = {
    "gpt-4o-mini": (0.15, 0.60),
    "gpt-4o": (2.50, 10.00),
    "gpt-4-turbo": (10.00, 30.00),
    "gpt-4": (30.00, 60.00),
    "gpt-3.5-turbo": (0.50, 1.50),
}
_DEFAULT_PRICE_PER_1M_USD = (1.00, 3.00)  # unknown OpenAI-routed model: conservative guess
_OLLAMA_PRICE_PER_1M_USD = (0.0, 0.0)  # self-hosted — no per-token cost


def _price_for(model: str, provider_name: str) -> tuple[float, float]:
    if provider_name == "ollama":
        return _OLLAMA_PRICE_PER_1M_USD
    for prefix, price in _PRICE_PER_1M_TOKENS_USD.items():
        if model.startswith(prefix):
            return price
    return _DEFAULT_PRICE_PER_1M_USD


def estimate_prompt_cost_usd(*, model: str, prompt_tokens: int, provider_name: str) -> float:
    prompt_price, _completion_price = _price_for(model, provider_name)
    return (prompt_tokens / 1_000_000) * prompt_price


def calculate_cost_usd(
    *, model: str, prompt_tokens: int, completion_tokens: int, provider_name: str
) -> float:
    prompt_price, completion_price = _price_for(model, provider_name)
    return (prompt_tokens / 1_000_000) * prompt_price + (
        completion_tokens / 1_000_000
    ) * completion_price
