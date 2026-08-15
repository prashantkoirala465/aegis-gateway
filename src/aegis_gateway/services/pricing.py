"""Static, approximate pricing used only to feed the Redis budget guardrail
(services/rate_limiter.py) — a fast, best-effort check that stops a tenant from
blowing through its monthly cap, not a billing system. Exact, reconciled cost
accounting against real provider-reported usage is Phase 6's job and will use actual
response usage data, not this table. Prices are prompt-token-only (completion cost
isn't knowable before the call is made) and USD per 1,000 tokens.
"""

_PRICE_PER_1K_PROMPT_TOKENS_USD: dict[str, float] = {
    "gpt-4o": 0.0025,
    "gpt-4o-mini": 0.00015,
    "gpt-4-turbo": 0.01,
    "gpt-4": 0.03,
    "gpt-3.5-turbo": 0.0005,
}
_DEFAULT_PRICE_PER_1K_USD = 0.001  # unknown OpenAI-routed model: conservative guess
_OLLAMA_PRICE_PER_1K_USD = 0.0  # self-hosted — no per-token cost to guard against


def estimate_prompt_cost_usd(*, model: str, prompt_tokens: int, provider_name: str) -> float:
    if provider_name == "ollama":
        return (prompt_tokens / 1000) * _OLLAMA_PRICE_PER_1K_USD
    for prefix, price in _PRICE_PER_1K_PROMPT_TOKENS_USD.items():
        if model.startswith(prefix):
            return (prompt_tokens / 1000) * price
    return (prompt_tokens / 1000) * _DEFAULT_PRICE_PER_1K_USD
