"""Prometheus metrics. Deliberately no tenant_id (or any other unbounded-cardinality
value) on any label — Prometheus's storage is O(unique label combinations), and a
label that grows with the number of tenants turns every metric into a slow memory
leak. Per-tenant breakdown lives in Postgres (usage_records/usage_rollups, Phase 6),
which is built for exactly that; these metrics answer "how is the gateway doing
overall", not "how is tenant X doing".
"""

from prometheus_client import Counter, Gauge, Histogram

http_requests_total = Counter(
    "aegis_http_requests_total",
    "Total HTTP requests handled",
    ["method", "route", "status"],
)
http_request_duration_seconds = Histogram(
    "aegis_http_request_duration_seconds",
    "HTTP request duration in seconds",
    ["method", "route"],
)

chat_completions_total = Counter(
    "aegis_chat_completions_total",
    "Chat completion requests by outcome",
    ["provider", "outcome"],  # outcome: success, error, blocked, rate_limited
)

cache_lookups_total = Counter(
    "aegis_cache_lookups_total",
    "Response cache lookups",
    ["result"],  # hit, miss
)

rate_limit_rejections_total = Counter(
    "aegis_rate_limit_rejections_total",
    "Requests rejected by a rate/budget/concurrency guardrail",
    # reason: rate_limit_exceeded, token_limit_exceeded, budget_exceeded,
    # concurrency_limit_exceeded
    ["reason"],
)

pii_redactions_total = Counter(
    "aegis_pii_redactions_total",
    "Requests that had at least one PII entity redacted",
)

injection_detections_total = Counter(
    "aegis_injection_detections_total",
    "Requests flagged by prompt-injection detection",
    ["mode"],  # block, log
)

provider_call_duration_seconds = Histogram(
    "aegis_provider_call_duration_seconds",
    "Upstream provider call duration in seconds",
    ["provider", "outcome"],  # outcome: success, error
)

# 0=closed, 1=half_open, 2=open — a gauge (not a counter) because what matters is the
# current state, not a running total of state changes.
provider_circuit_breaker_state = Gauge(
    "aegis_provider_circuit_breaker_state",
    "Circuit breaker state per provider (0=closed, 1=half_open, 2=open)",
    ["provider"],
)

usage_cost_usd_total = Counter(
    "aegis_usage_cost_usd_total",
    "Cumulative provider cost in USD",
    ["provider"],
)
usage_tokens_total = Counter(
    "aegis_usage_tokens_total",
    "Cumulative tokens processed",
    ["provider", "kind"],  # kind: prompt, completion
)

_CIRCUIT_STATE_VALUES = {"closed": 0, "half_open": 1, "open": 2}


def set_circuit_breaker_state(provider: str, state: str) -> None:
    provider_circuit_breaker_state.labels(provider=provider).set(_CIRCUIT_STATE_VALUES[state])
