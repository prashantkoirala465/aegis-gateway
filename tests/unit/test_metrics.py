from prometheus_client import Counter

from aegis_gateway.core.metrics import (
    cache_lookups_total,
    chat_completions_total,
    pii_redactions_total,
    provider_circuit_breaker_state,
    set_circuit_breaker_state,
)


def _value(counter: Counter, **labels: str) -> float:
    # prometheus_client has no public "current value" API outside of rendering the
    # whole exposition text — reading the internal _value is the standard way tests
    # verify a specific counter/gauge without parsing generate_latest() output.
    value: float = counter.labels(**labels)._value.get()
    return value


def test_set_circuit_breaker_state_maps_closed_half_open_open() -> None:
    set_circuit_breaker_state("unit-test-provider", "closed")
    assert provider_circuit_breaker_state.labels(provider="unit-test-provider")._value.get() == 0

    set_circuit_breaker_state("unit-test-provider", "half_open")
    assert provider_circuit_breaker_state.labels(provider="unit-test-provider")._value.get() == 1

    set_circuit_breaker_state("unit-test-provider", "open")
    assert provider_circuit_breaker_state.labels(provider="unit-test-provider")._value.get() == 2


def test_cache_lookups_counter_increments() -> None:
    before = _value(cache_lookups_total, result="hit")
    cache_lookups_total.labels(result="hit").inc()
    assert _value(cache_lookups_total, result="hit") == before + 1


def test_chat_completions_counter_labeled_by_provider_and_outcome() -> None:
    labels = {"provider": "unit-test-provider", "outcome": "success"}
    before = _value(chat_completions_total, **labels)
    chat_completions_total.labels(**labels).inc()
    assert _value(chat_completions_total, **labels) == before + 1


def test_pii_redactions_counter_has_no_labels() -> None:
    before = pii_redactions_total._value.get()
    pii_redactions_total.inc()
    assert pii_redactions_total._value.get() == before + 1
