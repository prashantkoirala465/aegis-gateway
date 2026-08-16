from aegis_gateway.services.pricing import calculate_cost_usd, estimate_prompt_cost_usd


def test_estimate_prompt_cost_scales_with_tokens() -> None:
    cost_1k = estimate_prompt_cost_usd(model="gpt-4o", prompt_tokens=1000, provider_name="openai")
    cost_2k = estimate_prompt_cost_usd(model="gpt-4o", prompt_tokens=2000, provider_name="openai")
    assert cost_1k > 0
    assert cost_2k == cost_1k * 2


def test_estimate_prompt_cost_ollama_is_free() -> None:
    cost = estimate_prompt_cost_usd(model="llama3.1", prompt_tokens=100_000, provider_name="ollama")
    assert cost == 0.0


def test_estimate_prompt_cost_unknown_model_falls_back_nonzero() -> None:
    cost = estimate_prompt_cost_usd(
        model="some-new-model", prompt_tokens=1000, provider_name="openai"
    )
    assert cost > 0


def test_calculate_cost_usd_includes_both_prompt_and_completion() -> None:
    prompt_only = calculate_cost_usd(
        model="gpt-4o", prompt_tokens=1000, completion_tokens=0, provider_name="openai"
    )
    with_completion = calculate_cost_usd(
        model="gpt-4o", prompt_tokens=1000, completion_tokens=1000, provider_name="openai"
    )
    assert with_completion > prompt_only


def test_calculate_cost_usd_completion_priced_higher_than_prompt_for_gpt4o() -> None:
    # Real-world asymmetry (gpt-4o: $2.50/1M input vs $10/1M output) — a pricing table
    # that collapsed these to one blended rate would misprice completion-heavy usage.
    prompt_cost = calculate_cost_usd(
        model="gpt-4o", prompt_tokens=1_000_000, completion_tokens=0, provider_name="openai"
    )
    completion_cost = calculate_cost_usd(
        model="gpt-4o", prompt_tokens=0, completion_tokens=1_000_000, provider_name="openai"
    )
    assert completion_cost > prompt_cost


def test_calculate_cost_usd_ollama_always_zero() -> None:
    cost = calculate_cost_usd(
        model="llama3.1",
        prompt_tokens=1_000_000,
        completion_tokens=1_000_000,
        provider_name="ollama",
    )
    assert cost == 0.0


def test_calculate_cost_usd_zero_tokens_is_zero() -> None:
    cost = calculate_cost_usd(
        model="gpt-4o", prompt_tokens=0, completion_tokens=0, provider_name="openai"
    )
    assert cost == 0.0
