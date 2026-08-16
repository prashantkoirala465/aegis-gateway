import uuid

from aegis_gateway.schemas.chat import ChatCompletionRequest, ChatMessage
from aegis_gateway.services.cache import compute_cache_key

TENANT_A = uuid.uuid4()
TENANT_B = uuid.uuid4()


def _request(**overrides: object) -> ChatCompletionRequest:
    defaults: dict[str, object] = {
        "model": "gpt-test",
        "messages": [ChatMessage(role="user", content="hello")],
    }
    defaults.update(overrides)
    return ChatCompletionRequest.model_validate(defaults)


def test_identical_requests_same_tenant_produce_same_key() -> None:
    key1 = compute_cache_key(TENANT_A, _request())
    key2 = compute_cache_key(TENANT_A, _request())
    assert key1 == key2


def test_same_request_different_tenant_produces_different_key() -> None:
    key_a = compute_cache_key(TENANT_A, _request())
    key_b = compute_cache_key(TENANT_B, _request())
    assert key_a != key_b
    assert str(TENANT_A) in key_a
    assert str(TENANT_B) in key_b


def test_different_message_content_produces_different_key() -> None:
    key1 = compute_cache_key(TENANT_A, _request())
    key2 = compute_cache_key(
        TENANT_A, _request(messages=[ChatMessage(role="user", content="goodbye")])
    )
    assert key1 != key2


def test_different_model_produces_different_key() -> None:
    key1 = compute_cache_key(TENANT_A, _request())
    key2 = compute_cache_key(TENANT_A, _request(model="gpt-other"))
    assert key1 != key2


def test_stream_flag_does_not_affect_key() -> None:
    key1 = compute_cache_key(TENANT_A, _request(stream=False))
    key2 = compute_cache_key(TENANT_A, _request(stream=True))
    assert key1 == key2


def test_different_temperature_produces_different_key() -> None:
    key1 = compute_cache_key(TENANT_A, _request(temperature=0.0))
    key2 = compute_cache_key(TENANT_A, _request(temperature=1.0))
    assert key1 != key2
