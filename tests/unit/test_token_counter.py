from aegis_gateway.schemas.chat import ChatMessage
from aegis_gateway.services.token_counter import count_prompt_tokens, count_text_tokens


def test_count_prompt_tokens_nonzero_for_real_message() -> None:
    messages = [ChatMessage(role="user", content="Hello, how are you?")]
    assert count_prompt_tokens(messages, "gpt-4o") > 0


def test_count_prompt_tokens_grows_with_more_messages() -> None:
    short = [ChatMessage(role="user", content="hi")]
    long = [
        ChatMessage(role="system", content="You are a helpful assistant."),
        ChatMessage(role="user", content="hi"),
        ChatMessage(role="assistant", content="Hello! How can I help you today?"),
    ]
    assert count_prompt_tokens(long, "gpt-4o") > count_prompt_tokens(short, "gpt-4o")


def test_count_prompt_tokens_unknown_model_falls_back() -> None:
    messages = [ChatMessage(role="user", content="test the fallback encoding path")]
    assert count_prompt_tokens(messages, "llama3.1") > 0


def test_count_text_tokens() -> None:
    assert count_text_tokens("", "gpt-4o") == 0
    assert count_text_tokens("hello world", "gpt-4o") > 0
