import tiktoken

from aegis_gateway.schemas.chat import ChatMessage

_FALLBACK_ENCODING = "cl100k_base"
_TOKENS_PER_MESSAGE = 3
_TOKENS_PER_NAME = 1
_TOKENS_PER_REPLY_PRIMER = 3


def _encoding_for(model: str) -> tiktoken.Encoding:
    try:
        return tiktoken.encoding_for_model(model)
    except KeyError:
        # Non-OpenAI models (Ollama/Llama/etc.) have no tiktoken encoding — cl100k_base
        # gives an approximate count, not an exact one. This is intentionally
        # documented as approximate everywhere it's used, not presented as exact.
        return tiktoken.get_encoding(_FALLBACK_ENCODING)


def count_prompt_tokens(messages: list[ChatMessage], model: str) -> int:
    """Implements OpenAI's documented per-message chat token-counting formula. Exact
    for OpenAI models; an approximation for anything else, since token boundaries are
    tokenizer-specific and this gateway doesn't ship a tokenizer per provider."""
    encoding = _encoding_for(model)
    num_tokens = 0
    for message in messages:
        num_tokens += _TOKENS_PER_MESSAGE
        num_tokens += len(encoding.encode(message.role))
        if isinstance(message.content, str):
            num_tokens += len(encoding.encode(message.content))
        name = getattr(message, "name", None)
        if isinstance(name, str):
            num_tokens += len(encoding.encode(name)) + _TOKENS_PER_NAME
    return num_tokens + _TOKENS_PER_REPLY_PRIMER


def count_text_tokens(text: str, model: str) -> int:
    return len(_encoding_for(model).encode(text))
