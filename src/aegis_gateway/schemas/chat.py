from typing import Any

from pydantic import BaseModel, ConfigDict


class ChatMessage(BaseModel):
    """Deliberately permissive: role/content are the only fields this gateway reasons
    about (routing, token counting); everything else (tool_calls, name, image parts,
    ...) passes through untouched via extra="allow" so new OpenAI request fields don't
    require a code change here to keep working end-to-end."""

    model_config = ConfigDict(extra="allow")

    role: str
    content: str | list[dict[str, Any]] | None = None


class ChatCompletionRequest(BaseModel):
    model_config = ConfigDict(extra="allow")

    model: str
    messages: list[ChatMessage]
    stream: bool = False


class Usage(BaseModel):
    model_config = ConfigDict(extra="allow")

    prompt_tokens: int
    completion_tokens: int
    total_tokens: int


class ChatCompletionResponse(BaseModel):
    """`choices` is left as raw dicts rather than fully modeled — the gateway forwards
    them to the caller unchanged and never needs to reason about their internal shape,
    so modeling every provider's choice/delta structure would be validation for its
    own sake."""

    model_config = ConfigDict(extra="allow")

    id: str
    object: str = "chat.completion"
    created: int
    model: str
    choices: list[dict[str, Any]]
    usage: Usage | None = None
