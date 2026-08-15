import math

import httpx

EMBEDDING_MODEL = "text-embedding-3-small"
_EMBEDDINGS_URL = "https://api.openai.com/v1/embeddings"


class EmbeddingUnavailableError(Exception):
    """Raised when no OpenAI API key is configured. Callers (prompt-injection
    detection now, semantic caching in Phase 5) must have a defined fallback for
    this — embeddings are an enhancement layer, not a hard dependency of the
    gateway starting up or serving requests."""


async def embed_texts(
    client: httpx.AsyncClient, *, texts: list[str], api_key: str
) -> list[list[float]]:
    if not api_key:
        raise EmbeddingUnavailableError("no OpenAI API key configured")
    response = await client.post(
        _EMBEDDINGS_URL,
        json={"model": EMBEDDING_MODEL, "input": texts},
        headers={"Authorization": f"Bearer {api_key}"},
        timeout=30.0,
    )
    response.raise_for_status()
    payload = response.json()
    # OpenAI returns `data` in the same order as `input`, but sorted by an `index`
    # field rather than guaranteed positionally — sort explicitly rather than assume.
    ordered = sorted(payload["data"], key=lambda item: item["index"])
    return [item["embedding"] for item in ordered]


def cosine_similarity(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b, strict=True))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(y * y for y in b))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)
