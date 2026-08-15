import httpx
import pytest

from aegis_gateway.services.embeddings import (
    EmbeddingUnavailableError,
    cosine_similarity,
    embed_texts,
)


def test_cosine_similarity_identical_vectors_is_one() -> None:
    assert cosine_similarity([1.0, 2.0, 3.0], [1.0, 2.0, 3.0]) == pytest.approx(1.0)


def test_cosine_similarity_orthogonal_vectors_is_zero() -> None:
    assert cosine_similarity([1.0, 0.0], [0.0, 1.0]) == pytest.approx(0.0)


def test_cosine_similarity_opposite_vectors_is_negative_one() -> None:
    assert cosine_similarity([1.0, 0.0], [-1.0, 0.0]) == pytest.approx(-1.0)


def test_cosine_similarity_zero_vector_is_zero_not_nan() -> None:
    assert cosine_similarity([0.0, 0.0], [1.0, 1.0]) == 0.0


async def test_embed_texts_raises_without_api_key() -> None:
    client = httpx.AsyncClient()
    with pytest.raises(EmbeddingUnavailableError):
        await embed_texts(client, texts=["hi"], api_key="")
    await client.aclose()


async def test_embed_texts_reorders_by_index_not_response_position() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        # Deliberately return out of order to prove the client sorts by `index`.
        return httpx.Response(
            200,
            json={
                "data": [
                    {"index": 1, "embedding": [0.0, 1.0]},
                    {"index": 0, "embedding": [1.0, 0.0]},
                ]
            },
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    embeddings = await embed_texts(client, texts=["first", "second"], api_key="fake-key")
    assert embeddings == [[1.0, 0.0], [0.0, 1.0]]
    await client.aclose()
