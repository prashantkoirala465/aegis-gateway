from httpx import AsyncClient


async def test_metrics_endpoint_exposes_prometheus_format(client: AsyncClient) -> None:
    response = await client.get("/metrics")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    body = response.text
    assert "aegis_http_requests_total" in body
    assert "aegis_chat_completions_total" in body
    assert "aegis_provider_circuit_breaker_state" in body


async def test_metrics_endpoint_reflects_real_requests(client: AsyncClient) -> None:
    await client.get("/healthz")
    response = await client.get("/metrics")
    body = response.text

    matching = [
        line
        for line in body.splitlines()
        if line.startswith("aegis_http_requests_total{")
        and 'route="/healthz"' in line
        and 'status="200"' in line
    ]
    assert matching, f"no matching aegis_http_requests_total line in:\n{body}"


async def test_metrics_endpoint_is_unauthenticated(client: AsyncClient) -> None:
    # No Authorization header at all — /metrics is meant to be scraped, not called
    # with a tenant API key, matching /healthz's precedent (see api/metrics.py).
    response = await client.get("/metrics")
    assert response.status_code == 200
