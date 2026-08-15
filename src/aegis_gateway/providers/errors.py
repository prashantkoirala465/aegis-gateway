from fastapi import HTTPException

from aegis_gateway.schemas.errors import openai_error


class ProviderError(Exception):
    """Base for every failure mode a provider adapter can raise. api/proxy.py maps
    each subclass to an OpenAI-shaped error response with an appropriate status code."""


class UpstreamTimeoutError(ProviderError):
    pass


class UpstreamConnectionError(ProviderError):
    pass


class UpstreamStatusError(ProviderError):
    """The upstream provider responded, but with a non-2xx status."""

    def __init__(self, status_code: int, body: str) -> None:
        self.status_code = status_code
        self.body = body
        super().__init__(f"upstream returned {status_code}: {body[:500]}")


class CircuitOpenError(ProviderError):
    """The circuit breaker is open for this provider — failing fast without a network
    call, because recent calls have been failing past the configured threshold."""


def provider_error_to_http_exception(exc: ProviderError) -> HTTPException:
    """Central mapping from a provider failure mode to the OpenAI-shaped HTTP error
    the caller sees — kept next to the exception hierarchy so a new ProviderError
    subclass and its HTTP mapping are added in the same place."""
    if isinstance(exc, CircuitOpenError):
        return HTTPException(
            status_code=503,
            detail=openai_error(str(exc), error_type="upstream_error", code="circuit_open"),
        )
    if isinstance(exc, UpstreamTimeoutError):
        return HTTPException(
            status_code=504,
            detail=openai_error(str(exc), error_type="upstream_error", code="upstream_timeout"),
        )
    if isinstance(exc, UpstreamConnectionError):
        return HTTPException(
            status_code=502,
            detail=openai_error(
                str(exc), error_type="upstream_error", code="upstream_connection_error"
            ),
        )
    if isinstance(exc, UpstreamStatusError):
        # 4xx from upstream (bad request to the provider, e.g. unknown model) is passed
        # through as-is; a 5xx that escaped retries still surfaces as our own 502
        # rather than leaking the upstream's exact status.
        status_code = exc.status_code if 400 <= exc.status_code < 500 else 502
        return HTTPException(
            status_code=status_code,
            detail=openai_error(exc.body[:500], error_type="upstream_error", code="upstream_error"),
        )
    return HTTPException(
        status_code=502,
        detail=openai_error(str(exc), error_type="upstream_error", code="unknown_provider_error"),
    )
