from fastapi import HTTPException


def openai_error(
    message: str, *, error_type: str, code: str, param: str | None = None
) -> dict[str, object]:
    """Shapes error bodies to match OpenAI's actual error JSON so any OpenAI SDK
    pointed at this gateway parses errors correctly, not just success responses."""
    return {"error": {"message": message, "type": error_type, "param": param, "code": code}}


class UnauthorizedError(HTTPException):
    def __init__(self, message: str = "Invalid API key provided.") -> None:
        super().__init__(
            status_code=401,
            detail=openai_error(
                message, error_type="invalid_request_error", code="invalid_api_key"
            ),
        )


class ForbiddenError(HTTPException):
    def __init__(self, message: str = "Insufficient permissions for this operation.") -> None:
        super().__init__(
            status_code=403,
            detail=openai_error(message, error_type="invalid_request_error", code="forbidden"),
        )
