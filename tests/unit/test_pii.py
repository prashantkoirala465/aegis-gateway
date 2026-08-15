import pytest

from aegis_gateway.detectors.pii import PiiRedactor, redact_messages
from aegis_gateway.schemas.chat import ChatMessage


@pytest.fixture(scope="module")
def redactor() -> PiiRedactor:
    # Loads a spaCy model — expensive enough to build once per test module rather
    # than per test.
    return PiiRedactor()


async def test_redacts_email_address(redactor: PiiRedactor) -> None:
    result = await redactor.redact("Contact me at jane.doe@example.com about the invoice.")
    assert "jane.doe@example.com" not in result.redacted_text
    assert "EMAIL_ADDRESS" in result.entity_types


async def test_redacts_phone_number(redactor: PiiRedactor) -> None:
    result = await redactor.redact("Call me at 212-555-0198 tomorrow.")
    assert "212-555-0198" not in result.redacted_text
    assert "PHONE_NUMBER" in result.entity_types


async def test_leaves_benign_text_unchanged(redactor: PiiRedactor) -> None:
    text = "What's a good recipe for banana bread?"
    result = await redactor.redact(text)
    assert result.redacted_text == text
    assert result.entity_types == ()


async def test_empty_text(redactor: PiiRedactor) -> None:
    result = await redactor.redact("")
    assert result.redacted_text == ""
    assert result.entity_types == ()


async def test_redact_messages_only_touches_string_content(redactor: PiiRedactor) -> None:
    messages = [
        ChatMessage(role="system", content="You are a helpful assistant."),
        ChatMessage(role="user", content="My email is john@example.com, please help."),
        ChatMessage(role="user", content=[{"type": "image_url", "image_url": {"url": "x"}}]),
    ]
    redacted, entity_types = await redact_messages(redactor, messages)

    assert redacted[0].content == messages[0].content  # untouched, no PII
    assert "john@example.com" not in (redacted[1].content or "")
    assert redacted[2].content == messages[2].content  # non-str content passed through
    assert "EMAIL_ADDRESS" in entity_types


async def test_redact_messages_no_pii_returns_same_content(redactor: PiiRedactor) -> None:
    messages = [ChatMessage(role="user", content="Just a normal question, nothing sensitive.")]
    redacted, entity_types = await redact_messages(redactor, messages)
    assert redacted[0].content == messages[0].content
    assert entity_types == ()
