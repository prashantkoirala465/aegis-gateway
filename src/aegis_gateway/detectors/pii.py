import asyncio
from dataclasses import dataclass

from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine

from aegis_gateway.schemas.chat import ChatMessage

# Presidio's zero-arg AnalyzerEngine() defaults to en_core_web_lg (~560MB) and, if
# it's not already installed, silently shells out to `spacy download` and blocks on
# that network call — a surprise that turned "run the tests" into a multi-minute hang
# the first time this was built. Explicitly pinning to en_core_web_sm (the model
# actually installed in the Dockerfile/CI, see docker/Dockerfile) makes the model in
# use match what's actually shipped, with no implicit network dependency at runtime.
_NLP_CONFIGURATION = {
    "nlp_engine_name": "spacy",
    "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
}


@dataclass(frozen=True)
class PiiRedactionResult:
    redacted_text: str
    entity_types: tuple[str, ...]


class PiiRedactor:
    """Wraps Presidio's analyzer (spaCy NER + built-in regex recognizers for email,
    phone, credit card, etc.) and anonymizer (redaction). Both load a spaCy model at
    construction — expensive enough (hundreds of ms) that this is built once at
    startup (see main.py lifespan), never per request.

    analyze()/anonymize() are synchronous, CPU-bound calls. Running them inline in an
    async request handler would block the event loop for every other in-flight
    request, so they're pushed to a thread via asyncio.to_thread — this is exactly
    why Phase 3's rate limiting sits in front of this detector: it gates access to
    CPU-costly work like this one.
    """

    def __init__(self) -> None:
        nlp_engine = NlpEngineProvider(nlp_configuration=_NLP_CONFIGURATION).create_engine()
        self._analyzer = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["en"])
        # presidio ships no stubs, hence the untyped-call ignore below.
        self._anonymizer = AnonymizerEngine()  # type: ignore[no-untyped-call]

    async def redact(self, text: str) -> PiiRedactionResult:
        if not text:
            return PiiRedactionResult(redacted_text=text, entity_types=())

        findings = await asyncio.to_thread(self._analyzer.analyze, text=text, language="en")
        if not findings:
            return PiiRedactionResult(redacted_text=text, entity_types=())

        # presidio_anonymizer's type stub wants its own (structurally identical)
        # RecognizerResult class rather than presidio_analyzer's — this is how
        # Presidio's own docs chain analyzer output into the anonymizer.
        anonymized = await asyncio.to_thread(
            self._anonymizer.anonymize,
            text=text,
            analyzer_results=findings,  # type: ignore[arg-type]
        )
        entity_types = tuple(sorted({finding.entity_type for finding in findings}))
        return PiiRedactionResult(redacted_text=anonymized.text, entity_types=entity_types)


async def redact_messages(
    redactor: PiiRedactor, messages: list[ChatMessage]
) -> tuple[list[ChatMessage], tuple[str, ...]]:
    """Redacts every string-content message in place (as a new list — messages are
    immutable pydantic models). Non-text content (image parts, etc.) is passed
    through unredacted — Presidio operates on text, and this gateway doesn't attempt
    OCR/vision-based PII detection."""
    redacted: list[ChatMessage] = []
    all_entity_types: set[str] = set()

    for message in messages:
        if not isinstance(message.content, str):
            redacted.append(message)
            continue
        result = await redactor.redact(message.content)
        if result.entity_types:
            all_entity_types.update(result.entity_types)
            redacted.append(message.model_copy(update={"content": result.redacted_text}))
        else:
            redacted.append(message)

    return redacted, tuple(sorted(all_entity_types))
