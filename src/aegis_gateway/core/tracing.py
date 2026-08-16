from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter, SpanExporter

from aegis_gateway.core.config import Settings

SERVICE_NAME = "aegis-gateway"


def configure_tracing(settings: Settings) -> TracerProvider:
    """Hand-placed spans across the request pipeline (see api/proxy.py, middleware/
    auth.py) — auth -> rate_limit -> security_pipeline -> cache_lookup ->
    provider_call — not full auto-instrumented distributed tracing. This is a
    monolith; "distributed" tracing here means internal pipeline spans, not a claim
    of cross-service tracing.

    Exports to the console by default — zero extra infra to see spans locally,
    consistent with how structlog already prints to stdout. Set
    OTEL_EXPORTER_OTLP_ENDPOINT to ship spans to a real backend (Jaeger, Tempo,
    Honeycomb, ...) instead. Deliberately not bundled into docker-compose the way
    Prometheus+Grafana are (see docker-compose.yml) — a trace backend is a bigger
    infra commitment than a metrics scrape target, and out of scope here.

    Idempotent per process: OTel's global tracer provider can only be installed
    once — `trace.set_tracer_provider()` silently no-ops (with a warning) on a
    second call. create_app() calls this every time it runs, which in production is
    once, but in tests happens once per test (a fresh app per test case) — without
    this guard every test after the first would log a spurious "overriding not
    allowed" warning for a provider swap that was never actually going to happen.
    """
    existing = trace.get_tracer_provider()
    if isinstance(existing, TracerProvider):
        return existing

    provider = TracerProvider(resource=Resource.create({"service.name": SERVICE_NAME}))

    exporter: SpanExporter
    if settings.otel_exporter_otlp_endpoint:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

        exporter = OTLPSpanExporter(endpoint=settings.otel_exporter_otlp_endpoint)
    else:
        exporter = ConsoleSpanExporter()

    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)
    return provider
