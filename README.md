# Aegis Gateway

[![CI](https://github.com/prashantkoirala465/aegis-gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/prashantkoirala465/aegis-gateway/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A multi-tenant gateway that sits in front of LLM providers (OpenAI, Anthropic, local
Ollama models) and exposes an OpenAI-compatible API surface: authentication, rate
limiting, prompt-injection and PII filtering, caching, cost accounting, and audit
logging. Same category as Portkey, LiteLLM proxy, or Cloudflare AI Gateway.

Status: feature-complete (all 9 build phases). Tenants, API keys, and Postgres RLS
back a tenant-facing HMAC API-key auth and a separate JWT-authenticated admin API;
`/v1/chat/completions` proxies to OpenAI and Ollama with streaming, retries, a
circuit breaker per provider, and idempotency keys; every request is gated by
per-tenant RPM/TPM token buckets, a monthly budget guardrail, and a concurrency cap;
message content runs through Presidio-based PII redaction and heuristic +
embedding-similarity prompt-injection detection before reaching a provider, with
every redaction, block, and auth failure written to a synchronous audit log;
identical requests are served from an exact-match Redis cache instead of hitting the
provider twice; every completed request writes an exact usage/cost record, rolled up
hourly and daily by an arq worker that also scans for tenants crossing their budget;
the whole pipeline is instrumented with Prometheus metrics (Grafana dashboard
included) and hand-placed OpenTelemetry spans; and the admin API covers tenant/key
CRUD, per-tenant policy toggles, and usage/audit-log queries. See Load testing below
for real numbers under concurrency and Migrations for a verified upgrade/downgrade
round trip.

## Architecture

```mermaid
flowchart LR
    Client -->|Bearer agk_live_...| Gateway
    subgraph Gateway[Aegis Gateway]
        Auth[Auth: HMAC API key] --> RateLimit[Rate limit / budget]
        RateLimit --> Security[PII redaction / prompt-injection detection]
        Security --> Cache[Cache lookup]
        Cache -->|miss| Provider[Provider adapter: retry + circuit breaker]
        Cache -->|hit| Response
        Provider --> Response
    end
    Provider --> OpenAI[(OpenAI)]
    Provider --> Anthropic[(Anthropic)]
    Provider --> Ollama[(Ollama, local)]
    Auth -.audit.-> Postgres[(Postgres)]
    Security -.audit.-> Postgres
    RateLimit -.counters.-> Redis[(Redis)]
    Cache -.-> Redis
```

## Stack

Python 3.12, FastAPI (async), Postgres 16 + pgvector, Redis, SQLAlchemy 2.0 (async),
Alembic, arq for background jobs, Presidio for PII detection, Prometheus/OpenTelemetry
for observability.

API keys are HMAC-SHA256 with a server-side pepper (indexable, no bcrypt-on-every-request
cost); admin passwords use argon2id. Postgres RLS enforces tenant isolation at the row
level, on top of the normal application-side `WHERE tenant_id = ...` filtering — the app
connects as a non-superuser role so the policies actually apply.

Every tenant has per-request limits — `rate_limit_rpm`, `rate_limit_tpm`,
`monthly_budget_usd`, `max_concurrent_requests` — enforced atomically in Redis via Lua
scripts (a plain get-then-set is a race under concurrent requests) before a request
reaches the provider. Change them (and every other per-tenant policy toggle) via
`PATCH /admin/tenants/{id}` — see Admin API below.

Message content is redacted for PII (Presidio: spaCy NER + built-in regex recognizers)
before it reaches a provider, unless a tenant has `pii_redaction_enabled=false`. Prompt-
injection detection runs regex heuristics plus, when `OPENAI_API_KEY` is set, cosine
similarity against a small embedded jailbreak corpus — best-effort defense-in-depth, not
a robust guarantee; it degrades to heuristic-only (logged once, not per request) with no
API key configured. Each tenant picks `injection_detection_mode`: `block` (403) or `log`
(allowed through, recorded). Every redaction, injection verdict, and auth failure writes
a synchronous row to `audit_log` — never queued, and never containing raw prompt/PII
content, only categories and scores.

Identical requests (same tenant, model, messages, and generation params — hashed after
redaction, so it's caching what actually gets sent) are served from Redis instead of
hitting the provider again, TTL-bound and skippable per tenant via `cache_enabled`. This
is exact-match only: a repeated non-deterministic request (temperature > 0) replays the
same cached answer rather than generating a fresh one, which is the expected tradeoff of
exact-match caching, not a bug. Semantic (embedding-similarity) caching is a documented
roadmap item, not built — see below.

Every completed request (streaming or not, cache hit or not) writes one `usage_records`
row with exact prompt/completion tokens and cost — separate prompt/completion pricing
per model, not a blended rate, since real providers price them differently. This is the
durable, exact number; the Redis budget guardrail above is a fast, approximate,
pre-flight-only estimate, never reconciled against it. A separate `worker` process (`arq`,
chosen over Celery — see `docs/adr/0002-*`) aggregates `usage_records` into hourly/daily
`usage_rollups` and scans month-to-date spend every 15 minutes, writing one
`budget.threshold_reached` audit event (deduped via a Redis marker) the first time a
tenant crosses 80% or 100% of budget.

`/metrics` exposes Prometheus counters/histograms/gauges for the whole pipeline —
request rate and latency, cache hit ratio, rate/budget/concurrency rejections by
reason, PII/injection detection counts, provider call latency, circuit breaker state,
and cost/token totals. Deliberately no `tenant_id` (or any other unbounded value) on
any label — a label that grows with the tenant count turns every metric into a slow
memory leak; per-tenant breakdown lives in Postgres (`usage_records`/`usage_rollups`),
which is built for exactly that. `docker compose up` also starts Prometheus (scraping
the gateway) and Grafana with a dashboard pre-provisioned — see Quickstart.

Requests are also traced with OpenTelemetry: hand-placed spans across
auth → rate_limit → security_pipeline → cache_lookup → provider_call, not full
auto-instrumented distributed tracing (this is a monolith). Spans print to the
console by default; set `OTEL_EXPORTER_OTLP_ENDPOINT` to ship them to a real
backend (Jaeger, Tempo, Honeycomb, ...) instead — deliberately not bundled into
docker-compose the way Prometheus/Grafana are, since a trace backend is a bigger
infra commitment than a metrics scrape target.

## Admin API

JWT-authenticated, entirely separate from the tenant-facing HMAC API-key auth on
`/v1/*` — no code path upgrades one into the other, so a leaked tenant key never
grants admin access. There's deliberately no `/admin/register`; admin accounts are
provisioned only via `scripts/seed.py`, run with owner DB credentials out-of-band, so
this API surface can never self-provision admins.

```bash
TOKEN=$(curl -s -X POST localhost:8000/admin/login \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@example.com", "password": "change-me-now"}' | jq -r .access_token)

curl -s -X POST localhost:8000/admin/tenants -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "New Tenant", "monthly_budget_usd": "50.00"}'

curl -s -X PATCH localhost:8000/admin/tenants/<id> -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"injection_detection_mode": "log", "rate_limit_rpm": 30}'

curl -s -X POST localhost:8000/admin/tenants/<id>/api-keys -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d '{"name": "prod key"}'
```

Also: `GET /admin/tenants`, `GET/DELETE /admin/tenants/{id}/api-keys[/{key_id}]`,
`GET /admin/tenants/{id}/usage/records|rollups`, `GET /admin/tenants/{id}/audit-log`,
and `GET /admin/audit-log` (system-wide, includes `tenant_id: null` events like auth
failures before a tenant could be resolved). Every mutating admin action writes its
own `audit_log` row — tenant creation, policy changes, key issuance/revocation — so
"who changed what" is answerable the same way "what did a tenant do" already was.
Every admin tier is equally privileged for now; no RBAC beyond "has a valid admin
JWT" — a documented simplification, not an oversight.

Full request/response schemas are interactive at `/docs` (Swagger UI) once the
gateway is running.

## Quickstart

```bash
cp .env.example .env
docker compose up --build
```

Starts Postgres, Redis, the gateway, the background worker, Prometheus, and Grafana.
The gateway container runs `alembic upgrade head` (which also creates the restricted
`aegis_app` runtime role) before starting. Grafana is at `localhost:3000` (anonymous
viewer access, no login) with the "Aegis Gateway" dashboard already provisioned;
Prometheus is at `localhost:9090`.

Bootstrap a tenant, admin user, and API key:

```bash
uv run python scripts/seed.py \
    --tenant-name "Demo Tenant" \
    --admin-email admin@example.com \
    --admin-password "change-me-now"
```

The key is printed once and stored only as an HMAC digest afterward.

```bash
curl -H "Authorization: Bearer agk_live_..." localhost:8000/v1/ping
curl localhost:8000/healthz
```

Proxy a real chat completion (routes to OpenAI for `gpt-*`/`o1`/`o3`/`o4` models,
Ollama otherwise — set `OPENAI_API_KEY` in `.env` or run Ollama locally):

```bash
curl localhost:8000/v1/chat/completions \
  -H "Authorization: Bearer agk_live_..." \
  -H "Content-Type: application/json" \
  -d '{"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}]}'
```

Add `"stream": true` for SSE, or an `Idempotency-Key` header to make retries of the
same request safe (a duplicate call with the same key replays the cached response
instead of hitting the provider — and re-billing — twice).

## Local development

```bash
uv venv && source .venv/bin/activate
uv pip install -e ".[dev]"
docker compose up -d postgres redis
alembic upgrade head
uvicorn aegis_gateway.main:app --reload
```

Tests: `pytest`. Lint/typecheck: `ruff check . && mypy src`.

## Migrations

`alembic downgrade base && alembic upgrade head` is verified to round-trip cleanly —
every `downgrade()` actually drops what its `upgrade()` created, including the
`aegis_app` role and its RLS policies, not just the tables. This gets exercised in
CI-adjacent local verification, not left as an untested `pass` stub.

## Load testing

Two `locust` scenarios in `tests/load/locustfile.py`, run headless against a live
`docker compose` stack — not part of `pytest`, and not dependent on a real upstream
provider succeeding (every request is expected to end in 429/502/503 without a real
OpenAI key or local Ollama; that's fine, both scenarios measure the gateway's own
overhead and concurrency-safety, not completion quality):

```bash
LOAD_TEST_RATE_LIMITED_KEY=agk_live_... uv run locust -f tests/load/locustfile.py \
  --headless --host http://localhost:8000 -u 20 -r 20 -t 30s RateLimitGuardrailUser

LOAD_TEST_STREAMING_KEY=agk_live_... uv run locust -f tests/load/locustfile.py \
  --headless --host http://localhost:8000 -u 20 -r 20 -t 30s SecurityPipelineUser
```

Real results from one run (20 concurrent users, 30s, this machine — not
representative of any particular production hardware):

- **Rate limiter under concurrency** (30 RPM cap): 3,169 requests fired, 3,130
  rejected with 429, only 39 admitted through to a provider attempt (23 real
  connection errors + 16 fast-failed once the circuit breaker opened) — within the
  token bucket's expected ceiling (capacity + refill over the window), confirming
  the atomic Lua script holds an exact cap with no over-admission race under real
  concurrent load. Median latency 76ms; a handful of outliers up to 9.6s, fully
  explained by retry-with-backoff on repeated connection failures (up to 3 attempts,
  each waiting up to ~4s of jittered backoff) — expected behavior, not a defect,
  and visible in production via the `aegis_provider_call_duration_seconds` histogram.
- **PII/injection pipeline under concurrent streaming load**: 1,657 requests, each
  running real Presidio PII redaction + prompt-injection heuristics, sustained at
  55–63 req/s with a steady median latency (~280ms) and no throughput collapse —
  evidence that offloading Presidio's synchronous analyzer via `asyncio.to_thread`
  (see `detectors/pii.py`) actually keeps the event loop responsive under load
  rather than serializing every request behind it.

## Roadmap

Not implemented yet, on purpose: semantic caching (exact-match caching is the real
feature, pgvector-based similarity is a stretch goal), a trained prompt-injection
classifier (shipping a heuristic + embedding-similarity detector instead), a generic
policy engine (fixed per-tenant toggles instead of a rules DSL), and anything requiring
HA/multi-region, admin SSO, automated key rotation, or GDPR erasure — out of scope for
a single-instance deployment.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for local setup, what CI checks, and the
patterns (RLS policies, test structure) new code is expected to follow.

## License

MIT — see [LICENSE](LICENSE).
