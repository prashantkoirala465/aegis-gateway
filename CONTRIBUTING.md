# Contributing

## Setup

```bash
cp .env.example .env
uv venv && source .venv/bin/activate
uv pip install -e ".[dev]"
docker compose up -d postgres redis
alembic upgrade head
uvicorn aegis_gateway.main:app --reload
```

## Before opening a PR

```bash
ruff check . && ruff format --check .
mypy src
pytest
```

CI runs the same checks (lint, typecheck, tests, `gitleaks`, `pip-audit`, a Docker
build) — see `.github/workflows/ci.yml`. All of it needs to be green.

Migrations: if you touch `db/models.py`, add an Alembic revision (`alembic revision
--autogenerate -m "..."`, then review the generated file by hand — autogenerate gets
RLS policies and role grants wrong, those are always written manually) and write a
real `downgrade()`, not `pass`. `alembic downgrade base && alembic upgrade head`
should round-trip cleanly; that's exactly what CI and local dev both rely on.

## Code style

- Type hints everywhere; `mypy --strict` passes on `src/`.
- Comments explain *why*, not *what* — if removing a comment wouldn't confuse a
  future reader, it shouldn't be there. The codebase leans on this a lot for
  non-obvious tradeoffs (see `services/rate_limiter.py`, `db/session.py`); match
  that style rather than narrating what the code already says.
- No new dependency for something the standard library or an existing dependency
  already covers.
- RLS-protected tables (`api_keys`, `audit_log`, `usage_records`, `usage_rollups`)
  need the same `tenant_isolation` policy pattern as the existing ones — see
  `alembic/versions/0001_initial_identity_schema.py` for the canonical policy SQL,
  and `db/session.set_rls_context()` for how the app sets the session GUCs it reads.

## Tests

- Unit tests (`tests/unit/`) shouldn't need Postgres/Redis — mock at the boundary
  (`httpx.MockTransport` for provider HTTP calls is the established pattern; see
  `tests/unit/test_openai_compatible_provider.py`).
- Integration tests (`tests/integration/`) need a running Postgres + Redis
  (`docker compose up -d postgres redis`) and expect `alembic upgrade head` to have
  already run.
- A new endpoint or detector without a test isn't done — this project verifies
  everything it claims: PII redaction is tested against real Presidio output, RLS
  isolation is tested by actually querying as a different tenant, the circuit
  breaker is tested by driving it through real state transitions. Prefer that over
  mocking the thing you're actually trying to verify.

## Reporting a security issue

Please don't open a public issue for a vulnerability. Email the address on the
maintainer's GitHub profile instead.
