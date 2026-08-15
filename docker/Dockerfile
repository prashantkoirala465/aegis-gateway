# syntax=docker/dockerfile:1
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN pip install --no-cache-dir uv

COPY pyproject.toml README.md ./
COPY src ./src

RUN uv pip install --system --no-cache .
RUN python -m spacy download en_core_web_sm

COPY alembic ./alembic
COPY alembic.ini ./

RUN useradd --create-home --uid 1000 aegis && chown -R aegis:aegis /app
USER aegis

EXPOSE 8000

CMD ["uvicorn", "aegis_gateway.main:app", "--host", "0.0.0.0", "--port", "8000"]
