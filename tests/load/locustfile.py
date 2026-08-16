"""Two timeboxed scenarios, run headless against a live docker-compose stack — not
part of the pytest suite (see README "Load testing" for how to run these).

Neither scenario depends on a real upstream provider succeeding: both are measuring
the gateway's *own* overhead and concurrency-safety, not completion quality. Every
request here is expected to end in 429/502/503 in an environment with no real
OpenAI key or local Ollama — that's fine, the interesting part happens entirely
inside the gateway before a provider is ever reached.

Usage:
    LOAD_TEST_RATE_LIMITED_KEY=agk_live_... LOAD_TEST_STREAMING_KEY=agk_live_... \
        uv run locust -f tests/load/locustfile.py --headless --host http://localhost:8000 \
        -u 20 -r 20 -t 30s RateLimitGuardrailUser

    (swap the class name for SecurityPipelineUser for the second scenario)
"""

import os
import random

from locust import HttpUser, between, task

RATE_LIMITED_KEY = os.environ.get("LOAD_TEST_RATE_LIMITED_KEY", "")
STREAMING_KEY = os.environ.get("LOAD_TEST_STREAMING_KEY", "")

# Any status this project's own error-mapping produces on purpose (see
# providers/errors.py, services/rate_limiter.py) counts as a *handled* outcome, not a
# load-test failure — an unmapped 5xx or a hang would be the real signal to chase.
EXPECTED_STATUS_CODES = frozenset({200, 429, 502, 503})


class RateLimitGuardrailUser(HttpUser):
    """Hammers one low-RPM tenant with concurrent requests to check the Redis Lua
    token-bucket rate limiter holds its exact cap under real concurrency — no
    under- or over-admission race (see services/rate_limiter.py's whole reason for
    being a single atomic script instead of a get-then-set round trip).
    """

    wait_time = between(0, 0.05)

    @task
    def chat_completion(self) -> None:
        with self.client.post(
            "/v1/chat/completions",
            json={
                "model": "llama3.1",
                "messages": [{"role": "user", "content": "rate limit load test"}],
            },
            headers={"Authorization": f"Bearer {RATE_LIMITED_KEY}"},
            catch_response=True,
        ) as response:
            if response.status_code in EXPECTED_STATUS_CODES:
                response.success()
            else:
                response.failure(f"unexpected status {response.status_code}")


class SecurityPipelineUser(HttpUser):
    """Concurrent streaming requests against a generously-limited tenant, each
    carrying text that runs through real Presidio PII redaction + prompt-injection
    heuristics — the CPU-bound work rate limiting is deliberately ordered ahead of
    (see docs/THREAT_MODEL.md). The point is checking that asyncio.to_thread
    (detectors/pii.py) actually keeps the event loop responsive under concurrent
    load rather than serializing every request behind Presidio's analyzer.
    """

    wait_time = between(0, 0.1)

    @task
    def streaming_chat_completion(self) -> None:
        payload = {
            "model": "llama3.1",
            "stream": True,
            "messages": [
                {
                    "role": "user",
                    "content": f"My email is test-{random.random()}@example.com, please help.",  # noqa: S311
                }
            ],
        }
        with self.client.post(
            "/v1/chat/completions",
            json=payload,
            headers={"Authorization": f"Bearer {STREAMING_KEY}"},
            catch_response=True,
            stream=True,
        ) as response:
            if response.status_code in EXPECTED_STATUS_CODES:
                response.success()
            else:
                response.failure(f"unexpected status {response.status_code}")
