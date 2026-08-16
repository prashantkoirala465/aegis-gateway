from arq import cron
from arq.connections import RedisSettings

from aegis_gateway.core.config import get_settings
from aegis_gateway.workers.tasks import (
    budget_threshold_scan,
    daily_usage_rollup,
    hourly_usage_rollup,
    shutdown,
    startup,
)

_settings = get_settings()


class WorkerSettings:
    """Run with: arq aegis_gateway.workers.settings.WorkerSettings

    One worker process handles both cron schedules below and any future ad-hoc
    enqueued jobs — arq doesn't need a separate scheduler component (see
    docs/adr/0002-task-queue-arq-over-celery.md for why arq over Celery+Beat).
    """

    redis_settings = RedisSettings.from_dsn(_settings.redis_url)
    on_startup = startup
    on_shutdown = shutdown
    cron_jobs = [
        # 5-minute buffer past the hour: no real race (usage writes are synchronous),
        # just a no-cost margin before aggregating the hour that just closed.
        cron(hourly_usage_rollup, minute=5, run_at_startup=False),
        cron(daily_usage_rollup, hour=0, minute=10, run_at_startup=False),
        cron(budget_threshold_scan, minute={0, 15, 30, 45}, run_at_startup=False),
    ]
