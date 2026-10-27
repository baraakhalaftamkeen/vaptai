"""Celery app. Redis is the transport; MariaDB stays authoritative for run status."""
from __future__ import annotations

import os

from celery import Celery

redis_url = os.environ.get("VAPT_REDIS_URL", "redis://localhost:6379/0")

celery_app = Celery("vapt_orchestrator", broker=redis_url, backend=redis_url)
celery_app.conf.update(
    task_acks_late=True,                 # redeliver if a worker dies mid-task
    worker_prefetch_multiplier=1,
    task_track_started=True,
    task_default_queue="runs",
    # Transactional-outbox relay: drain undelivered intents into the queue regularly.
    # Run `celery -A vapt_orch.celery_app.celery_app beat` alongside the worker.
    beat_schedule={
        "drain-outbox": {
            "task": "outbox.drain",
            "schedule": float(os.environ.get("VAPT_OUTBOX_DRAIN_SECONDS", "5")),
        },
        # Fire due recurring schedules (BAR-29). Minute cadence is enough for interval
        # scheduling; the task itself decides what is due.
        "tick-schedules": {
            "task": "schedules.tick",
            "schedule": float(os.environ.get("VAPT_SCHEDULE_TICK_SECONDS", "60")),
        },
    },
)

# Ensure task modules are imported for registration.
from . import tasks  # noqa: E402,F401
