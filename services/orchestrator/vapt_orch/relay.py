"""Transactional-outbox relay (plan §6).

The API commits a run/approval change AND an Outbox row in one DB transaction, so the
intent to start or resume a run is durable even if the broker is momentarily down. This
relay drains undelivered Outbox rows into Celery and marks them delivered — at-least-once
delivery, and the run tasks are idempotent, so a redelivery is harmless.

`dispatch_pending` takes an injected `dispatcher(topic, payload) -> None` so it can be
unit-tested without a live broker; the production dispatcher enqueues the real tasks.
"""
from __future__ import annotations

from collections.abc import Callable

from sqlalchemy import select
from sqlalchemy.orm import Session
from vapt_persistence.models import Outbox

# topic -> how to turn a payload into a task call. Kept here so start and resume are
# wired the same way and a new topic is a one-line addition.
Dispatcher = Callable[[str, dict], None]


def dispatch_pending(db: Session, dispatcher: Dispatcher, *, limit: int = 100) -> int:
    """Dispatch undelivered outbox rows oldest-first. Returns how many were dispatched.

    A row is marked delivered only after the dispatcher returns without raising, so a
    failed dispatch is retried on the next drain rather than being lost. One bad row
    (e.g. an unknown topic) is skipped and left undelivered instead of blocking the
    whole queue behind it."""
    rows = db.execute(
        select(Outbox).where(Outbox.delivered.is_(False)).order_by(Outbox.created_at).limit(limit)
    ).scalars().all()
    dispatched = 0
    for row in rows:
        try:
            dispatcher(row.topic, dict(row.payload or {}))
        except Exception:
            continue  # leave undelivered; a later drain (or an operator) handles it
        row.delivered = True
        db.flush()
        dispatched += 1
    return dispatched


def celery_dispatcher(topic: str, payload: dict) -> None:
    """Production dispatcher: map an outbox topic to a Celery task. Imported lazily to
    avoid a circular import with the tasks module."""
    from . import tasks

    run_id = payload.get("run_id")
    if topic == "run.start":
        tasks.start_run.delay(run_id)
    elif topic == "run.resume":
        tasks.resume_run.delay(run_id, payload.get("decision", "approve"))
    else:  # unknown topic: leave undelivered for inspection rather than silently dropping
        raise ValueError(f"unknown outbox topic: {topic!r}")
