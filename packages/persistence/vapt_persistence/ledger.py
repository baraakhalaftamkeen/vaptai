"""Execution ledger helpers (plan §6, §10).

Append-only records of every proposed/authorized/executed action, every policy
decision, every approval, and monotonic run events. This is the audit authority —
checkpoints are workflow progress, not a substitute for it.

All helpers take an active Session and flush (not commit) so the caller controls
the transaction boundary.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .models import (
    Approval,
    ModelCall,
    PolicyDecisionRecord,
    RunEvent,
    ToolActionRecord,
)


def next_event_seq(db: Session, run_id: str) -> int:
    # Flush first: the session is autoflush=False, so pending-but-unflushed events
    # (e.g. a run.started added by the task layer) must be made visible before we take
    # max(seq), or two events race to the same seq and collide on uq_run_event_seq.
    db.flush()
    seqs = db.execute(select(RunEvent.seq).where(RunEvent.run_id == run_id)).scalars().all()
    return (max(seqs) + 1) if seqs else 1


# How many times `record_event` retries on a seq collision before giving up. The
# collisions are RARE in practice (one SELECT + INSERT window per writer); each
# retry re-SELECTs max(seq), so after a few attempts the probability of continued
# collision falls off a cliff. 5 is a generous budget — it covers a worst-case
# concurrent 5-writer race without failing a run on transient contention.
_RECORD_EVENT_MAX_RETRIES = 5


def record_event(db: Session, run_id: str, kind: str, payload: dict | None = None) -> RunEvent:
    """Append a RunEvent, retrying on seq collision.

    The seq-allocation is "SELECT max(seq) + 1" (`next_event_seq` above). When two
    sessions compute seq concurrently — common when the orchestrator and API are
    both writing to the same run, or when a Celery retry replays plan.proposed
    while a leftover insert from the first attempt still occupies seq=N — the
    second INSERT hits `uq_run_event_seq` and raises IntegrityError.

    We handle it with a SAVEPOINT per attempt (`db.begin_nested()`): on
    IntegrityError the SAVEPOINT rolls back without touching the OUTER transaction
    (the caller still owns commit), we re-select max(seq) and try again with a
    fresh seq value. Up to `_RECORD_EVENT_MAX_RETRIES` attempts; after that we
    re-raise so an actual bug surfaces instead of silently dropping events.
    """
    for attempt in range(_RECORD_EVENT_MAX_RETRIES):
        sp = db.begin_nested()
        try:
            seq = next_event_seq(db, run_id)
            ev = RunEvent(run_id=run_id, seq=seq, kind=kind, payload=payload or {})
            db.add(ev)
            db.flush()
            sp.commit()
            return ev
        except IntegrityError:
            sp.rollback()
            if attempt == _RECORD_EVENT_MAX_RETRIES - 1:
                raise
            # Loop: next iteration re-selects max(seq) in a fresh SAVEPOINT.
    raise RuntimeError("record_event: exhausted retries without raising")  # pragma: no cover


def record_tool_action(
    db: Session,
    *,
    run_id: str,
    tool_id: str,
    profile_id: str,
    args: dict,
    target_ref: str,
    action_digest: str,
    idempotency_key: str,
    policy_class: str,
    state: str = "proposed",
) -> ToolActionRecord:
    """Idempotent on idempotency_key: a replay returns the existing record rather
    than inserting a duplicate (supports queue retries / graph replay)."""
    existing = db.execute(
        select(ToolActionRecord).where(ToolActionRecord.idempotency_key == idempotency_key)
    ).scalar_one_or_none()
    if existing is not None:
        return existing
    rec = ToolActionRecord(
        run_id=run_id,
        tool_id=tool_id,
        profile_id=profile_id,
        args=args,
        target_ref=target_ref,
        action_digest=action_digest,
        idempotency_key=idempotency_key,
        policy_class=policy_class,
        state=state,
    )
    db.add(rec)
    db.flush()
    return rec


def set_action_state(db: Session, action: ToolActionRecord, state: str) -> None:
    action.state = state
    db.flush()


def get_action_by_key(db: Session, idempotency_key: str) -> ToolActionRecord | None:
    """Look up a recorded action by its idempotency key. Lets a re-entrant graph node
    skip an action already executed in a prior invocation (the ledger, not the
    checkpoint, is the authority on what actually ran)."""
    return db.execute(
        select(ToolActionRecord).where(ToolActionRecord.idempotency_key == idempotency_key)
    ).scalar_one_or_none()


def record_model_call(
    db: Session,
    *,
    run_id: str | None,
    profile_id: str,
    provider: str,
    model_id: str,
    finish_reason: str,
    usage: dict | None = None,
    latency_ms: int = 0,
    trace_id: str | None = None,
    agent_id: str | None = None,
    prompt_version: str | None = None,
    data_class: str = "standard",
    error: str | None = None,
) -> ModelCall:
    """Append an audit row for one gateway invocation. Counts only — never the prompt
    or completion text. `error` is expected to be pre-redacted by the gateway."""
    usage = usage or {}
    rec = ModelCall(
        run_id=run_id,
        profile_id=profile_id,
        provider=provider,
        model_id=model_id,
        agent_id=agent_id,
        prompt_version=prompt_version,
        data_class=data_class,
        finish_reason=finish_reason,
        prompt_tokens=int(usage.get("input_tokens", usage.get("prompt_tokens", 0)) or 0),
        completion_tokens=int(usage.get("output_tokens", usage.get("completion_tokens", 0)) or 0),
        total_tokens=int(usage.get("total_tokens", 0) or 0),
        latency_ms=latency_ms,
        trace_id=trace_id,
        error=error,
    )
    db.add(rec)
    db.flush()
    return rec


def record_policy_decision(
    db: Session,
    *,
    run_id: str,
    action_digest: str,
    policy_version: str,
    decision: str,
    reason: str,
) -> PolicyDecisionRecord:
    rec = PolicyDecisionRecord(
        run_id=run_id,
        action_digest=action_digest,
        policy_version=policy_version,
        decision=decision,
        reason=reason,
    )
    db.add(rec)
    db.flush()
    return rec


def create_approval(
    db: Session,
    *,
    run_id: str,
    action_digest: str,
    policy_class: str,
    requested_by: str | None = None,
    expires_at: datetime | None = None,
) -> Approval:
    appr = Approval(
        run_id=run_id,
        action_digest=action_digest,
        policy_class=policy_class,
        state="pending",
        requested_by=requested_by,
        expires_at=expires_at,
    )
    db.add(appr)
    db.flush()
    return appr


def get_pending_approval(db: Session, run_id: str, action_digest: str) -> Approval | None:
    return db.execute(
        select(Approval).where(
            Approval.run_id == run_id,
            Approval.action_digest == action_digest,
            Approval.state == "pending",
        )
    ).scalar_one_or_none()
