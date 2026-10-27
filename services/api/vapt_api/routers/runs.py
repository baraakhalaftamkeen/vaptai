"""Run lifecycle endpoints.

Creating a run commits the run AND an outbox record in one transaction (plan §6):
queue delivery can be retried without creating another run. The orchestrator worker
consumes the outbox. pause/cancel set flags the orchestrator observes at safe points.
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session
from vapt_domain.enums import Role, RunStatus
from vapt_domain.schemas import RunCreate, RunOut
from vapt_persistence.models import Approval, Engagement, Outbox, Run, RunEvent

from ..deps import CurrentUser, get_current_user, get_db, require_project_role

router = APIRouter(prefix="/api/v2/runs", tags=["runs"])


class RunEventOut(BaseModel):
    seq: int
    kind: str
    payload: dict
    created_at: str


def _next_seq(db: Session, run_id: str) -> int:
    rows = db.execute(select(RunEvent.seq).where(RunEvent.run_id == run_id)).scalars().all()
    return (max(rows) + 1) if rows else 1


@router.post("", response_model=RunOut, status_code=status.HTTP_201_CREATED)
def create_run(
    body: RunCreate,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> Run:
    eng = db.get(Engagement, str(body.engagement_id))
    if eng is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "engagement not found")
    require_project_role(eng.project_id, user, Role.ANALYST, Role.LEAD)

    run = Run(
        engagement_id=eng.id,
        thread_id=str(uuid.uuid4()),
        status=RunStatus.QUEUED.value,
        phase="intake",
        auto_approve=bool(body.auto_approve),
    )
    db.add(run)
    db.flush()

    # Stash web credentials in Redis (same slot the webvuln node reads from) BEFORE the
    # outbox entry fires — if the operator provided them (typically on an auto-approve
    # run where the credentials-prompt approval would be bypassed), they must be
    # available when the orchestrator starts the webvuln phase. Fail-open: a Redis
    # issue here does not block run creation; the scan simply runs unauthenticated.
    creds_stashed = False
    creds_b_stashed = False
    creds_c_stashed = False
    if body.web_username and body.web_password:
        try:
            from vapt_persistence import web_credentials
            web_credentials.set_web_credentials(
                run.id, body.web_username.strip(), body.web_password)
            creds_stashed = True
            # Second account for IDOR — only accepted when the primary set is present
            # (same login_url is used for both, so A must succeed first).
            if body.web_username_b and body.web_password_b:
                web_credentials.set_web_credentials_b(
                    run.id, body.web_username_b.strip(), body.web_password_b)
                creds_b_stashed = True
            # Third account enables the admin + 2-user IDOR model: the probe
            # pairs B+C (two normal users) rather than A+B (admin+user), which
            # avoids false "legitimate access" positives on admin-only pages
            # the normal user is simply not allowed to see. B must be present
            # too — a bare A+C makes no sense.
            if (body.web_username_c and body.web_password_c
                    and creds_b_stashed):
                web_credentials.set_web_credentials_c(
                    run.id, body.web_username_c.strip(), body.web_password_c)
                creds_c_stashed = True
        except Exception:
            creds_stashed = False  # degrade to unauthenticated, don't fail the run
            creds_b_stashed = False
            creds_c_stashed = False
    db.add(RunEvent(run_id=run.id, seq=1, kind="run.created",
                    payload={"phase": "intake",
                             "auto_approve": bool(body.auto_approve),
                             "web_credentials": "provided" if creds_stashed else "none",
                             "web_credentials_b": "provided" if creds_b_stashed else "none",
                             "web_credentials_c": "provided" if creds_c_stashed else "none"}))
    db.add(Outbox(run_id=run.id, topic="run.start", payload={"run_id": run.id}))
    db.commit()
    db.refresh(run)
    return run


@router.get("", response_model=list[RunOut])
def list_runs(
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> list[Run]:
    # Scope to runs whose engagement is in a project the user can read.
    runs = db.execute(select(Run)).scalars().all()
    visible = []
    for r in runs:
        eng = db.get(Engagement, r.engagement_id)
        if eng and user.role_in(eng.project_id):
            visible.append(r)
    return visible


@router.get("/{run_id}", response_model=RunOut)
def get_run(
    run_id: str,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> Run:
    run = db.get(Run, run_id)
    if run is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "run not found")
    eng = db.get(Engagement, run.engagement_id)
    require_project_role(eng.project_id, user, Role.VIEWER, Role.ANALYST, Role.LEAD, Role.REVIEWER)
    return run


@router.get("/{run_id}/events", response_model=list[RunEventOut])
def run_events(
    run_id: str,
    after_seq: int = 0,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> list[RunEventOut]:
    """Monotonic run timeline. `after_seq` supports SSE-style replay from Last-Event-ID."""
    run = db.get(Run, run_id)
    if run is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "run not found")
    eng = db.get(Engagement, run.engagement_id)
    require_project_role(eng.project_id, user, Role.VIEWER, Role.ANALYST, Role.LEAD, Role.REVIEWER)
    events = db.execute(
        select(RunEvent).where(RunEvent.run_id == run_id, RunEvent.seq > after_seq).order_by(RunEvent.seq)
    ).scalars().all()
    return [
        RunEventOut(seq=e.seq, kind=e.kind, payload=e.payload or {}, created_at=e.created_at.isoformat())
        for e in events
    ]


class RetestOut(BaseModel):
    current_run_id: str
    prior_run_id: str
    counts: dict
    fixed: list[dict]
    still_open: list[dict]
    new: list[dict]


@router.post("/{run_id}/retest", response_model=RunOut, status_code=status.HTTP_201_CREATED)
def retest_run(
    run_id: str,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> Run:
    """Start a new run that re-checks this one; fixes can then be compared. Writes the
    run + an outbox start intent in one transaction, like create_run."""
    prior = db.get(Run, run_id)
    if prior is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "run not found")
    eng = db.get(Engagement, prior.engagement_id)
    require_project_role(eng.project_id, user, Role.ANALYST, Role.LEAD)

    run = Run(
        engagement_id=eng.id, thread_id=str(uuid.uuid4()),
        status=RunStatus.QUEUED.value, phase="intake", retest_of=prior.id,
    )
    db.add(run)
    db.flush()
    db.add(RunEvent(run_id=run.id, seq=1, kind="run.created",
                    payload={"phase": "intake", "retest_of": prior.id}))
    db.add(Outbox(run_id=run.id, topic="run.start", payload={"run_id": run.id}))
    db.commit()
    db.refresh(run)
    return run


@router.get("/{run_id}/retest", response_model=RetestOut)
def retest_comparison(
    run_id: str,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> RetestOut:
    """Compare this run's confirmed findings against the run it retests."""
    from vapt_agents.retest import compare_runs

    run = db.get(Run, run_id)
    if run is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "run not found")
    eng = db.get(Engagement, run.engagement_id)
    require_project_role(eng.project_id, user, Role.VIEWER, Role.ANALYST, Role.LEAD, Role.REVIEWER)
    if not run.retest_of:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "this run is not a retest of another run")
    res = compare_runs(db, run_id, run.retest_of)
    return RetestOut(
        current_run_id=res.current_run_id, prior_run_id=res.prior_run_id,
        counts=res.counts, fixed=res.fixed, still_open=res.still_open, new=res.new,
    )


@router.post("/{run_id}/pause", response_model=RunOut)
def pause_run(
    run_id: str,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> Run:
    run = _owned_run(db, user, run_id, Role.ANALYST, Role.LEAD)
    run.status = RunStatus.PAUSED.value
    db.add(RunEvent(run_id=run.id, seq=_next_seq(db, run.id), kind="run.paused", payload={}))
    db.commit()
    db.refresh(run)
    return run


_TERMINAL_STATUSES = {RunStatus.COMPLETED.value, RunStatus.CANCELLED.value, RunStatus.FAILED.value}


@router.post("/{run_id}/cancel", response_model=RunOut)
def cancel_run(
    run_id: str,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> Run:
    """Cancel a run. Terminates it immediately (abandoning any paused graph): pending
    approvals are rejected and the run goes to CANCELLED. Idempotent, and it also rescues
    a run left stuck in 'cancelling'. The cancellation_requested flag is set too, so an
    in-flight graph that checks it also bails at its next safe point. (Graceful mid-run
    cooperative cancellation is BAR-31; this guarantees a cancel always reaches a terminal
    state instead of hanging.)"""
    run = _owned_run(db, user, run_id, Role.ANALYST, Role.LEAD)
    if run.status in _TERMINAL_STATUSES:
        return run   # already finished — nothing to cancel

    # Reject any pending approvals so nothing can resume this run later.
    for appr in db.query(Approval).filter(
        Approval.run_id == run.id, Approval.state == "pending"
    ).all():
        appr.state = "rejected"

    run.cancellation_requested = True
    run.status = RunStatus.CANCELLED.value
    run.phase = "cancelled"
    db.add(RunEvent(run_id=run.id, seq=_next_seq(db, run.id), kind="run.cancelled",
                    payload={"by": user.id}))
    db.commit()
    db.refresh(run)
    return run


def _owned_run(db: Session, user: CurrentUser, run_id: str, *roles: Role) -> Run:
    run = db.get(Run, run_id)
    if run is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "run not found")
    eng = db.get(Engagement, run.engagement_id)
    require_project_role(eng.project_id, user, *roles)
    return run
