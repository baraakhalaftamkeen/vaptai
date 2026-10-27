"""Dashboard summary: one request for the operator's whole picture.

Aggregates run state, the pending-approval queue, finding counts by severity, and
the governed-action mix (how much work ran at each policy class). Scoped to the
projects the caller belongs to.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from vapt_domain.enums import ApprovalState
from vapt_persistence.models import (
    Approval,
    Engagement,
    Finding,
    Run,
    ToolActionRecord,
)

from ..deps import CurrentUser, get_current_user, get_db

router = APIRouter(prefix="/api/v2", tags=["dashboard"])


class PendingApproval(BaseModel):
    id: str
    run_id: str
    policy_class: str
    action_digest: str
    tool_id: str | None = None
    target_ref: str | None = None


class RunSummary(BaseModel):
    id: str
    engagement_name: str
    status: str
    phase: str | None
    updated_at: str


class FindingSummary(BaseModel):
    id: str
    run_id: str
    title: str
    severity: str
    status: str


class DashboardOut(BaseModel):
    run_counts: dict[str, int]
    severity_counts: dict[str, int]
    finding_status_counts: dict[str, int]
    action_class_counts: dict[str, int]
    pending_approvals: list[PendingApproval]
    active_runs: list[RunSummary]
    recent_findings: list[FindingSummary]
    totals: dict[str, int]


_ACTIVE = {"queued", "running", "paused", "awaiting_approval", "cancelling"}


@router.get("/dashboard", response_model=DashboardOut)
def dashboard(
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> DashboardOut:
    # Engagements the caller can see, by project membership.
    engagements = {
        e.id: e
        for e in db.execute(select(Engagement)).scalars().all()
        if user.role_in(e.project_id)
    }
    runs = [
        r for r in db.execute(select(Run)).scalars().all() if r.engagement_id in engagements
    ]
    run_ids = {r.id for r in runs}

    run_counts: dict[str, int] = {}
    for r in runs:
        run_counts[r.status] = run_counts.get(r.status, 0) + 1

    findings = [
        f for f in db.execute(select(Finding)).scalars().all() if f.run_id in run_ids
    ]
    severity_counts: dict[str, int] = {}
    finding_status_counts: dict[str, int] = {}
    for f in findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        finding_status_counts[f.status] = finding_status_counts.get(f.status, 0) + 1

    actions = [
        a for a in db.execute(select(ToolActionRecord)).scalars().all() if a.run_id in run_ids
    ]
    action_class_counts: dict[str, int] = {}
    for a in actions:
        action_class_counts[a.policy_class] = action_class_counts.get(a.policy_class, 0) + 1
    action_by_digest = {a.action_digest: a for a in actions}

    approvals = [
        a
        for a in db.execute(
            select(Approval).where(Approval.state == ApprovalState.PENDING.value)
        ).scalars().all()
        if a.run_id in run_ids
    ]
    pending = []
    for a in approvals:
        act = action_by_digest.get(a.action_digest)
        pending.append(
            PendingApproval(
                id=a.id, run_id=a.run_id, policy_class=a.policy_class,
                action_digest=a.action_digest,
                tool_id=act.tool_id if act else None,
                target_ref=act.target_ref if act else None,
            )
        )

    active = sorted(
        (r for r in runs if r.status in _ACTIVE), key=lambda r: r.updated_at, reverse=True
    )[:6]
    active_runs = [
        RunSummary(
            id=r.id,
            engagement_name=engagements[r.engagement_id].name,
            status=r.status,
            phase=r.phase,
            updated_at=r.updated_at.isoformat(),
        )
        for r in active
    ]

    recent = sorted(findings, key=lambda f: f.created_at, reverse=True)[:8]
    recent_findings = [
        FindingSummary(id=f.id, run_id=f.run_id, title=f.title, severity=f.severity, status=f.status)
        for f in recent
    ]

    return DashboardOut(
        run_counts=run_counts,
        severity_counts=severity_counts,
        finding_status_counts=finding_status_counts,
        action_class_counts=action_class_counts,
        pending_approvals=pending,
        active_runs=active_runs,
        recent_findings=recent_findings,
        totals={
            "engagements": len(engagements),
            "runs": len(runs),
            "findings": len(findings),
            "actions": len(actions),
        },
    )
