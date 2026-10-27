"""Findings + evidence endpoints (plan §8).

Findings preserve observation vs interpretation: a finding carries a status
(candidate/confirmed/false_positive/inconclusive) and links to the observations that
produced it, each tagged with its source tool.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from vapt_domain.enums import Role
from vapt_persistence.models import Engagement, Finding, FindingObservation, Run

from ..deps import CurrentUser, get_current_user, get_db, require_project_role

router = APIRouter(prefix="/api/v2", tags=["findings"])


class ObservationOut(BaseModel):
    id: str
    source_tool: str
    detail: dict
    created_at: str


class FindingOut(BaseModel):
    id: str
    run_id: str
    title: str
    status: str
    severity: str
    description: str
    observations: list[ObservationOut] = []
    created_at: str


def _authz_run(db: Session, user: CurrentUser, run_id: str) -> Run:
    run = db.get(Run, run_id)
    if run is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "run not found")
    eng = db.get(Engagement, run.engagement_id)
    require_project_role(eng.project_id, user, Role.VIEWER, Role.ANALYST, Role.LEAD, Role.REVIEWER)
    return run


@router.get("/runs/{run_id}/findings", response_model=list[FindingOut])
def list_findings(
    run_id: str,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> list[FindingOut]:
    _authz_run(db, user, run_id)
    findings = db.execute(select(Finding).where(Finding.run_id == run_id)).scalars().all()
    return [_to_out(db, f) for f in findings]


@router.get("/findings/{finding_id}", response_model=FindingOut)
def get_finding(
    finding_id: str,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> FindingOut:
    f = db.get(Finding, finding_id)
    if f is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")
    _authz_run(db, user, f.run_id)
    return _to_out(db, f)


def _to_out(db: Session, f: Finding) -> FindingOut:
    obs = db.execute(
        select(FindingObservation).where(FindingObservation.finding_id == f.id)
    ).scalars().all()
    return FindingOut(
        id=f.id,
        run_id=f.run_id,
        title=f.title,
        status=f.status,
        severity=f.severity,
        description=f.description or "",
        observations=[
            ObservationOut(
                id=o.id, source_tool=o.source_tool, detail=o.detail or {},
                created_at=o.created_at.isoformat(),
            )
            for o in obs
        ],
        created_at=f.created_at.isoformat(),
    )
