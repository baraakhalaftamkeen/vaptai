"""Recurring assessment schedules for an engagement (plan §5, BAR-29).

Interval-based for the beta: a schedule fires every `interval_minutes`, and the
orchestrator's beat tick creates the run (linked as a retest of the prior run). Cron is
stored for display/future use."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session
from vapt_domain.enums import Role
from vapt_persistence.models import Engagement, Schedule

from ..deps import CurrentUser, get_current_user, get_db, require_project_role

router = APIRouter(prefix="/api/v2/engagements", tags=["schedules"])


class ScheduleCreate(BaseModel):
    interval_minutes: int = Field(ge=5, le=525600)   # 5 min .. 1 year
    enabled: bool = True


class ScheduleOut(BaseModel):
    id: str
    engagement_id: str
    interval_minutes: int | None
    enabled: bool
    cron: str
    next_fire_at: str | None
    last_fired_at: str | None
    created_at: str


def _engagement(db: Session, engagement_id: str) -> Engagement:
    eng = db.get(Engagement, engagement_id)
    if eng is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "engagement not found")
    return eng


def _out(s: Schedule) -> ScheduleOut:
    return ScheduleOut(
        id=s.id, engagement_id=s.engagement_id, interval_minutes=s.interval_minutes,
        enabled=s.enabled, cron=s.cron or "",
        next_fire_at=s.next_fire_at.isoformat() if s.next_fire_at else None,
        last_fired_at=s.last_fired_at.isoformat() if s.last_fired_at else None,
        created_at=s.created_at.isoformat(),
    )


@router.post("/{engagement_id}/schedules", response_model=ScheduleOut,
             status_code=status.HTTP_201_CREATED)
def create_schedule(
    engagement_id: str,
    body: ScheduleCreate,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> ScheduleOut:
    eng = _engagement(db, engagement_id)
    require_project_role(eng.project_id, user, Role.ANALYST, Role.LEAD)
    now = datetime.now(UTC)
    sch = Schedule(
        engagement_id=engagement_id,
        cron=f"every {body.interval_minutes}m",
        interval_minutes=body.interval_minutes,
        enabled=body.enabled,
        next_fire_at=now + timedelta(minutes=body.interval_minutes) if body.enabled else None,
    )
    db.add(sch)
    db.commit()
    db.refresh(sch)
    return _out(sch)


@router.get("/{engagement_id}/schedules", response_model=list[ScheduleOut])
def list_schedules(
    engagement_id: str,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> list[ScheduleOut]:
    eng = _engagement(db, engagement_id)
    require_project_role(eng.project_id, user, Role.VIEWER, Role.ANALYST, Role.LEAD, Role.REVIEWER)
    rows = db.execute(
        select(Schedule).where(Schedule.engagement_id == engagement_id)
        .order_by(Schedule.created_at.desc())
    ).scalars().all()
    return [_out(s) for s in rows]


@router.delete("/{engagement_id}/schedules/{schedule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_schedule(
    engagement_id: str,
    schedule_id: str,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> None:
    eng = _engagement(db, engagement_id)
    require_project_role(eng.project_id, user, Role.ANALYST, Role.LEAD)
    sch = db.get(Schedule, schedule_id)
    if sch is None or sch.engagement_id != engagement_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "schedule not found")
    db.delete(sch)
    db.commit()
