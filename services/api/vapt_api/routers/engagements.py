"""Engagement intake: creates an engagement + its first scope version.

Scope is stored versioned (append-only). New assets stay proposed (approved=False)
until scope membership is established — wildcards never auto-expand execution scope.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session
from vapt_domain.enums import Role
from vapt_domain.schemas import EngagementCreate, EngagementOut
from vapt_persistence.models import Engagement, ScopeVersion

from ..deps import CurrentUser, get_current_user, get_db, require_project_role
from .projects import default_project_id

router = APIRouter(prefix="/api/v2/engagements", tags=["engagements"])


@router.post("", response_model=EngagementOut, status_code=status.HTTP_201_CREATED)
def create_engagement(
    body: EngagementCreate,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> Engagement:
    project_id = default_project_id(db)
    require_project_role(project_id, user, Role.ANALYST, Role.LEAD)

    eng = Engagement(
        project_id=project_id,
        name=body.name,
        testing_mode=body.testing_mode.value,
        target_type=body.target_type.value,
        scope_version=1,
    )
    db.add(eng)
    db.flush()  # assign eng.id

    db.add(
        ScopeVersion(
            engagement_id=eng.id,
            version=1,
            scope=body.scope.model_dump(mode="json"),
        )
    )
    db.commit()
    db.refresh(eng)
    return eng


@router.get("", response_model=list[EngagementOut])
def list_engagements(
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> list[Engagement]:
    project_id = default_project_id(db)
    require_project_role(project_id, user, Role.VIEWER, Role.ANALYST, Role.LEAD, Role.REVIEWER)
    return db.execute(
        select(Engagement).where(Engagement.project_id == project_id)
    ).scalars().all()


@router.get("/{engagement_id}", response_model=EngagementOut)
def get_engagement(
    engagement_id: str,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> Engagement:
    eng = db.get(Engagement, engagement_id)
    if eng is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "engagement not found")
    require_project_role(eng.project_id, user, Role.VIEWER, Role.ANALYST, Role.LEAD, Role.REVIEWER)
    return eng
