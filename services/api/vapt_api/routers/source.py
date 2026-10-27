"""Source bundle upload + listing for white-box engagements (plan §5, BAR-27).

The uploaded archive is stored and safely extracted; a SourceBundle row links it to the
engagement. A source run analyzes the latest bundle. The bundle is the engagement's
authorized scope — there is no network target."""
from __future__ import annotations

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session
from vapt_domain.enums import Role
from vapt_persistence.models import Engagement, SourceBundle

from ..config import get_settings
from ..deps import CurrentUser, get_current_user, get_db, require_project_role
from ..sourcestore import UnsafeArchive, store_bundle

router = APIRouter(prefix="/api/v2/engagements", tags=["source"])


class SourceBundleOut(BaseModel):
    id: str
    engagement_id: str
    filename: str
    sha256: str
    byte_length: int
    file_count: int
    created_at: str


def _engagement(db: Session, engagement_id: str) -> Engagement:
    eng = db.get(Engagement, engagement_id)
    if eng is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "engagement not found")
    return eng


def _out(b: SourceBundle) -> SourceBundleOut:
    return SourceBundleOut(
        id=b.id, engagement_id=b.engagement_id, filename=b.filename, sha256=b.sha256,
        byte_length=b.byte_length, file_count=b.file_count, created_at=b.created_at.isoformat(),
    )


@router.post("/{engagement_id}/source", response_model=SourceBundleOut,
             status_code=status.HTTP_201_CREATED)
async def upload_source(
    engagement_id: str,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> SourceBundleOut:
    eng = _engagement(db, engagement_id)
    require_project_role(eng.project_id, user, Role.ANALYST, Role.LEAD)

    data = await file.read()
    if not data:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "empty upload")
    if len(data) > get_settings().source_max_bytes:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "source bundle too large")

    try:
        meta = store_bundle(engagement_id, file.filename or "bundle", data)
    except UnsafeArchive as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc

    bundle = SourceBundle(
        id=meta["id"], engagement_id=engagement_id, filename=file.filename or "bundle",
        sha256=meta["sha256"], byte_length=meta["byte_length"],
        storage_key=meta["storage_key"], extracted_path=meta["extracted_path"],
        file_count=meta["file_count"], uploaded_by=user.id,
    )
    db.add(bundle)
    db.commit()
    db.refresh(bundle)
    return _out(bundle)


@router.get("/{engagement_id}/source", response_model=list[SourceBundleOut])
def list_source(
    engagement_id: str,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> list[SourceBundleOut]:
    eng = _engagement(db, engagement_id)
    require_project_role(eng.project_id, user, Role.VIEWER, Role.ANALYST, Role.LEAD, Role.REVIEWER)
    rows = db.execute(
        select(SourceBundle).where(SourceBundle.engagement_id == engagement_id)
        .order_by(SourceBundle.created_at.desc())
    ).scalars().all()
    return [_out(b) for b in rows]
