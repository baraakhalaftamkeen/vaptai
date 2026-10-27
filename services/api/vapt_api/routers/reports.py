"""Report retrieval, download, regeneration and reviewer sign-off (plan §8, BAR-28).

A run's reporting agent generates a draft Report during the run. These endpoints expose
the latest report's metadata and rendered HTML/PDF, let an analyst regenerate it from the
current findings, and let a reviewer/lead sign it off (draft → final)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session
from vapt_agents.report import build_and_store, try_pdf
from vapt_domain.enums import Role
from vapt_persistence.models import Engagement, Report, Run

from ..deps import CurrentUser, get_current_user, get_db, require_project_role

router = APIRouter(prefix="/api/v2/runs", tags=["reports"])


class ReportOut(BaseModel):
    id: str
    run_id: str
    fmt: str
    status: str
    title: str
    summary: str
    remediation: str
    stats: dict
    signed_off_by: str | None
    created_at: str


def _run_project(db: Session, run_id: str) -> tuple[Run, str]:
    run = db.get(Run, run_id)
    if run is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "run not found")
    eng = db.get(Engagement, run.engagement_id)
    return run, eng.project_id


def _latest(db: Session, run_id: str) -> Report | None:
    return db.execute(
        select(Report).where(Report.run_id == run_id).order_by(Report.created_at.desc())
    ).scalars().first()


def _out(r: Report) -> ReportOut:
    return ReportOut(
        id=r.id, run_id=r.run_id, fmt=r.fmt, status=r.status, title=r.title,
        summary=r.summary or "", remediation=r.remediation or "", stats=r.stats or {},
        signed_off_by=r.signed_off_by, created_at=r.created_at.isoformat(),
    )


@router.get("/{run_id}/report", response_model=ReportOut)
def get_report(
    run_id: str,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> ReportOut:
    _, project_id = _run_project(db, run_id)
    require_project_role(project_id, user, Role.VIEWER, Role.ANALYST, Role.LEAD, Role.REVIEWER)
    report = _latest(db, run_id)
    if report is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no report generated for this run yet")
    return _out(report)


@router.get("/{run_id}/report/download")
def download_report(
    run_id: str,
    format: str = "html",
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> Response:
    _, project_id = _run_project(db, run_id)
    require_project_role(project_id, user, Role.VIEWER, Role.ANALYST, Role.LEAD, Role.REVIEWER)
    report = _latest(db, run_id)
    if report is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no report generated for this run yet")

    filename = f"report-{run_id[:8]}"
    if format == "pdf":
        pdf = try_pdf(report.content)
        if pdf is None:
            # PDF rendering isn't available on this host; the HTML is print-ready.
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "PDF rendering unavailable (WeasyPrint not installed); download HTML and print to PDF",
            )
        return Response(
            content=pdf, media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}.pdf"'},
        )
    return Response(
        content=report.content, media_type="text/html",
        headers={"Content-Disposition": f'inline; filename="{filename}.html"'},
    )


@router.post("/{run_id}/report/regenerate", response_model=ReportOut)
def regenerate_report(
    run_id: str,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> ReportOut:
    run, project_id = _run_project(db, run_id)
    require_project_role(project_id, user, Role.ANALYST, Role.LEAD)
    prev = _latest(db, run_id)
    # Re-render from the CURRENT findings, keeping the model-drafted narrative if present.
    report = build_and_store(
        db, run_id,
        summary=(prev.summary if prev else ""),
        remediation=(prev.remediation if prev else ""),
        generated_by=f"regenerated:{user.id}",
        title=(prev.title if prev else "Assessment report"),
    )
    db.commit()
    db.refresh(report)
    return _out(report)


class SignoffResult(ReportOut):
    pass


@router.post("/{run_id}/report/signoff", response_model=ReportOut)
def signoff_report(
    run_id: str,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> ReportOut:
    _, project_id = _run_project(db, run_id)
    require_project_role(project_id, user, Role.LEAD, Role.REVIEWER)
    report = _latest(db, run_id)
    if report is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no report to sign off")
    if report.status == "final":
        raise HTTPException(status.HTTP_409_CONFLICT, "report already signed off")
    report.status = "final"
    report.signed_off_by = user.id
    db.commit()
    db.refresh(report)
    return _out(report)
