"""Minimal project helper for the single-tenant beta.

The beta targets one organization with one default project; multi-project/tenant
management is deferred. This module just resolves (and lazily seeds) that project.
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session
from vapt_persistence.models import Project

from ..config import get_settings


def default_project_id(db: Session) -> str:
    settings = get_settings()
    proj = db.execute(
        select(Project).where(Project.name == settings.default_project_name)
    ).scalar_one_or_none()
    if proj is None:
        proj = Project(name=settings.default_project_name)
        db.add(proj)
        db.commit()
        db.refresh(proj)
    return proj.id
