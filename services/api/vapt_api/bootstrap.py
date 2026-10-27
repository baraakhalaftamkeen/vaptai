"""One-time bootstrap: create tables (dev), seed the default project + first admin.

The admin is seeded from config on first run only — never a shared hard-coded
default in source. In staging/prod, use migrations (Alembic) instead of create_all
and rotate the bootstrap password immediately.
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session
from vapt_domain.enums import Role
from vapt_persistence import Base, get_engine
from vapt_persistence.models import Membership, Project, User

from .config import get_settings
from .security import hash_password


def create_all_dev() -> None:
    Base.metadata.create_all(bind=get_engine())


def seed_admin(db: Session) -> None:
    settings = get_settings()
    existing = db.execute(select(User).limit(1)).scalar_one_or_none()
    if existing is not None:
        return  # already seeded

    project = db.execute(
        select(Project).where(Project.name == settings.default_project_name)
    ).scalar_one_or_none()
    if project is None:
        project = Project(name=settings.default_project_name)
        db.add(project)
        db.flush()

    admin = User(
        username=settings.bootstrap_admin_user,
        password_hash=hash_password(settings.bootstrap_admin_password),
        is_active=True,
    )
    db.add(admin)
    db.flush()
    db.add(Membership(project_id=project.id, user_id=admin.id, role=Role.ADMIN.value))
    db.commit()
