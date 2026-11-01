"""One-time bootstrap: create tables (dev), seed the default project + first admin.

The admin is seeded from config on first run only — never a shared hard-coded
default in source. In staging/prod, use migrations (Alembic) instead of create_all
and rotate the bootstrap password immediately.
"""
from __future__ import annotations

import logging

from sqlalchemy import select, text
from sqlalchemy.orm import Session
from vapt_domain.enums import Role
from vapt_persistence import Base, get_engine
from vapt_persistence.models import Membership, Project, User

from .config import get_settings
from .security import hash_password

log = logging.getLogger(__name__)

_COLUMN_MIGRATIONS: list[tuple[str, str, str]] = [
    ("findings", "target_url", "VARCHAR(1000) NOT NULL DEFAULT ''"),
    ("findings", "resolution_status", "VARCHAR(30) NOT NULL DEFAULT 'open'"),
    ("findings", "notes", "TEXT NOT NULL DEFAULT ''"),
    ("findings", "enrichment", "JSON DEFAULT NULL"),
]


def _add_missing_columns(engine) -> None:
    with engine.connect() as conn:
        for table, column, col_def in _COLUMN_MIGRATIONS:
            try:
                conn.execute(text(f"SELECT `{column}` FROM `{table}` LIMIT 0"))
            except Exception:
                try:
                    conn.execute(text(
                        f"ALTER TABLE `{table}` ADD COLUMN `{column}` {col_def}"
                    ))
                    conn.commit()
                    log.info("added column %s.%s", table, column)
                except Exception as exc:
                    log.warning("could not add column %s.%s: %s", table, column, exc)


def create_all_dev() -> None:
    engine = get_engine()
    Base.metadata.create_all(bind=engine)
    _add_missing_columns(engine)


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
