"""FastAPI application entry point."""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from vapt_persistence import init_engine

from .bootstrap import create_all_dev, seed_admin
from .config import get_settings
from .deps import get_db
from .routers import (
    approvals,
    auth,
    cve,
    dashboard,
    engagements,
    findings,
    health,
    playbooks,
    reports,
    runs,
    schedules,
    source,
    users,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    init_engine(settings.database_url, echo=settings.echo_sql)
    # Dev convenience: create tables + seed admin. Prod uses Alembic migrations.
    if settings.database_url.startswith("sqlite"):
        create_all_dev()
    db_gen = get_db()
    db = next(db_gen)
    try:
        seed_admin(db)
    finally:
        db.close()
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(title="VAPT-AI V2 API", version="0.1.0", lifespan=lifespan)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(health.router)
    app.include_router(auth.router)
    app.include_router(users.router)
    app.include_router(engagements.router)
    app.include_router(source.router)
    app.include_router(schedules.router)
    app.include_router(runs.router)
    app.include_router(approvals.router)
    app.include_router(findings.router)
    app.include_router(playbooks.router)
    app.include_router(reports.router)
    app.include_router(dashboard.router)
    app.include_router(cve.router)
    return app


app = create_app()
