"""Engine + session management.

Sync SQLAlchemy by design: DB access runs outside the async event loop
(plan §3). The API calls these from threadpool-executed sync dependencies.
"""
from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

_engine: Engine | None = None
SessionLocal: sessionmaker | None = None


def init_engine(url: str, echo: bool = False) -> Engine:
    """Initialise the global engine. Call once at startup (or per test)."""
    global _engine, SessionLocal
    connect_args = {}
    if url.startswith("sqlite"):
        connect_args = {"check_same_thread": False}
    _engine = create_engine(
        url,
        echo=echo,
        pool_pre_ping=True,
        future=True,
        connect_args=connect_args,
    )
    SessionLocal = sessionmaker(bind=_engine, autoflush=False, expire_on_commit=False, future=True)
    return _engine


def get_engine() -> Engine:
    if _engine is None:
        raise RuntimeError("engine not initialised; call init_engine() first")
    return _engine


@contextmanager
def session_scope() -> Iterator[Session]:
    """Transactional scope. Commits on success, rolls back on error."""
    if SessionLocal is None:
        raise RuntimeError("engine not initialised; call init_engine() first")
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
