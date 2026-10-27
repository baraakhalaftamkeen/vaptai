"""Declarative base + portable column helpers.

The schema is designed for MariaDB (the plan preserves it) but stays
engine-portable so tests can run on SQLite. UUIDs are stored as CHAR(36),
JSON via SQLAlchemy's JSON type (native JSON on MariaDB, text on SQLite).
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import CHAR, DateTime, func
from sqlalchemy.orm import DeclarativeBase, mapped_column


def utcnow() -> datetime:
    return datetime.now(UTC)


def uuid_str() -> str:
    return str(uuid.uuid4())


class Base(DeclarativeBase):
    pass


def pk_column():
    return mapped_column(CHAR(36), primary_key=True, default=uuid_str)


def fk_uuid(nullable: bool = False):
    return mapped_column(CHAR(36), nullable=nullable, index=True)


def created_column():
    return mapped_column(DateTime(timezone=True), default=utcnow, server_default=func.now())


def updated_column():
    return mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, server_default=func.now()
    )
