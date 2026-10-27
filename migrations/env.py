"""Alembic environment. Reads the URL from VAPT_DATABASE_URL and targets the
SQLAlchemy metadata from vapt_persistence so autogenerate works.
"""
from __future__ import annotations

import os
import sys
from logging.config import fileConfig
from pathlib import Path

from alembic import context
from sqlalchemy import engine_from_config, pool

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent / "packages" / "domain"))
sys.path.insert(0, str(_HERE.parent / "packages" / "persistence"))

from vapt_persistence import (
    Base,  # noqa: E402
    models,  # noqa: E402,F401  (register tables)
)

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

db_url = os.environ.get("VAPT_DATABASE_URL", "sqlite:///./vapt_v2_dev.db")
config.set_main_option("sqlalchemy.url", db_url)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    context.configure(
        url=db_url, target_metadata=target_metadata, literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
