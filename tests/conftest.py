"""Make the monorepo packages importable without installing them, and give each
test a fresh in-memory SQLite database.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
for rel in (
    "packages/domain",
    "packages/persistence",
    "packages/llm_gateway",
    "packages/policy",
    "packages/tools",
    "packages/harness",
    "packages/skills",
    "packages/agents",
    "services/api",
    "services/orchestrator",
):
    sys.path.insert(0, str(ROOT / rel))

# Use an isolated sqlite file per session for the API app.
os.environ.setdefault("VAPT_DATABASE_URL", "sqlite:///./vapt_test.db")
os.environ.setdefault("VAPT_BOOTSTRAP_ADMIN_PASSWORD", "test-admin-pw")


@pytest.fixture()
def db_engine(tmp_path):
    from vapt_persistence import Base, init_engine

    url = f"sqlite:///{tmp_path}/t.db"
    engine = init_engine(url)
    Base.metadata.create_all(engine)
    return engine
