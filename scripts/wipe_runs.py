#!/usr/bin/env python3
"""Delete ALL runs and everything hanging off them, in FK-safe order.

Keeps projects, users, engagements, scopes, assets, model profiles and schedules —
only runs and their children (findings, events, ledger, approvals, reports, …) plus the
LangGraph checkpoints are removed, so you get a clean slate to re-run without dropping the
engagements you set up.

Uses the SAME database the app uses: it auto-loads VAPT_DATABASE_URL from the repo's .env
(the app is on MySQL, e.g. mysql+pymysql://vapt:***@localhost:3306/vapt_v2), so you don't
have to export anything. Works on MySQL/MariaDB and SQLite alike. Safe-guarded: it refuses
to run without --yes, and it ABORTS (instead of creating an empty DB) if the target
database has no `runs` table — that means it's pointed at the wrong place.

    cd ~/Desktop/VAPT-AI/vapt-ai-v2        # the real repo (where .env lives)
    source .venv/bin/activate
    python scripts/wipe_runs.py --yes
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

from sqlalchemy import create_engine, inspect, text

# Children first, parents last — valid on MySQL (FK enforced) and SQLite alike. Every
# table here is run-scoped; nothing outside a run is touched.
_ORDER = [
    "finding_observations",      # -> findings
    "findings",                  # -> runs
    "tasks",                     # -> runs
    "run_events",                # -> runs
    "outbox",                    # -> runs
    "tool_actions",              # -> runs
    "execution_leases",          # -> runs
    "policy_decisions",          # -> runs
    "approvals",                 # -> runs
    "artifacts",                 # -> runs
    "reports",                   # -> runs
    # LangGraph checkpoints are keyed by thread_id (one per run); with every run gone there
    # is nothing left to resume, so clear them too or stale graph state lingers.
    "graph_checkpoint_writes",
    "graph_checkpoint_blobs",
    "graph_checkpoints",
]


def _load_dotenv() -> None:
    """Load VAPT_DATABASE_URL (and siblings) from the repo's .env if not already set, so
    the script hits the SAME database the app does without needing a pre-exported shell."""
    if os.environ.get("VAPT_DATABASE_URL"):
        return
    env_path = Path(__file__).resolve().parent.parent / ".env"
    if not env_path.exists():
        return
    for raw in env_path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key, val = key.strip(), val.strip().strip('"').strip("'")
        os.environ.setdefault(key, val)


def _masked(url: str) -> str:
    import re
    return re.sub(r"(://[^:/@]+:)[^@]+(@)", r"\1****\2", url)


def main() -> int:
    if "--yes" not in sys.argv:
        print("Refusing to wipe without confirmation. Re-run with:  "
              "python scripts/wipe_runs.py --yes")
        return 2

    _load_dotenv()
    url = os.environ.get("VAPT_DATABASE_URL", "sqlite:///./vapt_v2_dev.db")
    print(f"Database: {_masked(url)}")
    engine = create_engine(url, future=True)

    # Guard: never create/empty-wipe the wrong database. If `runs` isn't here, the URL is
    # pointed somewhere it shouldn't be (e.g. the sqlite fallback) — stop loudly.
    if "runs" not in inspect(engine).get_table_names():
        print("ABORT: no `runs` table in this database — it looks empty or wrong.\n"
              "       Run this from the real repo (where .env sets VAPT_DATABASE_URL to\n"
              "       your MySQL URL), or export VAPT_DATABASE_URL yourself.")
        return 3

    def _count(conn, table: str) -> int:
        try:
            return conn.execute(text(f"SELECT COUNT(*) FROM {table}")).scalar() or 0
        except Exception:
            return -1

    with engine.begin() as conn:
        # Break the runs self-reference (retest_of -> runs.id) before deleting runs, so the
        # final DELETE can't trip the FK on MySQL.
        try:
            conn.execute(text("UPDATE runs SET retest_of = NULL WHERE retest_of IS NOT NULL"))
        except Exception:
            pass

        # model_calls.run_id is nullable — drop only the run-scoped ones, keep the rest.
        try:
            n = conn.execute(text("DELETE FROM model_calls WHERE run_id IS NOT NULL")).rowcount
            print(f"  model_calls (run-scoped)      removed {n}")
        except Exception as e:
            print(f"  model_calls                   skipped ({e.__class__.__name__})")

        for table in _ORDER:
            before = _count(conn, table)
            if before < 0:
                print(f"  {table:<28}  (absent, skipped)")
                continue
            conn.execute(text(f"DELETE FROM {table}"))
            print(f"  {table:<28}  removed {before}")

        runs_before = _count(conn, "runs")
        conn.execute(text("DELETE FROM runs"))
        print(f"  {'runs':<28}  removed {runs_before}")

    print("Done — all runs wiped. Engagements and everything else are intact.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
