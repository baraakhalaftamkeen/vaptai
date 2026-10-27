"""Seed a demo engagement + run + one pending P2 approval, so the approval inbox
and run timeline have something to show before intrusive scanners are wired in.

Usage (from repo root, venv active, .env pointing at your DB):
    python scripts/seed_demo.py

It reads VAPT_DATABASE_URL from the environment (load .env first, e.g.
`set -a; . ./.env; set +a`). Safe to run repeatedly — it always makes a fresh run.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for rel in ("packages/domain", "packages/persistence"):
    sys.path.insert(0, str(ROOT / rel))

from vapt_persistence import init_engine, session_scope  # noqa: E402
from vapt_persistence import ledger  # noqa: E402
from vapt_persistence.models import Engagement, Project, Run, ScopeVersion  # noqa: E402


def main() -> None:
    url = os.environ.get("VAPT_DATABASE_URL", "sqlite:///./vapt_v2_dev.db")
    init_engine(url)
    with session_scope() as db:
        project = db.query(Project).filter(Project.name == "Default").first()
        if project is None:
            project = Project(name="Default")
            db.add(project)
            db.flush()

        eng = Engagement(
            project_id=project.id,
            name="Demo lab engagement",
            testing_mode="gray_box",
            target_type="web",
            scope_version=1,
        )
        db.add(eng)
        db.flush()
        db.add(ScopeVersion(
            engagement_id=eng.id, version=1,
            scope={"domains": ["example.com"], "allowed_action_classes": ["p0_passive", "p1_low_impact"]},
        ))

        run = Run(engagement_id=eng.id, thread_id=eng.id, status="awaiting_approval", phase="scan")
        db.add(run)
        db.flush()

        ledger.record_event(db, run.id, "run.created", {"demo": True})
        ledger.record_event(db, run.id, "phase.scan", {})
        digest = "demo" + "0" * 60
        ledger.record_tool_action(
            db, run_id=run.id, tool_id="nuclei_intrusive", profile_id="default",
            args={"target": "example.com", "severity": "high,critical"},
            target_ref="example.com", action_digest=digest,
            idempotency_key="demo-key-1", policy_class="p2_intrusive", state="proposed",
        )
        ledger.record_policy_decision(
            db, run_id=run.id, action_digest=digest, policy_version="v1",
            decision="require_approval", reason="P2 intrusive validation",
        )
        appr = ledger.create_approval(
            db, run_id=run.id, action_digest=digest, policy_class="p2_intrusive",
        )
        ledger.record_event(db, run.id, "approval.requested",
                            {"approval_id": appr.id, "digest": digest})

        print("Seeded demo:")
        print(f"  engagement_id = {eng.id}")
        print(f"  run_id        = {run.id}")
        print(f"  approval_id   = {appr.id}  (pending, P2)")
        print("Open the Approvals page in the UI to approve/reject it.")


if __name__ == "__main__":
    main()
