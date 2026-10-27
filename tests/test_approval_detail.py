"""An approval must tell the reviewer WHAT will run (tool, target, why) — derived from
the proposed action on the same digest — not just a policy class + opaque digest."""
from __future__ import annotations

import pytest
import vapt_persistence.db as dbmod
from vapt_api.routers.approvals import _enrich
from vapt_persistence import Base, init_engine
from vapt_persistence.models import Approval, Engagement, Project, Run, ToolActionRecord


@pytest.fixture()
def db(tmp_path):
    init_engine(f"sqlite:///{tmp_path}/ap.db")
    Base.metadata.create_all(dbmod.get_engine())
    s = dbmod.SessionLocal()
    p = Project(name="P"); s.add(p); s.flush()
    e = Engagement(project_id=p.id, name="L", testing_mode="black_box", target_type="network")
    s.add(e); s.flush()
    r = Run(engagement_id=e.id, thread_id="t", status="awaiting_approval"); s.add(r); s.flush()
    s.commit()
    yield s, r.id
    s.close()


def _approval(s, run_id, digest, pclass="p1_low_impact"):
    a = Approval(run_id=run_id, action_digest=digest, policy_class=pclass, state="pending")
    s.add(a); s.flush()
    return a


def _action(s, run_id, digest, tool_id, target, args):
    s.add(ToolActionRecord(run_id=run_id, tool_id=tool_id, profile_id="default", args=args,
                           target_ref=target, action_digest=digest, idempotency_key=digest,
                           policy_class="p1_low_impact", state="proposed"))
    s.flush()


def test_poc_approval_shows_what_will_run(db):
    s, run_id = db
    _action(s, run_id, "d1", "burp_request", "172.25.188.23", {"scheme": "http", "port": "5985"})
    out = _enrich(s, _approval(s, run_id, "d1"))
    assert out.tool_id == "burp_request"
    assert out.target == "http://172.25.188.23:5985"
    assert "read-only request" in out.summary.lower()
    assert "proof-of-concept" in out.reason.lower()      # names WHY approval is needed


def test_intrusive_scan_approval_names_tool_and_target(db):
    s, run_id = db
    _action(s, run_id, "d2", "nuclei_intrusive", "172.25.188.23", {"severity": "high,critical"})
    out = _enrich(s, _approval(s, run_id, "d2", pclass="p2_intrusive"))
    assert out.tool_id == "nuclei_intrusive"
    assert "172.25.188.23" in out.target
    assert "intrusive" in out.reason.lower()


def test_enrich_is_safe_when_no_action_record(db):
    s, run_id = db
    out = _enrich(s, _approval(s, run_id, "missing"))
    assert out.tool_id is None and out.summary is None   # degrades, never raises
