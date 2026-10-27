"""The report must not claim 'no coverage gaps' when tools actually failed or were
unavailable. gather() derives gaps from the ledger, including tools that ran but
returned failed/unknown — named, and deduped per (tool, outcome)."""
from __future__ import annotations

import pytest
import vapt_persistence.db as dbmod
from vapt_agents.report import gather
from vapt_persistence import Base, init_engine
from vapt_persistence.models import Engagement, Project, Run, RunEvent


@pytest.fixture()
def db(tmp_path):
    init_engine(f"sqlite:///{tmp_path}/r.db")
    Base.metadata.create_all(dbmod.get_engine())
    s = dbmod.SessionLocal()
    p = Project(name="P"); s.add(p); s.flush()
    e = Engagement(project_id=p.id, name="L", testing_mode="black_box", target_type="network")
    s.add(e); s.flush()
    r = Run(engagement_id=e.id, thread_id="t", status="completed"); s.add(r); s.flush()
    s.commit()
    yield s, r.id
    s.close()


def _ev(s, run_id, seq, kind, payload):
    s.add(RunEvent(run_id=run_id, seq=seq, kind=kind, payload=payload))


def test_failed_and_unknown_tools_become_named_gaps(db):
    s, run_id = db
    # tls_check ran and failed; burp_request was unavailable (ran twice -> one gap).
    _ev(s, run_id, 1, "action.proposed", {"digest": "d1", "tool": "tls_check", "target": "x"})
    _ev(s, run_id, 2, "action.executed", {"digest": "d1", "outcome": "failed", "exit_code": 246})
    _ev(s, run_id, 3, "action.proposed", {"digest": "d2", "tool": "burp_request", "target": "x"})
    _ev(s, run_id, 4, "action.executed", {"digest": "d2", "outcome": "unknown", "exit_code": None})
    _ev(s, run_id, 5, "action.proposed", {"digest": "d2", "tool": "burp_request", "target": "x"})
    _ev(s, run_id, 6, "action.executed", {"digest": "d2", "outcome": "unknown", "exit_code": None})
    s.commit()

    gaps = gather(s, run_id).coverage_gaps
    assert any("tls_check" in g and "246" in g for g in gaps), gaps
    assert any("burp_request" in g and "unavailable" in g for g in gaps), gaps
    assert sum("burp_request" in g for g in gaps) == 1          # deduped


def test_successful_tools_produce_no_gap(db):
    s, run_id = db
    _ev(s, run_id, 1, "action.proposed", {"digest": "d1", "tool": "nmap_service_scan", "target": "x"})
    _ev(s, run_id, 2, "action.executed", {"digest": "d1", "outcome": "ok", "exit_code": 0})
    s.commit()
    assert gather(s, run_id).coverage_gaps == []


def test_denied_action_still_reported(db):
    s, run_id = db
    _ev(s, run_id, 1, "action.denied", {"digest": "d1", "reason": "target not in approved scope"})
    s.commit()
    gaps = gather(s, run_id).coverage_gaps
    assert any("not in approved scope" in g for g in gaps)
