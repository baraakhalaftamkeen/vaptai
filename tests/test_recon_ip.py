"""Recon skips DNS resolution for a bare-IP target (dnsx can't resolve an IP and only
fails), but still runs it for a hostname target."""
from __future__ import annotations

from datetime import UTC, datetime

import pytest
import vapt_persistence.db as dbmod
from vapt_agents import phases
from vapt_agents.runscope import RunScope
from vapt_domain.enums import PolicyClass, TestingMode
from vapt_domain.schemas import ToolResult
from vapt_harness import GovernedHarness
from vapt_persistence import Base, init_engine
from vapt_persistence.models import Engagement, Project, Run, RunEvent
from vapt_tools import REGISTRY


class RecordingBroker:
    def __init__(self):
        self.calls: list[str] = []

    def execute(self, tool_id: str, args: dict) -> ToolResult:
        self.calls.append(tool_id)
        now = datetime.now(UTC)
        return ToolResult(outcome="ok", exit_code=0, started_at=now, finished_at=now,
                          tool_version="stub", observations=[{"stdout": "ok"}])


@pytest.fixture()
def db(tmp_path):
    init_engine(f"sqlite:///{tmp_path}/recon.db")
    Base.metadata.create_all(dbmod.get_engine())
    s = dbmod.SessionLocal()
    p = Project(name="P"); s.add(p); s.flush()
    e = Engagement(project_id=p.id, name="L", testing_mode="black_box", target_type="network")
    s.add(e); s.flush()
    r = Run(engagement_id=e.id, thread_id="t", status="running"); s.add(r); s.flush()
    s.commit()
    yield s, r.id
    s.close()


def _scope(run_id, target, cidrs):
    return RunScope(run_id=run_id, testing_mode=TestingMode.BLACK_BOX, target=target,
                    domains=[] if cidrs else [target], ip_cidrs=cidrs,
                    allowed_action_classes=[PolicyClass.P0_PASSIVE, PolicyClass.P1_LOW_IMPACT])


def test_recon_skips_dns_for_ip_target(db):
    s, run_id = db
    broker = RecordingBroker()
    assets = phases.recon_phase(s, _scope(run_id, "172.25.188.23", ["172.25.188.23/32"]),
                                GovernedHarness(REGISTRY, broker=broker))
    s.commit()
    assert assets == ["172.25.188.23"]
    assert "dns_resolve" not in broker.calls            # skipped for an IP
    notes = [e for e in s.query(RunEvent).all() if e.kind == "recon.note"]
    assert notes and "dns" in str(notes[0].payload).lower()


def test_recon_runs_dns_for_hostname_target(db):
    s, run_id = db
    broker = RecordingBroker()
    phases.recon_phase(s, _scope(run_id, "example.com", []),
                       GovernedHarness(REGISTRY, broker=broker))
    s.commit()
    assert "dns_resolve" in broker.calls                # hostname: resolution is meaningful
