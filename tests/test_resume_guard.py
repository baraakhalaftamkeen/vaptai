"""Regression for the uq_run_event_seq crash: a stale/duplicate run.resume (an approval
decided after the run already finished, or two resumes racing) must be a no-op — it must
not re-invoke the finished graph and write a second run.completed. The guard is 'only
resume when the graph is actually paused at an interrupt', which these tests pin down."""
from __future__ import annotations

from datetime import UTC, datetime

import pytest
import vapt_persistence.db as dbmod
from langgraph.checkpoint.memory import MemorySaver
from langgraph.types import Command
from vapt_agents.runscope import RunScope
from vapt_domain.enums import PolicyClass, TestingMode
from vapt_domain.schemas import ToolResult
from vapt_harness import GovernedHarness
from vapt_orch.graph.engagement import build_engagement_graph
from vapt_persistence import Base, init_engine
from vapt_persistence.models import Engagement, Project, Run
from vapt_tools import REGISTRY


class _Stub:
    def execute(self, tool_id, args):
        now = datetime.now(UTC)
        canned = {"nmap_service_scan": "80/tcp open http", "http_probe": "http://h [200] [x]"}
        return ToolResult(outcome="ok", exit_code=0, started_at=now, finished_at=now,
                          tool_version="stub", observations=[{"stdout": canned.get(tool_id, "")}])


@pytest.fixture()
def db(tmp_path):
    init_engine(f"sqlite:///{tmp_path}/rg.db")
    Base.metadata.create_all(dbmod.get_engine())
    s = dbmod.SessionLocal()
    p = Project(name="P"); s.add(p); s.flush()
    e = Engagement(project_id=p.id, name="L", testing_mode="black_box", target_type="network")
    s.add(e); s.flush()
    r = Run(engagement_id=e.id, thread_id="t-rg", status="running"); s.add(r); s.flush()
    s.commit()
    yield s, r.id
    s.close()


def _graph(s, run_id, cp):
    scope = RunScope(run_id=run_id, testing_mode=TestingMode.BLACK_BOX, target="h",
                     domains=["h"], ip_cidrs=[],
                     allowed_action_classes=[PolicyClass.P0_PASSIVE, PolicyClass.P1_LOW_IMPACT],
                     signed_profile=True)
    return build_engagement_graph(db=s, scope=scope, harness=GovernedHarness(REGISTRY, broker=_Stub()),
                                  gateway=None, checkpointer=cp)


def test_completed_graph_has_no_pending_interrupt(db):
    s, run_id = db
    cp = MemorySaver()
    g = _graph(s, run_id, cp)
    cfg = {"configurable": {"thread_id": "t-rg"}}
    out = g.invoke({"schema_version": 1, "run_id": run_id, "thread_id": "t-rg", "scope_ref": "h"}, cfg)
    s.commit()
    assert out["phase"] == "report"
    # The guard resume_run relies on: a finished graph exposes no `next`, so a stale resume
    # is detected and skipped.
    assert not g.get_state(cfg).next


def test_paused_graph_has_pending_interrupt(db):
    s, run_id = db
    cp = MemorySaver()
    scope = RunScope(run_id=run_id, testing_mode=TestingMode.BLACK_BOX, target="h",
                     domains=["h"], ip_cidrs=[],
                     allowed_action_classes=[PolicyClass.P0_PASSIVE, PolicyClass.P1_LOW_IMPACT],
                     signed_profile=False)   # unsigned -> P1 scan needs approval -> pauses
    g = build_engagement_graph(db=s, scope=scope, harness=GovernedHarness(REGISTRY, broker=_Stub()),
                               gateway=None, checkpointer=cp)
    cfg = {"configurable": {"thread_id": "t-rg"}}
    out = g.invoke({"schema_version": 1, "run_id": run_id, "thread_id": "t-rg", "scope_ref": "h"}, cfg)
    s.commit()
    assert "__interrupt__" in out
    assert g.get_state(cfg).next            # a paused graph DOES have pending work
