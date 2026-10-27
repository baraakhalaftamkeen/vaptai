"""The real engagement graph: intake→plan→recon→scan→validate→report, with the scan
node pausing via interrupt() on an action that needs approval and resuming on approve.

A stub broker supplies deterministic tool output; gateway=None forces the deterministic
fallback plan (no live LLM needed in CI).
"""
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
from vapt_persistence.models import Engagement, Finding, Project, Run
from vapt_tools import REGISTRY


class StubBroker:
    def execute(self, tool_id: str, args: dict) -> ToolResult:
        canned = {
            "dns_resolve": "example.com [93.184.216.34]",
            "nmap_service_scan": "22/tcp open ssh\n443/tcp open https",
            "http_probe": "https://example.com [200] [Example Domain]",
            "nuclei_safe": "[tls-version] [ssl] [info] https://example.com",
        }
        now = datetime.now(UTC)
        return ToolResult(
            outcome="ok", exit_code=0, started_at=now, finished_at=now,
            tool_version="stub", observations=[{"stdout": canned.get(tool_id, "")}],
        )


@pytest.fixture()
def db(tmp_path):
    init_engine(f"sqlite:///{tmp_path}/g.db")
    Base.metadata.create_all(dbmod.get_engine())
    s = dbmod.SessionLocal()
    p = Project(name="P"); s.add(p); s.flush()
    e = Engagement(project_id=p.id, name="Lab", testing_mode="black_box", target_type="web")
    s.add(e); s.flush()
    r = Run(engagement_id=e.id, thread_id="t-graph", status="running"); s.add(r); s.flush()
    s.commit()
    yield s, r.id
    s.close()


def _scope(run_id, *, signed):
    return RunScope(
        run_id=run_id, testing_mode=TestingMode.BLACK_BOX, target="example.com",
        domains=["example.com"], ip_cidrs=[],
        allowed_action_classes=[PolicyClass.P0_PASSIVE, PolicyClass.P1_LOW_IMPACT],
        signed_profile=signed,
    )


def test_graph_runs_to_report_with_signed_profile(db):
    s, run_id = db
    harness = GovernedHarness(REGISTRY, broker=StubBroker())
    graph = build_engagement_graph(
        db=s, scope=_scope(run_id, signed=True), harness=harness,
        gateway=None, checkpointer=MemorySaver(),
    )
    cfg = {"configurable": {"thread_id": "t-graph"}}
    out = graph.invoke(
        {"schema_version": 1, "run_id": run_id, "thread_id": "t-graph", "scope_ref": "example.com"},
        cfg,
    )
    s.commit()
    assert "__interrupt__" not in out              # signed P1 auto-allows: no pause
    assert out["phase"] == "report"
    assert out["plan_source"] == "fallback"
    confirmed = [f for f in s.query(Finding).all() if f.status == "confirmed"]
    assert confirmed, "expected confirmed findings from the graph run"


def test_graph_pauses_for_approval_then_resumes(db):
    s, run_id = db
    harness = GovernedHarness(REGISTRY, broker=StubBroker())
    graph = build_engagement_graph(
        db=s, scope=_scope(run_id, signed=False), harness=harness,  # unsigned -> P1 needs approval
        gateway=None, checkpointer=MemorySaver(),
    )
    cfg = {"configurable": {"thread_id": "t-graph"}}
    out = graph.invoke(
        {"schema_version": 1, "run_id": run_id, "thread_id": "t-graph", "scope_ref": "example.com"},
        cfg,
    )
    s.commit()

    # First action pauses the graph.
    assert "__interrupt__" in out
    pauses = 0
    while "__interrupt__" in out:
        pauses += 1
        assert pauses <= 10, "too many pauses — resume loop not converging"
        out = graph.invoke(Command(resume={"decision": "approve"}), cfg)
        s.commit()

    assert out["phase"] == "report"
    assert pauses == 3                              # nmap, http_probe, nuclei_safe each gated
    # Approved scan actions yielded candidate findings...
    assert s.query(Finding).count() > 0, "approved scan actions should yield candidates"
    # ...but in an UNSIGNED run the validate re-probe is itself P1 and also needs
    # approval, so nothing auto-confirms: candidates stay inconclusive. That is the
    # governed model working, not a bug.
    assert not [f for f in s.query(Finding).all() if f.status == "confirmed"]
    assert all(f.status in ("candidate", "inconclusive") for f in s.query(Finding).all())


def test_graph_reject_records_gap_and_no_findings(db):
    s, run_id = db
    harness = GovernedHarness(REGISTRY, broker=StubBroker())
    graph = build_engagement_graph(
        db=s, scope=_scope(run_id, signed=False), harness=harness,
        gateway=None, checkpointer=MemorySaver(),
    )
    cfg = {"configurable": {"thread_id": "t-graph"}}
    out = graph.invoke(
        {"schema_version": 1, "run_id": run_id, "thread_id": "t-graph", "scope_ref": "example.com"},
        cfg,
    )
    s.commit()
    while "__interrupt__" in out:
        out = graph.invoke(Command(resume={"decision": "reject"}), cfg)
        s.commit()

    assert out["phase"] == "report"
    assert s.query(Finding).count() == 0           # nothing executed -> no candidates
    assert any("approval reject" in g for g in out.get("coverage_gaps", []))
