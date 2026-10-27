"""A planned scan tool that ran but produced no usable result (binary missing ->
'unknown', or non-zero exit -> 'failed') must be recorded as a coverage gap, so a
report never silently claims full coverage when a tool could not actually run."""
from __future__ import annotations

from datetime import UTC, datetime

import pytest
import vapt_persistence.db as dbmod
from langgraph.checkpoint.memory import MemorySaver
from vapt_agents.runscope import RunScope
from vapt_domain.enums import PolicyClass, TestingMode
from vapt_domain.schemas import ToolResult
from vapt_harness import GovernedHarness
from vapt_orch.graph.engagement import build_engagement_graph
from vapt_persistence import Base, init_engine
from vapt_persistence.models import Engagement, Project, Run
from vapt_tools import REGISTRY


class PartlyMissingBroker:
    """http_probe/nmap succeed; nuclei_safe's binary is 'not installed' (unknown)."""

    def execute(self, tool_id: str, args: dict) -> ToolResult:
        now = datetime.now(UTC)
        if tool_id == "nuclei_safe":
            return ToolResult(outcome="unknown", exit_code=None, started_at=now, finished_at=now,
                              tool_version="stub",
                              observations=[{"note": "binary 'nuclei' not installed"}])
        canned = {
            "dns_resolve": "example.com [93.184.216.34]",
            "nmap_service_scan": "80/tcp open http",
            "http_probe": "http://example.com [200] [IIS]",
        }
        return ToolResult(outcome="ok", exit_code=0, started_at=now, finished_at=now,
                          tool_version="stub", observations=[{"stdout": canned.get(tool_id, "")}])


@pytest.fixture()
def db(tmp_path):
    init_engine(f"sqlite:///{tmp_path}/cov.db")
    Base.metadata.create_all(dbmod.get_engine())
    s = dbmod.SessionLocal()
    p = Project(name="P"); s.add(p); s.flush()
    e = Engagement(project_id=p.id, name="Lab", testing_mode="black_box", target_type="network")
    s.add(e); s.flush()
    r = Run(engagement_id=e.id, thread_id="t-cov", status="running"); s.add(r); s.flush()
    s.commit()
    yield s, r.id
    s.close()


def test_unavailable_tool_recorded_as_coverage_gap(db):
    s, run_id = db
    scope = RunScope(
        run_id=run_id, testing_mode=TestingMode.BLACK_BOX, target="example.com",
        domains=["example.com"], ip_cidrs=[],
        allowed_action_classes=[PolicyClass.P0_PASSIVE, PolicyClass.P1_LOW_IMPACT],
        signed_profile=True,                       # P1 auto-allows, so no approval pauses
    )
    graph = build_engagement_graph(db=s, scope=scope, harness=GovernedHarness(REGISTRY, broker=PartlyMissingBroker()),
                                   gateway=None, checkpointer=MemorySaver())
    cfg = {"configurable": {"thread_id": "t-cov"}}
    out = graph.invoke({"schema_version": 1, "run_id": run_id, "thread_id": "t-cov",
                        "scope_ref": "example.com"}, cfg)
    s.commit()
    assert out["phase"] == "report"
    gaps = out.get("coverage_gaps", [])
    assert any("nuclei_safe" in g and "not installed" in g for g in gaps), gaps
