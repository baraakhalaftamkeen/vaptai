"""The attack agent: opt-in and always human-gated. Disabled by default (pass-through);
when enabled, every PoC on a confirmed finding is forced through approval regardless of
policy class, and executes only after approve. Also checks the reporting node finalizes."""
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
from vapt_persistence.models import Engagement, Finding, Project, Run, RunEvent, ToolActionRecord
from vapt_tools import REGISTRY


class StubBroker:
    def execute(self, tool_id: str, args: dict) -> ToolResult:
        canned = {
            "dns_resolve": "example.com [93.184.216.34]",
            "nmap_service_scan": "22/tcp open ssh",
            "http_probe": "https://example.com [200] [Example Domain]",
            "nuclei_safe": "",
            "burp_request": "HTTP/1.1 200 OK",
        }
        now = datetime.now(UTC)
        return ToolResult(outcome="ok", exit_code=0, started_at=now, finished_at=now,
                          tool_version="stub", observations=[{"stdout": canned.get(tool_id, "")}])


@pytest.fixture()
def db(tmp_path):
    init_engine(f"sqlite:///{tmp_path}/a.db")
    Base.metadata.create_all(dbmod.get_engine())
    s = dbmod.SessionLocal()
    p = Project(name="P"); s.add(p); s.flush()
    e = Engagement(project_id=p.id, name="Lab", testing_mode="black_box", target_type="web")
    s.add(e); s.flush()
    r = Run(engagement_id=e.id, thread_id="t-atk", status="running"); s.add(r); s.flush()
    s.commit()
    yield s, r.id
    s.close()


def _scope(run_id, *, exploit):
    return RunScope(
        run_id=run_id, testing_mode=TestingMode.BLACK_BOX, target="example.com",
        domains=["example.com"], ip_cidrs=[],
        allowed_action_classes=[PolicyClass.P0_PASSIVE, PolicyClass.P1_LOW_IMPACT],
        signed_profile=True, allow_exploitation=exploit,
    )


def _run(s, run_id, exploit):
    harness = GovernedHarness(REGISTRY, broker=StubBroker())
    graph = build_engagement_graph(
        db=s, scope=_scope(run_id, exploit=exploit), harness=harness,
        gateway=None, checkpointer=MemorySaver(),
    )
    cfg = {"configurable": {"thread_id": "t-atk"}}
    out = graph.invoke(
        {"schema_version": 1, "run_id": run_id, "thread_id": "t-atk", "scope_ref": "example.com"}, cfg)
    s.commit()
    return graph, cfg, out


def test_attack_disabled_is_pass_through(db):
    s, run_id = db
    _, _, out = _run(s, run_id, exploit=False)
    assert "__interrupt__" not in out            # no PoC gating when exploitation is off
    assert out["phase"] == "report"
    # A report was generated and its id surfaced as report_ref.
    from vapt_persistence.models import Report
    assert out.get("report_ref")
    assert s.query(Report).filter_by(run_id=run_id).count() == 1
    # No burp_request action was ever proposed.
    assert s.query(ToolActionRecord).filter_by(tool_id="burp_request").count() == 0
    # Reporting + remediation nodes ran.
    kinds = {e.kind for e in s.query(RunEvent).all()}
    assert "remediation.drafted" in kinds and "report.generated" in kinds


def test_attack_enabled_forces_approval_per_applicable_finding(db):
    s, run_id = db
    graph, cfg, out = _run(s, run_id, exploit=True)

    confirmed = [f for f in s.query(Finding).all() if f.status == "confirmed"]
    assert confirmed, "signed-profile run should confirm findings"
    # http_evidence applies only to HTTP-service findings (per-finding playbook selection),
    # NOT to every confirmed finding (the nmap port / CVE ones are skipped).
    from vapt_persistence.models import FindingObservation
    http_targets = {
        o.finding_id for o in s.query(FindingObservation).filter_by(source_tool="http_probe")
        if s.get(Finding, o.finding_id).status == "confirmed"
    }
    assert http_targets and len(http_targets) < len(confirmed)

    # The graph pauses once per APPLICABLE finding, not per confirmed finding.
    assert "__interrupt__" in out
    pauses = 0
    while "__interrupt__" in out:
        pauses += 1
        assert pauses <= len(http_targets) + 2
        out = graph.invoke(Command(resume={"decision": "approve"}), cfg)
        s.commit()

    assert pauses == len(http_targets)
    assert out["phase"] == "report"
    executed = s.query(ToolActionRecord).filter_by(tool_id="burp_request", state="executed").count()
    assert executed == len(http_targets)


def test_attack_reject_blocks_poc(db):
    s, run_id = db
    graph, cfg, out = _run(s, run_id, exploit=True)
    assert "__interrupt__" in out
    while "__interrupt__" in out:
        out = graph.invoke(Command(resume={"decision": "reject"}), cfg)
        s.commit()
    assert out["phase"] == "report"
    # No PoC executed; gaps recorded.
    assert s.query(ToolActionRecord).filter_by(tool_id="burp_request", state="executed").count() == 0
    assert any("PoC reject" in g for g in out.get("coverage_gaps", []))
