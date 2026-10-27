"""Week 3 exit gate: a black/gray-box web case runs end to end and produces
evidence-linked findings. Candidates come from scan output; validation confirms them.
A stub broker supplies deterministic tool output (no real scanners needed in CI).
"""
from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy import select

from vapt_domain.enums import PolicyClass, TestingMode
from vapt_domain.schemas import ToolResult
from vapt_harness import GovernedHarness
from vapt_persistence import Base, init_engine
import vapt_persistence.db as dbmod
from vapt_persistence.models import Engagement, Finding, FindingObservation, Project, Run
from vapt_tools import REGISTRY
from vapt_agents import run_web_network_pipeline
from vapt_agents.web_network import RunScope


class StubBroker:
    """Returns canned stdout per tool so normalize() yields findings deterministically."""

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
    init_engine(f"sqlite:///{tmp_path}/p.db")
    Base.metadata.create_all(dbmod.get_engine())
    s = dbmod.SessionLocal()
    p = Project(name="P")
    s.add(p)
    s.flush()
    e = Engagement(project_id=p.id, name="Lab", testing_mode="black_box", target_type="web")
    s.add(e)
    s.flush()
    r = Run(engagement_id=e.id, thread_id="t1", status="running")
    s.add(r)
    s.flush()
    s.commit()
    yield s, r.id
    s.close()


def _scope(run_id):
    return RunScope(
        run_id=run_id,
        testing_mode=TestingMode.BLACK_BOX,
        target="example.com",
        domains=["example.com"],
        ip_cidrs=[],
        allowed_action_classes=[PolicyClass.P0_PASSIVE, PolicyClass.P1_LOW_IMPACT],
        signed_profile=True,
    )


def test_pipeline_produces_confirmed_findings_with_evidence(db):
    s, run_id = db
    harness = GovernedHarness(REGISTRY, broker=StubBroker())
    result = run_web_network_pipeline(s, _scope(run_id), harness)
    s.commit()

    assert result.asset_refs == ["example.com"]
    assert len(result.candidate_finding_ids) >= 1
    # Every confirmed finding exists, is CONFIRMED, and has >=1 linked observation.
    assert result.confirmed_finding_ids, "expected at least one confirmed finding"
    for fid in result.confirmed_finding_ids:
        f = s.get(Finding, fid)
        assert f.status == "confirmed"
        obs = s.execute(
            select(FindingObservation).where(FindingObservation.finding_id == fid)
        ).scalars().all()
        assert len(obs) >= 1
        assert obs[0].source_tool  # evidence is tagged with its source tool


def test_out_of_scope_target_denied_no_findings(db):
    s, run_id = db
    harness = GovernedHarness(REGISTRY, broker=StubBroker())
    scope = _scope(run_id)
    scope.target = "not-in-scope.com"  # not in domains
    result = run_web_network_pipeline(s, scope, harness)
    s.commit()
    # Nothing executes out of scope -> no candidate findings, coverage gaps recorded.
    assert result.candidate_finding_ids == []
    assert result.coverage_gaps
