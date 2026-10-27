"""Guards against two real bugs seen in a live run: ANSI escape codes leaking into
finding titles, and a FAILED tool run (wrong/missing binary) producing fake findings.
Also checks the reporting brief is grounded in actual findings."""
from __future__ import annotations

from datetime import UTC, datetime

import pytest

from vapt_domain.enums import PolicyClass, TestingMode
from vapt_domain.schemas import ToolResult
from vapt_harness import GovernedHarness
from vapt_persistence import Base, init_engine
import vapt_persistence.db as dbmod
from vapt_persistence.models import Engagement, Finding, Project, Run
from vapt_tools import REGISTRY
from vapt_agents import phases
from vapt_agents.normalize import normalize
from vapt_agents.report import findings_brief
from vapt_agents.runscope import RunScope


def test_ansi_codes_stripped_from_titles():
    raw = "http://h [\x1b[32m200\x1b[0m] [\x1b[36mIIS\x1b[0m]"
    obs = normalize("http_probe", [{"stdout": raw}])
    assert "\x1b" not in obs[0].title
    assert obs[0].title == "HTTP service: http://h [200] [IIS]"


class _Broker:
    def __init__(self, outcome: str):
        self._outcome = outcome

    def execute(self, tool_id: str, args: dict) -> ToolResult:
        now = datetime.now(UTC)
        # stdout looks like an error, as a shadowed/wrong binary would emit.
        return ToolResult(outcome=self._outcome, exit_code=1, started_at=now, finished_at=now,
                          tool_version="stub", observations=[{"stdout": "could not run: missing deps"}])


@pytest.fixture()
def db(tmp_path):
    init_engine(f"sqlite:///{tmp_path}/n.db")
    Base.metadata.create_all(dbmod.get_engine())
    s = dbmod.SessionLocal()
    p = Project(name="P"); s.add(p); s.flush()
    e = Engagement(project_id=p.id, name="L", testing_mode="black_box", target_type="web")
    s.add(e); s.flush()
    r = Run(engagement_id=e.id, thread_id="t", status="running"); s.add(r); s.flush()
    s.commit()
    yield s, r.id
    s.close()


def _scope(run_id):
    return RunScope(run_id=run_id, testing_mode=TestingMode.BLACK_BOX, target="example.com",
                    domains=["example.com"], ip_cidrs=[],
                    allowed_action_classes=[PolicyClass.P0_PASSIVE, PolicyClass.P1_LOW_IMPACT],
                    signed_profile=True)


def test_failed_tool_run_yields_no_findings(db):
    s, run_id = db
    harness = GovernedHarness(REGISTRY, broker=_Broker("failed"))
    step = phases.scan_action(s, _scope(run_id), harness, tool_id="http_probe", args={}, task_id="scan-0")
    assert step.outcome.executed            # the harness dispatched it...
    assert step.candidate_ids == []         # ...but a failed run produces NO findings
    assert s.query(Finding).count() == 0


def test_findings_brief_is_grounded(db):
    s, run_id = db
    s.add(Finding(run_id=run_id, title="Open port 22 (ssh)", status="confirmed", severity="info"))
    s.add(Finding(run_id=run_id, title="noise", status="inconclusive", severity="info"))
    s.commit()
    brief = findings_brief(s, run_id)
    assert "Open port 22 (ssh)" in brief
    assert "noise" not in brief             # inconclusive findings aren't asserted as fact
