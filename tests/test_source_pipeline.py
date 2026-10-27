"""White-box source graph end to end: static analyzers run through the harness against
the uploaded bundle (local tools, in scope by workspace with NO domains), produce
candidate findings, and evidence-anchored validation confirms only those whose source
location actually exists. A stub broker supplies canned analyzer JSON."""
from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
import vapt_persistence.db as dbmod
from langgraph.checkpoint.memory import MemorySaver
from vapt_agents.runscope import RunScope
from vapt_domain.enums import PolicyClass, TestingMode
from vapt_domain.schemas import ToolResult
from vapt_harness import GovernedHarness
from vapt_orch.graph.source import build_source_graph
from vapt_persistence import Base, init_engine
from vapt_persistence.models import Engagement, Finding, Project, Run, ToolActionRecord
from vapt_tools import REGISTRY


def _semgrep_json(path: str) -> str:
    return json.dumps({"results": [
        {"check_id": "py.sqli", "path": path, "start": {"line": 12},
         "extra": {"severity": "ERROR", "message": "possible SQL injection"}},
    ]})


_GITLEAKS_JSON = json.dumps([
    {"RuleID": "aws-key", "File": "missing_secrets.py", "StartLine": 3,
     "Description": "AWS key", "Secret": "AKIAEXAMPLE"},
])
_DEP_JSON = json.dumps({"vulnerabilities": [
    {"package": "flask", "version": "0.5", "id": "CVE-2000-0001", "severity": "high"},
]})


class StubBroker:
    def __init__(self, semgrep_path: str):
        self._semgrep_path = semgrep_path

    def execute(self, tool_id: str, args: dict) -> ToolResult:
        canned = {
            "semgrep_scan": _semgrep_json(self._semgrep_path),
            "gitleaks_scan": _GITLEAKS_JSON,
            "dep_audit": _DEP_JSON,
        }
        now = datetime.now(UTC)
        return ToolResult(outcome="ok", exit_code=0, started_at=now, finished_at=now,
                          tool_version="stub", observations=[{"stdout": canned.get(tool_id, "")}])


@pytest.fixture()
def bundle(tmp_path):
    # A real extracted bundle: app/db.py exists; the gitleaks finding points at a file
    # that does NOT exist, so it must stay inconclusive.
    root = tmp_path / "extracted"
    (root / "app").mkdir(parents=True)
    (root / "app" / "db.py").write_text("import sqlite3\n")
    return str(root)


@pytest.fixture()
def db(tmp_path):
    init_engine(f"sqlite:///{tmp_path}/src.db")
    Base.metadata.create_all(dbmod.get_engine())
    s = dbmod.SessionLocal()
    p = Project(name="P"); s.add(p); s.flush()
    e = Engagement(project_id=p.id, name="WB", testing_mode="white_box", target_type="source")
    s.add(e); s.flush()
    r = Run(engagement_id=e.id, thread_id="t-src", status="running"); s.add(r); s.flush()
    s.commit()
    yield s, r.id
    s.close()


def _scope(run_id, bundle_path):
    return RunScope(
        run_id=run_id, testing_mode=TestingMode.WHITE_BOX, target=bundle_path,
        domains=[], ip_cidrs=[],   # source scope has NO network domains
        allowed_action_classes=[PolicyClass.P0_PASSIVE, PolicyClass.P1_LOW_IMPACT],
        signed_profile=True,
    )


def test_source_graph_analyzes_and_confirms_by_evidence(db, bundle):
    s, run_id = db
    harness = GovernedHarness(REGISTRY, broker=StubBroker(semgrep_path="app/db.py"))
    graph = build_source_graph(
        db=s, scope=_scope(run_id, bundle), harness=harness, bundle_path=bundle,
        gateway=None, checkpointer=MemorySaver(),
    )
    out = graph.invoke(
        {"schema_version": 1, "run_id": run_id, "thread_id": "t-src", "scope_ref": bundle},
        {"configurable": {"thread_id": "t-src"}},
    )
    s.commit()

    assert "__interrupt__" not in out        # P0/P1 local + signed profile: no pause
    assert out["phase"] == "report"

    findings = s.query(Finding).all()
    by_tool = {o.source_tool: f for f in findings for o in f.observations}
    assert "semgrep" in by_tool and "gitleaks" in by_tool and "dep_audit" in by_tool

    # semgrep points at app/db.py which exists -> confirmed.
    semgrep_f = by_tool["semgrep"]
    assert semgrep_f.status == "confirmed"
    # gitleaks points at a missing file -> inconclusive.
    assert by_tool["gitleaks"].status == "inconclusive"
    # dep_audit is advisory-anchored -> confirmed without a source line.
    assert by_tool["dep_audit"].status == "confirmed"

    # Local analyzers executed even though scope has NO domains (in-scope by workspace).
    assert s.query(ToolActionRecord).filter_by(tool_id="semgrep_scan", state="executed").count() == 1


def test_source_run_with_no_bundle_finishes_cleanly(db):
    s, run_id = db
    harness = GovernedHarness(REGISTRY, broker=StubBroker(semgrep_path="x"))
    graph = build_source_graph(
        db=s, scope=_scope(run_id, "source://none"), harness=harness, bundle_path=None,
        gateway=None, checkpointer=MemorySaver(),
    )
    out = graph.invoke(
        {"schema_version": 1, "run_id": run_id, "thread_id": "t-src", "scope_ref": "source://none"},
        {"configurable": {"thread_id": "t-src"}},
    )
    s.commit()
    assert out["phase"] == "report"
    assert s.query(Finding).count() == 0
    assert any("no bundle" in g for g in out.get("coverage_gaps", []))
