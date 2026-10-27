"""Approved-PoC playbook flow (BAR-30): playbook resolution, safe PoC argv, and the
attack node running the ENGAGEMENT'S chosen playbook — still forced through approval —
and linking PoC evidence to the confirmed finding. Plus the playbooks API."""
from __future__ import annotations

from datetime import UTC, datetime

import pytest
import vapt_persistence.db as dbmod
from langgraph.checkpoint.memory import MemorySaver
from langgraph.types import Command
from vapt_agents.playbooks import PLAYBOOKS, get_playbook
from vapt_agents.runscope import RunScope
from vapt_domain.enums import PolicyClass, TestingMode
from vapt_domain.schemas import ToolResult
from vapt_harness import GovernedHarness
from vapt_orch.graph.engagement import build_engagement_graph
from vapt_persistence import Base, init_engine
from vapt_persistence.models import (
    Engagement,
    Finding,
    FindingObservation,
    Project,
    Run,
    ToolActionRecord,
)
from vapt_tools import REGISTRY


def test_playbook_resolution_and_fallback():
    assert get_playbook("screenshot").tool_id == "poc_screenshot"
    assert get_playbook("http_evidence").tool_id == "burp_request"
    assert get_playbook(None).id == "http_evidence"
    assert get_playbook("does-not-exist").id == "http_evidence"   # safe fallback


def test_poc_screenshot_argv_is_safe():
    spec = REGISTRY.get("poc_screenshot")
    assert spec.policy_class == PolicyClass.P2_INTRUSIVE
    assert spec.build_argv({"target": "example.com"}) == [
        "vapt-poc-screenshot", "--url", "https://example.com"]
    with pytest.raises(ValueError):
        spec.build_argv({"target": "-rf"})           # option-like target rejected


class StubBroker:
    def execute(self, tool_id: str, args: dict) -> ToolResult:
        canned = {
            "dns_resolve": "example.com [93.184.216.34]",
            "nmap_service_scan": "22/tcp open ssh",
            "http_probe": "https://example.com [200] [Example Domain]",
            "poc_screenshot": '{"artifact": "screenshots/poc-1.png", "status": 200}',
        }
        now = datetime.now(UTC)
        return ToolResult(outcome="ok", exit_code=0, started_at=now, finished_at=now,
                          tool_version="stub", observations=[{"stdout": canned.get(tool_id, "")}])


@pytest.fixture()
def db(tmp_path):
    init_engine(f"sqlite:///{tmp_path}/pb.db")
    Base.metadata.create_all(dbmod.get_engine())
    s = dbmod.SessionLocal()
    p = Project(name="P"); s.add(p); s.flush()
    e = Engagement(project_id=p.id, name="Lab", testing_mode="black_box", target_type="web")
    s.add(e); s.flush()
    r = Run(engagement_id=e.id, thread_id="t-pb", status="running"); s.add(r); s.flush()
    s.commit()
    yield s, r.id
    s.close()


def _scope(run_id):
    return RunScope(
        run_id=run_id, testing_mode=TestingMode.BLACK_BOX, target="example.com",
        domains=["example.com"], ip_cidrs=[],
        allowed_action_classes=[PolicyClass.P0_PASSIVE, PolicyClass.P1_LOW_IMPACT],
        signed_profile=True, allow_exploitation=True, poc_playbook="screenshot",
    )


def test_attack_runs_selected_playbook_and_records_evidence(db):
    s, run_id = db
    harness = GovernedHarness(REGISTRY, broker=StubBroker())
    graph = build_engagement_graph(db=s, scope=_scope(run_id), harness=harness,
                                   gateway=None, checkpointer=MemorySaver())
    cfg = {"configurable": {"thread_id": "t-pb"}}
    out = graph.invoke(
        {"schema_version": 1, "run_id": run_id, "thread_id": "t-pb", "scope_ref": "example.com"}, cfg)
    s.commit()

    confirmed = [f for f in s.query(Finding).all() if f.status == "confirmed"]
    assert confirmed and "__interrupt__" in out       # PoC pauses for approval
    # screenshot (an HTTP playbook) targets only HTTP-service findings, not the nmap ports.
    http_targets = {
        o.finding_id for o in s.query(FindingObservation).filter_by(source_tool="http_probe")
        if s.get(Finding, o.finding_id).status == "confirmed"
    }
    assert http_targets and len(http_targets) < len(confirmed)

    while "__interrupt__" in out:
        out = graph.invoke(Command(resume={"decision": "approve"}), cfg)
        s.commit()

    assert out["phase"] == "report"
    # The SELECTED playbook's tool ran (poc_screenshot), not the default burp_request.
    assert s.query(ToolActionRecord).filter_by(tool_id="poc_screenshot", state="executed").count() == len(http_targets)
    assert s.query(ToolActionRecord).filter_by(tool_id="burp_request").count() == 0
    # PoC evidence is linked to each applicable finding, without leaking raw capture.
    poc_obs = s.query(FindingObservation).filter(FindingObservation.source_tool == "poc:screenshot").all()
    assert len(poc_obs) == len(http_targets)
    assert poc_obs[0].detail.get("tool") == "poc_screenshot"


# ----------------------------- API ---------------------------------------- #
@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("VAPT_DATABASE_URL", f"sqlite:///{tmp_path}/api.db")
    monkeypatch.setenv("VAPT_BOOTSTRAP_ADMIN_PASSWORD", "pw12345")
    from vapt_api.config import get_settings
    get_settings.cache_clear()
    from fastapi.testclient import TestClient
    from vapt_api.main import create_app
    with TestClient(create_app()) as c:
        c.post("/api/v2/auth/session", json={"username": "admin", "password": "pw12345"})
        yield c


def test_playbooks_api_lists_catalog(client):
    r = client.get("/api/v2/playbooks")
    assert r.status_code == 200
    ids = {p["id"] for p in r.json()}
    assert ids == set(PLAYBOOKS.keys())
