"""(a) the attack phase must not force approvals for a PoC whose binary is absent, and
(b) the graph follows up on non-standard web ports nmap discovered with an httpx probe."""
from __future__ import annotations

from datetime import UTC, datetime

import pytest
import vapt_persistence.db as dbmod
from langgraph.checkpoint.memory import MemorySaver
from vapt_agents import phases
from vapt_agents.runscope import RunScope
from vapt_domain.enums import PolicyClass, TestingMode
from vapt_domain.schemas import ToolResult
from vapt_harness import GovernedHarness
from vapt_orch.graph.engagement import build_engagement_graph
from vapt_tools import broker as bmod
from vapt_persistence import Base, init_engine
from vapt_persistence.models import Engagement, Finding, FindingObservation, Project, Run
from vapt_tools import REGISTRY


# -- (a) tool availability ---------------------------------------------------
def test_tool_available_reflects_binary_presence(monkeypatch):
    monkeypatch.setattr(bmod.shutil, "which", lambda b: "/usr/bin/nmap" if b == "nmap" else None)
    h = GovernedHarness(REGISTRY)   # default (real) broker -> checks the filesystem
    assert h.tool_available("nmap_service_scan", {"target": "x", "ports": "80"}) is True
    assert h.tool_available("burp_request", {"target": "x"}) is False   # vapt-burp absent


# -- httpx port argument -----------------------------------------------------
def test_httpx_targets_specific_port():
    argv = REGISTRY.get("http_probe").build_argv({"target": "1.2.3.4", "port": "8080"})
    assert argv[argv.index("-u") + 1] == "1.2.3.4:8080"


def test_httpx_rejects_bad_port():
    with pytest.raises(ValueError):
        REGISTRY.get("http_probe").build_argv({"target": "1.2.3.4", "port": "99999"})


# -- (b) web-port selection --------------------------------------------------
@pytest.fixture()
def db(tmp_path):
    init_engine(f"sqlite:///{tmp_path}/sp.db")
    Base.metadata.create_all(dbmod.get_engine())
    s = dbmod.SessionLocal()
    p = Project(name="P"); s.add(p); s.flush()
    e = Engagement(project_id=p.id, name="L", testing_mode="black_box", target_type="network")
    s.add(e); s.flush()
    r = Run(engagement_id=e.id, thread_id="t-sp", status="running"); s.add(r); s.flush()
    s.commit()
    yield s, r.id
    s.close()


def _nmap_finding(s, run_id, port, service):
    f = Finding(run_id=run_id, title=f"Open port {port} ({service})", status="candidate", severity="info")
    s.add(f); s.flush()
    s.add(FindingObservation(finding_id=f.id, source_tool="nmap_service_scan",
                             detail={"port": port, "service": service}))
    s.flush()


def test_web_ports_selects_nonstandard_http_only(db):
    s, run_id = db
    for port, svc in [("80", "http"), ("443", "https"), ("445", "microsoft-ds"),
                      ("3389", "ms-wbt-server"), ("8080", "http-proxy"), ("5985", "wsman")]:
        _nmap_finding(s, run_id, port, svc)
    s.commit()
    ports = {p for p, _ in phases.web_ports_from_findings(s, run_id)}
    assert ports == {"8080", "5985"}        # 80/443 excluded (base probe), SMB/RDP not web


def test_has_tls_port(db):
    s, run_id = db
    # No nmap findings yet → None (don't skip tls_check prematurely).
    assert phases.has_tls_port(s, run_id) is None
    # Plain-HTTP + SMB + RDP, no TLS → False (tls_check should be skipped).
    for port, svc in [("80", "http"), ("445", "microsoft-ds"), ("3389", "ms-wbt-server")]:
        _nmap_finding(s, run_id, port, svc)
    s.commit()
    assert phases.has_tls_port(s, run_id) is False
    # Add a 443/https service → True.
    _nmap_finding(s, run_id, "443", "https"); s.commit()
    assert phases.has_tls_port(s, run_id) is True


# -- (b) end-to-end: the graph probes a discovered 8080 ----------------------
class _ProbeBroker:
    def execute(self, tool_id, args):
        now = datetime.now(UTC)
        if tool_id == "nmap_service_scan":
            out = ('<port protocol="tcp" portid="8080"><state state="open"/>'
                   '<service name="http-proxy"/></port>')
        elif tool_id == "http_probe" and str(args.get("port")) == "8080":
            out = "http://h:8080 [200] [Jenkins]"
        elif tool_id == "http_probe":
            out = "http://h [200] [IIS]"
        else:
            out = ""
        return ToolResult(outcome="ok", exit_code=0, started_at=now, finished_at=now,
                          tool_version="stub", observations=[{"stdout": out}])


def test_graph_probes_discovered_web_port(db):
    s, run_id = db
    scope = RunScope(run_id=run_id, testing_mode=TestingMode.BLACK_BOX, target="example.com",
                     domains=["example.com"], ip_cidrs=[],
                     allowed_action_classes=[PolicyClass.P0_PASSIVE, PolicyClass.P1_LOW_IMPACT],
                     signed_profile=True)
    graph = build_engagement_graph(db=s, scope=scope,
                                   harness=GovernedHarness(REGISTRY, broker=_ProbeBroker()),
                                   gateway=None, checkpointer=MemorySaver())
    cfg = {"configurable": {"thread_id": "t-sp"}}
    out = graph.invoke({"schema_version": 1, "run_id": run_id, "thread_id": "t-sp",
                        "scope_ref": "example.com"}, cfg)
    s.commit()
    assert out["phase"] == "report"
    titles = [f.title for f in s.query(Finding).all()]
    assert any("8080" in t and "Jenkins" in t for t in titles), titles  # follow-up probe fired
