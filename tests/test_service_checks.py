"""Service-specific checks (BAR-41 follow-ups): ZAP alert parsing, NSE host-script
parsing + tool, port-aware validation, and the vapt-burp PoC shim."""
from __future__ import annotations

from datetime import UTC, datetime

import pytest
import vapt_persistence.db as dbmod
from vapt_agents import phases
from vapt_agents.normalize import normalize
from vapt_agents.planner import plan_scan
from vapt_agents.runscope import RunScope
from vapt_domain.enums import AgentRole, PolicyClass, TestingMode
from vapt_domain.schemas import ToolResult
from vapt_harness import GovernedHarness
from vapt_persistence import Base, init_engine
from vapt_persistence.models import Engagement, Finding, FindingObservation, Project, Run
from vapt_tools import REGISTRY


# -- ZAP alert parsing -------------------------------------------------------
def test_zap_alerts_parsed_with_severity():
    out = ("WARN-NEW: CSP Header Not Set [10038] x 3\n"
           "FAIL-NEW: Cross Site Scripting (Reflected) [40012] x 1\n"
           "PASS: Something fine [10099]\n")
    obs = normalize("zap_baseline", [{"stdout": out}])
    by = {o.detail["plugin_id"]: o for o in obs}
    assert by["10038"].severity == "low" and "CSP Header Not Set" in by["10038"].title
    assert by["40012"].severity == "medium"
    assert "10099" not in by          # PASS lines aren't findings


# -- NSE host-script parsing -------------------------------------------------
def test_nse_smb_signing_not_required_is_medium():
    xml = ('<script id="smb2-security-mode" output="&#xa;  Message signing enabled '
           'but not required"/>')
    obs = normalize("host_scripts", [{"stdout": xml}])
    assert obs and obs[0].severity == "medium"
    assert "not required" in obs[0].title.lower() and obs[0].detail["port"] == "445"


def test_nse_rdp_and_nbstat_info():
    xml = ('<script id="rdp-ntlm-info" output="Target_Name: LAB"/>'
           '<script id="nbstat" output="NetBIOS name: WIN-X"/>')
    obs = {o.detail["script"]: o for o in normalize("host_scripts", [{"stdout": xml}])}
    assert obs["rdp-ntlm-info"].detail["port"] == "3389"
    assert obs["nbstat"].detail["port"] == "139"


def test_host_scripts_tool_is_bounded_and_safe():
    argv = REGISTRY.get("host_scripts").build_argv({"target": "10.0.0.1", "ports": "445,3389"})
    assert "--script" in argv and "-sT" in argv          # connect scan, not privileged
    scripts = argv[argv.index("--script") + 1]
    assert "exploit" not in scripts and "brute" not in scripts   # safe discovery only


# -- PoC tools are ATTACK-only and must never be planned as a scan step ------
def test_burp_request_is_attack_agent_only():
    spec = REGISTRY.get("burp_request")
    assert spec.allowed_agents == [AgentRole.ATTACK]       # not SCAN/VALIDATE
    scrn = REGISTRY.get("poc_screenshot")
    assert scrn.allowed_agents == [AgentRole.ATTACK]


class _PlanGateway:
    def __init__(self, parsed):
        self._parsed = parsed

    def invoke(self, profile_id, messages, output_schema=None, data_class="standard", context=None):
        from vapt_llm import GatewayResponse
        return GatewayResponse(text="", parsed=self._parsed, profile_id="planning",
                               provider="openai", model_id="m", finish_reason="stop",
                               usage={"total_tokens": 1}, latency_ms=1, trace_id="t", error=None)


def test_planner_drops_poc_tools_even_if_model_proposes_them():
    scope = RunScope(run_id="r1", testing_mode=TestingMode.BLACK_BOX, target="h",
                     domains=["h"], ip_cidrs=[],
                     allowed_action_classes=[PolicyClass.P0_PASSIVE, PolicyClass.P1_LOW_IMPACT])
    gw = _PlanGateway({"steps": [{"tool_id": "nmap_service_scan"}, {"tool_id": "burp_request"},
                                 {"tool_id": "poc_screenshot"}, {"tool_id": "http_probe"}]})
    res = plan_scan(gw, scope)
    kept = [a.tool_id for a in res.actions]
    assert "burp_request" not in kept and "poc_screenshot" not in kept
    assert "nmap_service_scan" in kept and "http_probe" in kept


# -- Burp shim argv ----------------------------------------------------------
def test_burp_argv_honors_override_and_port(monkeypatch):
    monkeypatch.setenv("VAPT_BURP_BIN", "/opt/vapt-burp")
    argv = REGISTRY.get("burp_request").build_argv({"target": "h", "port": "8443"})
    assert argv[0] == "/opt/vapt-burp"
    assert argv[-1] == "https://h:8443"


# -- port-aware validation + service-port selection --------------------------
@pytest.fixture()
def db(tmp_path):
    init_engine(f"sqlite:///{tmp_path}/sc.db")
    Base.metadata.create_all(dbmod.get_engine())
    s = dbmod.SessionLocal()
    p = Project(name="P"); s.add(p); s.flush()
    e = Engagement(project_id=p.id, name="L", testing_mode="black_box", target_type="network")
    s.add(e); s.flush()
    r = Run(engagement_id=e.id, thread_id="t", status="running"); s.add(r); s.flush()
    s.commit()
    yield s, r.id
    s.close()


def _nmap_finding(s, run_id, port, service):
    f = Finding(run_id=run_id, title=f"Open port {port}", status="candidate", severity="info")
    s.add(f); s.flush()
    s.add(FindingObservation(finding_id=f.id, source_tool="nmap_service_scan",
                             detail={"port": port, "service": service}))
    s.flush()
    return f.id


def test_service_ports_selects_windows_ports(db):
    s, run_id = db
    for port, svc in [("80", "http"), ("445", "microsoft-ds"), ("3389", "ms-wbt-server"),
                      ("139", "netbios-ssn"), ("5985", "wsman")]:
        _nmap_finding(s, run_id, port, svc)
    s.commit()
    assert set(phases.service_ports_from_findings(s, run_id)) == {"445", "3389", "139"}


class _PortCapturingBroker:
    def __init__(self):
        self.last_args = None

    def execute(self, tool_id, args):
        self.last_args = dict(args)
        now = datetime.now(UTC)
        return ToolResult(outcome="ok", exit_code=0, started_at=now, finished_at=now,
                          tool_version="stub", observations=[{"stdout": "http://h:3389 [200] [x]"}])


def test_poc_targets_only_http_findings(db):
    s, run_id = db
    # one HTTP-service finding + two non-web (nmap port) findings, all confirmed
    h = Finding(run_id=run_id, title="HTTP service: http://x [200]", status="confirmed", severity="info")
    s.add(h); s.flush()
    s.add(FindingObservation(finding_id=h.id, source_tool="http_probe", detail={"line": "http://x [200]"}))
    for port in ("445", "3389"):
        f = Finding(run_id=run_id, title=f"Open port {port}", status="confirmed", severity="info")
        s.add(f); s.flush()
        s.add(FindingObservation(finding_id=f.id, source_tool="nmap_service_scan", detail={"port": port}))
    s.commit()
    assert phases.poc_targets_for(s, run_id, "http_evidence") == [h.id]      # only the web one
    assert len(phases.poc_targets_for(s, run_id, "some_generic_playbook")) == 3  # generic → all


def test_poc_args_target_the_real_http_service(db):
    s, run_id = db
    # An HTTP finding on a non-standard port -> PoC should hit that scheme+port…
    f = Finding(run_id=run_id, title="HTTP service: http://h:5985 [404]", status="confirmed", severity="info")
    s.add(f); s.flush()
    s.add(FindingObservation(finding_id=f.id, source_tool="http_probe",
                             detail={"line": "http://h:5985 [404] [Not Found]"}))
    s.commit()
    assert phases.poc_args_for(s, f.id) == {"scheme": "http", "port": "5985"}

    # …a non-HTTP finding falls back to the base plain-HTTP web surface (no https/443).
    g = _nmap_finding(s, run_id, "445", "microsoft-ds")
    s.commit()
    assert phases.poc_args_for(s, g) == {"scheme": "http"}


def test_validate_reprobes_the_findings_port(db):
    s, run_id = db
    fid = _nmap_finding(s, run_id, "3389", "ms-wbt-server")
    s.commit()
    broker = _PortCapturingBroker()
    scope = RunScope(run_id=run_id, testing_mode=TestingMode.BLACK_BOX, target="h",
                     domains=["h"], ip_cidrs=[],
                     allowed_action_classes=[PolicyClass.P0_PASSIVE, PolicyClass.P1_LOW_IMPACT],
                     signed_profile=True)
    phases.validate_candidate(s, scope, GovernedHarness(REGISTRY, broker=broker), fid)
    assert broker.last_args.get("port") == "3389"     # re-probed the finding's port
