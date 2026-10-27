"""Windows vuln checks: the safe ms17-010 detection (P1, auto), the aggressive crash-risky
checks (P2, human-gated), the VULNERABLE normalizer, and OS-CPE CVE leads."""
from __future__ import annotations

from datetime import UTC, datetime

import pytest
import vapt_persistence.db as dbmod
from langgraph.checkpoint.memory import MemorySaver
from langgraph.types import Command
from vapt_agents import phases
from vapt_agents.normalize import normalize
from vapt_agents.runscope import RunScope
from vapt_domain.enums import PolicyClass, TestingMode
from vapt_domain.schemas import ToolResult
from vapt_harness import GovernedHarness
from vapt_orch.graph.engagement import build_engagement_graph
from vapt_persistence import Base, init_engine
from vapt_persistence.models import Engagement, Finding, FindingObservation, Project, Run
from vapt_tools import REGISTRY


# -- normalizer --------------------------------------------------------------
_VULN_XML = ('<script id="smb-vuln-ms17-010" output="&#xa;  VULNERABLE:&#xa;  Remote Code '
            'Execution&#xa;    State: VULNERABLE&#xa;    IDs:  CVE:CVE-2017-0143"/>')
_SAFE_XML = ('<script id="smb-vuln-ms17-010" output="&#xa;    State: NOT VULNERABLE"/>')


def test_win_vuln_vulnerable_is_critical_with_cve():
    obs = normalize("win_vuln_scan", [{"stdout": _VULN_XML}])
    assert obs and obs[0].severity == "critical"
    assert "EternalBlue" in obs[0].title and "CVE-2017-0143" in obs[0].title
    assert obs[0].detail["cve"] == "CVE-2017-0143"


def test_win_vuln_not_vulnerable_yields_nothing():
    assert normalize("win_vuln_scan", [{"stdout": _SAFE_XML}]) == []


# -- tool classes/argv -------------------------------------------------------
def test_win_vuln_tools_classes_and_scripts():
    safe = REGISTRY.get("win_vuln_scan")
    assert safe.policy_class == PolicyClass.P1_LOW_IMPACT
    assert "smb-vuln-ms17-010" in safe.build_argv({"target": "h", "ports": "445"})

    aggr = REGISTRY.get("win_vuln_aggressive")
    assert aggr.policy_class == PolicyClass.P2_INTRUSIVE          # gated
    argv = aggr.build_argv({"target": "h", "ports": "445,3389"})
    assert "smb-vuln-ms08-067" in " ".join(argv) and "rdp-vuln-ms12-020" in " ".join(argv)


# -- OS hint + OS-CPE findings ----------------------------------------------
@pytest.fixture()
def db(tmp_path):
    init_engine(f"sqlite:///{tmp_path}/wv.db")
    Base.metadata.create_all(dbmod.get_engine())
    s = dbmod.SessionLocal()
    p = Project(name="P"); s.add(p); s.flush()
    e = Engagement(project_id=p.id, name="L", testing_mode="black_box", target_type="network")
    s.add(e); s.flush()
    r = Run(engagement_id=e.id, thread_id="t", status="running"); s.add(r); s.flush()
    s.commit()
    yield s, r.id
    s.close()


def _host_script_finding(s, run_id, script, detail_text):
    f = Finding(run_id=run_id, title=script, status="candidate", severity="info")
    s.add(f); s.flush()
    s.add(FindingObservation(finding_id=f.id, source_tool="host_scripts",
                             detail={"script": script, "detail": detail_text}))
    s.flush()


def test_os_hint_from_rdp_build(db):
    s, run_id = db
    _host_script_finding(s, run_id, "rdp-ntlm-info", "Target_Name: LAB\nProduct_Version: 10.0.17763")
    s.commit()
    assert phases.os_hint_from_findings(s, run_id) == "Windows Server 2019"


def test_os_hint_from_smb_os_discovery(db):
    s, run_id = db
    _host_script_finding(s, run_id, "smb-os-discovery", "OS: Windows Server 2016 Standard 14393")
    s.commit()
    assert phases.os_hint_from_findings(s, run_id) == "Windows Server 2016"


def test_os_cpe_findings_persist(db):
    s, run_id = db
    _host_script_finding(s, run_id, "rdp-ntlm-info", "Product_Version: 10.0.17763")
    s.commit()
    matches = [{"cve_id": "CVE-2019-0708", "cvss": 9.8, "severity": "critical",
                "description": "BlueKeep RDP RCE"}]
    created = phases.os_cpe_findings(s, run_id, matcher=lambda os_name: matches)
    assert created == 1
    f = next(f for f in s.query(Finding).all() if "CVE-2019-0708" in f.title)
    assert "Windows Server 2019" in f.title
    assert phases.cve_ref_for(s, f.id) is not None        # flows through CVE confirmation


# -- gated aggressive scan in the graph --------------------------------------
class _Broker:
    def execute(self, tool_id, args):
        now = datetime.now(UTC)
        canned = {
            "nmap_service_scan": "445/tcp open microsoft-ds",
            "http_probe": "http://h [200] [IIS]",
            "win_vuln_aggressive": _VULN_XML_RAW,
        }
        return ToolResult(outcome="ok", exit_code=0, started_at=now, finished_at=now,
                          tool_version="stub", observations=[{"stdout": canned.get(tool_id, "")}])


_VULN_XML_RAW = ('<script id="smb-vuln-ms08-067" output="  State: VULNERABLE  IDs: '
                 'CVE:CVE-2008-4250"/>')


def test_aggressive_scan_is_gated_and_runs_on_approval(db):
    s, run_id = db
    scope = RunScope(run_id=run_id, testing_mode=TestingMode.BLACK_BOX, target="h",
                     domains=["h"], ip_cidrs=[],
                     allowed_action_classes=[PolicyClass.P0_PASSIVE, PolicyClass.P1_LOW_IMPACT,
                                             PolicyClass.P2_INTRUSIVE],   # intrusive authorized
                     signed_profile=True)
    g = build_engagement_graph(db=s, scope=scope, harness=GovernedHarness(REGISTRY, broker=_Broker()),
                               gateway=None, checkpointer=MemorySaver())
    cfg = {"configurable": {"thread_id": "t"}}
    out = g.invoke({"schema_version": 1, "run_id": run_id, "thread_id": "t", "scope_ref": "h"}, cfg)
    s.commit()
    # The P2 aggressive scan pauses for approval even on a signed profile.
    assert "__interrupt__" in out
    while "__interrupt__" in out:
        out = g.invoke(Command(resume={"decision": "approve"}), cfg)
        s.commit()
    assert out["phase"] == "report"
    titles = [f.title for f in s.query(Finding).all()]
    assert any("MS08-067" in t and "CVE-2008-4250" in t for t in titles)   # ran after approval
