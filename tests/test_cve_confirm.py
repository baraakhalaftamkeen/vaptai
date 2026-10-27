"""CVE confirmation (ported from V1 validate_cve_on_target, governed): a version-matched
CVE is promoted to confirmed only if its nuclei template fires; else flagged
exploit_available when Exploit-DB has a public exploit; else inconclusive."""
from __future__ import annotations

from datetime import UTC, datetime

import pytest
import vapt_persistence.db as dbmod
from vapt_agents import phases
from vapt_agents.runscope import RunScope
from vapt_domain.enums import PolicyClass, TestingMode
from vapt_domain.schemas import ToolResult
from vapt_harness import GovernedHarness
from vapt_persistence import Base, init_engine
from vapt_persistence.models import Engagement, Finding, FindingObservation, Project, Run
from vapt_tools import REGISTRY


# -- argv builders -----------------------------------------------------------
def test_searchsploit_argv_cve_and_query():
    assert REGISTRY.get("searchsploit").build_argv({"cve": "CVE-2021-41773"})[-3:] == \
        ["--cve", "CVE-2021-41773", "-j"]
    assert REGISTRY.get("searchsploit").build_argv({"query": "apache 2.4"})[-1] == "apache 2.4"


def test_searchsploit_rejects_injection():
    with pytest.raises(ValueError):
        REGISTRY.get("searchsploit").build_argv({"query": "--foo; rm"})


def test_nuclei_cve_argv():
    argv = REGISTRY.get("nuclei_cve").build_argv(
        {"target": "h", "cve": "CVE-2021-41773", "scheme": "http", "port": "8080"})
    assert "-id" in argv and argv[argv.index("-id") + 1] == "cve-2021-41773"
    assert "http://h:8080" in argv


# -- confirmation outcomes ---------------------------------------------------
class _Broker:
    """nuclei_cve fires iff `nuclei_fires`. Exploitation intel is injected separately
    (via validate_cve_candidate's exploit_check), not run as a tool."""
    def __init__(self, *, nuclei_fires: bool):
        self.nf = nuclei_fires

    def execute(self, tool_id, args):
        now = datetime.now(UTC)
        out = "[cve-2021-41773] [http] [critical] https://h" if (tool_id == "nuclei_cve" and self.nf) else ""
        return ToolResult(outcome="ok", exit_code=0, started_at=now, finished_at=now,
                          tool_version="stub", observations=[{"stdout": out}])


def _exploit(exploited: bool, basis: str = "CISA KEV — actively exploited in the wild"):
    return lambda cve: {"exploited": exploited, "basis": basis if exploited else ""}


@pytest.fixture()
def db(tmp_path):
    init_engine(f"sqlite:///{tmp_path}/cc.db")
    Base.metadata.create_all(dbmod.get_engine())
    s = dbmod.SessionLocal()
    p = Project(name="P"); s.add(p); s.flush()
    e = Engagement(project_id=p.id, name="L", testing_mode="black_box", target_type="network")
    s.add(e); s.flush()
    r = Run(engagement_id=e.id, thread_id="t", status="running"); s.add(r); s.flush()
    s.commit()
    yield s, r.id
    s.close()


def _cve_finding(s, run_id, cve="CVE-2021-41773", port="80"):
    f = Finding(run_id=run_id, title=f"{cve} (CVSS 9.8)", status="candidate", severity="critical")
    s.add(f); s.flush()
    s.add(FindingObservation(finding_id=f.id, source_tool="nmap_vuln",
                             detail={"cve": cve, "cvss": 9.8, "port": port}))
    s.flush()
    return f.id


def _scope(run_id):
    return RunScope(run_id=run_id, testing_mode=TestingMode.BLACK_BOX, target="h",
                    domains=["h"], ip_cidrs=[],
                    allowed_action_classes=[PolicyClass.P0_PASSIVE, PolicyClass.P1_LOW_IMPACT],
                    signed_profile=True)


def test_nuclei_fired_confirms(db):
    s, run_id = db
    fid = _cve_finding(s, run_id); s.commit()
    h = GovernedHarness(REGISTRY, broker=_Broker(nuclei_fires=True))
    out = phases.validate_cve_candidate(s, _scope(run_id), h, fid, exploit_check=_exploit(False))
    assert out == "confirmed"
    assert s.get(Finding, fid).status == "confirmed"


def test_kev_exploited_keeps_candidate(db):
    s, run_id = db
    fid = _cve_finding(s, run_id); s.commit()
    h = GovernedHarness(REGISTRY, broker=_Broker(nuclei_fires=False))
    out = phases.validate_cve_candidate(s, _scope(run_id), h, fid, exploit_check=_exploit(True))
    assert out == "exploit_available"
    assert s.get(Finding, fid).status == "candidate"          # strong lead, not confirmed
    obs = {o.source_tool: (o.detail or {}) for o in s.query(FindingObservation).filter_by(finding_id=fid)}
    assert "exploit-intel" in obs and "KEV" in obs["exploit-intel"]["basis"]


def test_version_only_is_inconclusive(db):
    s, run_id = db
    fid = _cve_finding(s, run_id); s.commit()
    h = GovernedHarness(REGISTRY, broker=_Broker(nuclei_fires=False))
    out = phases.validate_cve_candidate(s, _scope(run_id), h, fid, exploit_check=_exploit(False))
    assert out == "inconclusive"
    assert s.get(Finding, fid).status == "inconclusive"


# -- safe on-target NSE confirmation of OS-CPE leads (Fix #2) -----------------
class _NseBroker:
    """win_vuln_scan reports VULNERABLE iff `vuln`; nuclei never fires. Confirms that an
    OS-CPE lead for an ms17-010-family CVE is promoted via the safe on-target check."""
    def __init__(self, *, vuln: bool):
        self.vuln = vuln

    def execute(self, tool_id, args):
        now = datetime.now(UTC)
        out = ""
        if tool_id == "win_vuln_scan":
            out = ("State: VULNERABLE  IDs: CVE:CVE-2017-0144" if self.vuln
                   else "State: NOT VULNERABLE")
        return ToolResult(outcome="ok", exit_code=0, started_at=now, finished_at=now,
                          tool_version="stub", observations=[{"stdout": out}])


def _os_cpe_finding(s, run_id, cve="CVE-2017-0144"):
    """An OS-CPE lead (no port) for a CVE family we have a safe on-target check for."""
    f = Finding(run_id=run_id, title=f"{cve} — affects Windows Server 2019",
                status="candidate", severity="critical")
    s.add(f); s.flush()
    s.add(FindingObservation(finding_id=f.id, source_tool="nvd_os_cpe",
                             detail={"cve": cve, "os": "Windows Server 2019"}))
    s.flush()
    return f.id


def test_os_cpe_lead_confirmed_on_target(db):
    s, run_id = db
    fid = _os_cpe_finding(s, run_id); s.commit()
    h = GovernedHarness(REGISTRY, broker=_NseBroker(vuln=True))
    out = phases.validate_cve_candidate(s, _scope(run_id), h, fid, exploit_check=_exploit(False))
    assert out == "confirmed"                                   # safe NSE proved it on-target
    assert s.get(Finding, fid).status == "confirmed"
    obs = {o.source_tool: (o.detail or {}) for o in s.query(FindingObservation).filter_by(finding_id=fid)}
    assert "VULNERABLE" in obs["win_vuln_scan"]["basis"]


def test_os_cpe_lead_not_vulnerable_stays_inconclusive(db):
    s, run_id = db
    fid = _os_cpe_finding(s, run_id); s.commit()
    h = GovernedHarness(REGISTRY, broker=_NseBroker(vuln=False))
    out = phases.validate_cve_candidate(s, _scope(run_id), h, fid, exploit_check=_exploit(False))
    assert out == "inconclusive"                                # NOT VULNERABLE → no false confirm
    assert s.get(Finding, fid).status == "inconclusive"


class _RecordingBroker:
    """Records which tools were executed; returns an empty-but-ok result for each."""
    def __init__(self):
        self.calls: list[str] = []

    def execute(self, tool_id, args):
        self.calls.append(tool_id)
        now = datetime.now(UTC)
        return ToolResult(outcome="ok", exit_code=0, started_at=now, finished_at=now,
                          tool_version="stub", observations=[{"stdout": ""}])


def test_os_cpe_lead_skips_nuclei(db):
    # An OS-level CVE lead (PGM RCE) has no nuclei template and no safe NSE check, so the
    # nuclei step must be SKIPPED (not run and logged as a noisy "did not complete"), and
    # the finding falls straight to inconclusive.
    s, run_id = db
    fid = _os_cpe_finding(s, run_id, cve="CVE-2023-36397"); s.commit()
    b = _RecordingBroker()
    h = GovernedHarness(REGISTRY, broker=b)
    out = phases.validate_cve_candidate(s, _scope(run_id), h, fid, exploit_check=_exploit(False))
    assert out == "inconclusive"
    assert "nuclei_cve" not in b.calls          # nuclei never attempted for an OS-CPE lead


def test_service_cve_still_runs_nuclei(db):
    # A service-matched CVE (source nmap_vuln) is NOT an OS lead, so nuclei IS attempted.
    s, run_id = db
    fid = _cve_finding(s, run_id, cve="CVE-2021-41773", port="80"); s.commit()
    b = _RecordingBroker()
    h = GovernedHarness(REGISTRY, broker=b)
    phases.validate_cve_candidate(s, _scope(run_id), h, fid, exploit_check=_exploit(False))
    assert "nuclei_cve" in b.calls              # templates exist for service/web CVEs
