"""External authenticated-scanner intel: the vapt-nessus-import / vapt-tenable CLIs, the
shared `_intel` normalizer, and `ingest_external_intel` — which folds Tenable.sc + .nessus
findings into a run as CONFIRMED, corroborates (promotes) existing CVE findings, and treats
exploit-available like CISA KEV."""
from __future__ import annotations

import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest
import vapt_persistence.db as dbmod
from vapt_agents import phases
from vapt_agents.normalize import normalize
from vapt_agents.runscope import RunScope
from vapt_domain.enums import PolicyClass, TestingMode
from vapt_domain.schemas import ToolResult
from vapt_harness import GovernedHarness
from vapt_persistence import Base, init_engine
from vapt_persistence.models import Engagement, Finding, FindingObservation, Project, Run
from vapt_tools import REGISTRY

_REPO = Path(__file__).resolve().parents[1]
_NESSUS = _REPO / "workers" / "bin" / "vapt-nessus-import"
_TENABLE = _REPO / "workers" / "bin" / "vapt-tenable"

_NESSUS_XML = """<?xml version="1.0"?>
<NessusClientData_v2><Report name="r"><ReportHost name="172.25.188.23">
<HostProperties><tag name="host-ip">172.25.188.23</tag>
<tag name="operating-system">Microsoft Windows Server 2022</tag></HostProperties>
<ReportItem port="445" protocol="tcp" severity="4" pluginID="97833" pluginName="MS17-010">
<synopsis>SMB RCE.</synopsis><solution>Patch.</solution>
<cve>CVE-2017-0144</cve><cvss3_base_score>9.8</cvss3_base_score>
<exploit_available>true</exploit_available><exploit_framework_metasploit>true</exploit_framework_metasploit>
</ReportItem></ReportHost></Report></NessusClientData_v2>"""

_TENABLE_JSON = {"response": {"results": [
    {"ip": "172.25.188.23", "port": "445", "protocol": "tcp", "pluginName": "MS17-010",
     "severity": {"id": "4"}, "cve": "CVE-2017-0144", "cvssV3BaseScore": "9.8",
     "exploitAvailable": "Yes", "exploitFrameworks": "Metasploit", "synopsis": "SMB RCE",
     "solution": "Patch", "operatingSystem": "Windows Server 2022"},
    {"ip": "172.25.188.23", "port": "80", "pluginName": "IIS", "severity": {"id": "0"},
     "cve": "", "exploitAvailable": "No"},
]}}


# -- CLIs (subprocess, offline) ----------------------------------------------
def test_nessus_cli_parses_to_jsonl(tmp_path):
    f = tmp_path / "s.nessus"; f.write_text(_NESSUS_XML)
    out = subprocess.run([sys.executable, str(_NESSUS), str(f)],
                         capture_output=True, text=True)
    assert out.returncode == 0
    rows = [json.loads(l) for l in out.stdout.splitlines() if l.strip()]
    assert rows[0]["cve"] == "CVE-2017-0144" and rows[0]["severity"] == "critical"
    assert rows[0]["exploit"] is True and rows[0]["source"] == "nessus"


def test_nessus_cli_missing_file_exits_2(tmp_path):
    out = subprocess.run([sys.executable, str(_NESSUS), str(tmp_path / "nope.nessus")],
                         capture_output=True, text=True)
    assert out.returncode == 2 and out.stdout.strip() == ""


def test_tenable_cli_analysis_file(tmp_path):
    f = tmp_path / "a.json"; f.write_text(json.dumps(_TENABLE_JSON))
    out = subprocess.run([sys.executable, str(_TENABLE), "--analysis-file", str(f)],
                         capture_output=True, text=True)
    assert out.returncode == 0
    rows = [json.loads(l) for l in out.stdout.splitlines() if l.strip()]
    assert rows[0]["cve"] == "CVE-2017-0144" and rows[0]["exploit"] is True
    assert rows[0]["source"] == "tenable" and rows[1]["cve"] == ""


def test_tenable_cli_not_configured_exits_3(tmp_path):
    env = {"VAPT_TENABLE_CREDS": str(tmp_path / "none.json")}   # no env keys, no creds file
    for k in ("VAPT_TENABLE_URL", "VAPT_TENABLE_ACCESS_KEY", "VAPT_TENABLE_SECRET_KEY"):
        env.setdefault(k, "")
    import os as _os
    full = {**_os.environ, **env}
    for k in ("VAPT_TENABLE_URL", "VAPT_TENABLE_ACCESS_KEY", "VAPT_TENABLE_SECRET_KEY"):
        full[k] = ""
    out = subprocess.run([sys.executable, str(_TENABLE), "--ip", "1.2.3.4"],
                         capture_output=True, text=True, env=full)
    assert out.returncode == 3 and out.stdout.strip() == ""


def test_tenable_cli_reads_v1_creds_file(tmp_path, monkeypatch):
    # V1-style creds file is picked up when env vars are unset (no copying into .env).
    creds = tmp_path / "tenable.json"
    creds.write_text(json.dumps({"host": "10.0.0.5", "access_key": "AK", "secret_key": "SK"}))
    from importlib.machinery import SourceFileLoader
    from importlib.util import module_from_spec, spec_from_loader
    _loader = SourceFileLoader("vt_shim", str(_TENABLE))
    vt = module_from_spec(spec_from_loader("vt_shim", _loader)); _loader.exec_module(vt)
    monkeypatch.setenv("VAPT_TENABLE_CREDS", str(creds))
    for k in ("VAPT_TENABLE_URL", "VAPT_TENABLE_ACCESS_KEY", "VAPT_TENABLE_SECRET_KEY"):
        monkeypatch.delenv(k, raising=False)
    assert vt.load_creds() == ("10.0.0.5", "AK", "SK")


# -- normalizer --------------------------------------------------------------
_INTEL_JSONL = ('{"ip":"h","port":"445","plugin":"MS17-010","severity":"critical",'
                '"cve":"CVE-2017-0144","exploit":true,"frameworks":"Metasploit","source":"tenable"}\n'
                '{"_summary":{"findings":1}}')


def test_intel_normalizer_tenable():
    obs = normalize("tenable_scan", [{"stdout": _INTEL_JSONL}])
    assert len(obs) == 1
    o = obs[0]
    assert o.severity == "critical" and o.detail["cve"] == "CVE-2017-0144"
    assert o.detail["exploit"] is True and o.detail["source"] == "tenable"
    assert "CVE-2017-0144" in o.title and "h:445" in o.title


def test_intel_normalizer_skips_junk():
    assert normalize("nessus_import", [{"stdout": "not json\n{bad\n"}]) == []


def test_tenable_configured(tmp_path, monkeypatch):
    monkeypatch.setenv("VAPT_TENABLE_CREDS", str(tmp_path / "none.json"))  # no file fallback
    for k in ("VAPT_TENABLE_URL", "VAPT_TENABLE_ACCESS_KEY", "VAPT_TENABLE_SECRET_KEY"):
        monkeypatch.setenv(k, "x")
    assert phases.tenable_configured() is True
    monkeypatch.delenv("VAPT_TENABLE_SECRET_KEY")
    assert phases.tenable_configured() is False
    # A V1-style creds file alone (no env) also counts as configured.
    creds = tmp_path / "tenable.json"
    creds.write_text(json.dumps({"host": "h", "access_key": "a", "secret_key": "s"}))
    monkeypatch.setenv("VAPT_TENABLE_CREDS", str(creds))
    for k in ("VAPT_TENABLE_URL", "VAPT_TENABLE_ACCESS_KEY", "VAPT_TENABLE_SECRET_KEY"):
        monkeypatch.delenv(k, raising=False)
    assert phases.tenable_configured() is True


# -- ingestion + corroboration ----------------------------------------------
@pytest.fixture()
def db(tmp_path):
    init_engine(f"sqlite:///{tmp_path}/tn.db")
    Base.metadata.create_all(dbmod.get_engine())
    s = dbmod.SessionLocal()
    p = Project(name="P"); s.add(p); s.flush()
    e = Engagement(project_id=p.id, name="L", testing_mode="black_box", target_type="network")
    s.add(e); s.flush()
    r = Run(engagement_id=e.id, thread_id="t", status="running"); s.add(r); s.flush()
    s.commit()
    yield s, r.id
    s.close()


def _scope(run_id, **kw):
    return RunScope(run_id=run_id, testing_mode=TestingMode.BLACK_BOX, target="h",
                    domains=["h"], ip_cidrs=[],
                    allowed_action_classes=[PolicyClass.P0_PASSIVE, PolicyClass.P1_LOW_IMPACT],
                    signed_profile=True, **kw)


class _IntelBroker:
    """Returns canned intel JSONL for the nessus/tenable shims."""
    def __init__(self, *, nessus="", tenable=""):
        self.nessus, self.tenable = nessus, tenable

    def execute(self, tool_id, args):
        now = datetime.now(UTC)
        out = self.nessus if tool_id == "nessus_import" else self.tenable if tool_id == "tenable_scan" else ""
        return ToolResult(outcome="ok", exit_code=0, started_at=now, finished_at=now,
                          tool_version="stub", observations=[{"stdout": out}])


def test_nessus_import_creates_confirmed_finding(db):
    s, run_id = db
    jsonl = ('{"ip":"h","port":"445","plugin":"MS17-010","severity":"critical",'
             '"cve":"CVE-2099-0001","exploit":true,"frameworks":"Metasploit",'
             '"solution":"Patch","source":"nessus"}')
    h = GovernedHarness(REGISTRY, broker=_IntelBroker(nessus=jsonl))
    n = phases.ingest_external_intel(s, _scope(run_id), h, nessus_path="scan.nessus")
    s.commit()
    assert n == 1
    f = next(f for f in s.query(Finding).all() if "CVE-2099-0001" in f.title)
    assert f.status == "confirmed" and f.severity == "critical"
    tools = {o.source_tool for o in s.query(FindingObservation).filter_by(finding_id=f.id)}
    assert "nessus" in tools and "exploit-intel" in tools      # exploit flagged like KEV


def test_tenable_corroborates_and_promotes_existing(db, monkeypatch):
    s, run_id = db
    # An active-scan CVE lead (from nmap vulners), currently just a candidate.
    lead = Finding(run_id=run_id, title="CVE-2017-0144 (CVSS 9.8)", status="candidate",
                   severity="critical")
    s.add(lead); s.flush()
    s.add(FindingObservation(finding_id=lead.id, source_tool="nmap_vuln",
                             detail={"cve": "CVE-2017-0144", "port": "445"}))
    s.commit()

    for k in ("VAPT_TENABLE_URL", "VAPT_TENABLE_ACCESS_KEY", "VAPT_TENABLE_SECRET_KEY"):
        monkeypatch.setenv(k, "x")
    jsonl = ('{"ip":"h","port":"445","plugin":"MS17-010","severity":"critical",'
             '"cve":"CVE-2017-0144","exploit":true,"frameworks":"Metasploit","source":"tenable"}')
    h = GovernedHarness(REGISTRY, broker=_IntelBroker(tenable=jsonl))
    n = phases.ingest_external_intel(s, _scope(run_id), h)
    s.commit()
    assert n == 1
    s.refresh(lead)
    assert lead.status == "confirmed"                          # promoted, not duplicated
    assert s.query(Finding).count() == 1                       # no duplicate CVE finding
    tools = {o.source_tool for o in s.query(FindingObservation).filter_by(finding_id=lead.id)}
    assert "tenable" in tools and "exploit-intel" in tools
