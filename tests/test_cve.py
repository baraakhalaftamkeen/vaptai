"""CVE integration (ported from V1): NVD lookup/enrichment, the vulners normalizer, and
the nmap_vuln tool. Network is injected (`_fetch`) so CI never hits NVD."""
from __future__ import annotations

import pytest
import vapt_persistence.db as dbmod
from vapt_agents import cve, phases
from vapt_agents.cve import (
    cpe_cve_match,
    cve_feed,
    enrich_cve_findings,
    is_exploited,
    kev_cves,
    lookup_cve,
    resolve_cpe,
    severity_from_cvss,
)
from vapt_agents.normalize import normalize
from vapt_persistence import Base, init_engine
from vapt_persistence.models import Engagement, Finding, FindingObservation, Project, Run
from vapt_tools import REGISTRY


@pytest.fixture(autouse=True)
def _isolate_cache(tmp_path, monkeypatch):
    monkeypatch.setenv("VAPT_CVE_CACHE", str(tmp_path / "cve_cache.json"))
    monkeypatch.setenv("VAPT_KEV_CACHE", str(tmp_path / "kev_catalog.json"))
    monkeypatch.setenv("VAPT_FEED_CACHE", str(tmp_path / "cve_feed.json"))


# -- CVSS banding ------------------------------------------------------------
@pytest.mark.parametrize("score,band", [
    (9.8, "critical"), (9.0, "critical"), (7.5, "high"), (4.0, "medium"),
    (3.9, "low"), (0.0, "info"), (None, "info"),
])
def test_severity_from_cvss(score, band):
    assert severity_from_cvss(score) == band


# -- NVD lookup (injected fetch) ---------------------------------------------
_NVD = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-41773",
                "metrics": {
                    "cvssMetricV31": [
                        {"cvssData": {"baseScore": 9.8, "vectorString": "CVSS:3.1/AV:N"}}
                    ]
                },
                "descriptions": [
                    {"lang": "en", "value": "Path traversal in Example httpd."}
                ],
                "references": [
                    {"url": "https://nvd.nist.gov/vuln/detail/CVE-2021-41773"}
                ],
            }
        }
    ]
}


def test_lookup_cve_parses_nvd():
    info = lookup_cve("CVE-2021-41773", _fetch=lambda c, t: _NVD)
    assert info["cvss"] == 9.8 and info["severity"] == "critical"
    assert "traversal" in info["description"].lower()
    assert info["references"]


def test_lookup_cve_bad_id_and_offline_are_safe():
    assert lookup_cve("not-a-cve") == {}
    def _boom(c, t):
        raise OSError("offline")
    assert lookup_cve("CVE-2021-41773", _fetch=_boom) == {}


# -- CISA KEV + exploitation intel (no local Exploit-DB) ---------------------
_KEV = {"vulnerabilities": [{"cveID": "CVE-2021-41773"}, {"cveID": "CVE-2017-0144"}]}


def test_kev_cves_parsed_and_offline_safe():
    cves = kev_cves(_fetch=lambda t: _KEV)
    assert "CVE-2021-41773" in cves and "CVE-2017-0144" in cves

    def _boom(t):
        raise OSError("offline")
    # cache was written by the first call; isolate by clearing env path via a fresh id
    assert isinstance(kev_cves(_fetch=_boom), set)      # never raises


def test_is_exploited_prefers_kev():
    out = is_exploited("CVE-2021-41773", _fetch_kev=lambda t: _KEV)
    assert out["exploited"] is True and "KEV" in out["basis"]


def test_is_exploited_falls_back_to_nvd_exploit_ref():
    nvd_with_exploit = {"exploit_refs": ["https://example.com/poc"]}
    out = is_exploited("CVE-2000-1111", nvd_info=nvd_with_exploit, _fetch_kev=lambda t: {"vulnerabilities": []})
    assert out["exploited"] is True and "NVD" in out["basis"]


def test_is_exploited_none_when_no_signal():
    out = is_exploited("CVE-2000-2222", nvd_info={"exploit_refs": []},
                       _fetch_kev=lambda t: {"vulnerabilities": []})
    assert out["exploited"] is False


# -- CVE feed (NVD recent) ---------------------------------------------------
_FEED = {"vulnerabilities": [
    {"cve": {"id": "CVE-2026-0001",
             "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.9}}]},
             "descriptions": [{"lang": "en", "value": "Critical RCE in WidgetServer."}],
             "published": "2026-10-10T00:00:00"}},
    {"cve": {"id": "CVE-2026-0002",
             "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 8.1}}]},
             "descriptions": [{"lang": "en", "value": "High-severity auth bypass."}],
             "published": "2026-10-09T00:00:00"}},
    {"cve": {"id": "CVE-2026-0003",      # below min_score -> filtered
             "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 5.0}}]},
             "descriptions": [{"lang": "en", "value": "Medium info leak."}],
             "published": "2026-10-08T00:00:00"}},
]}


def test_cve_feed_filters_and_sorts():
    items = cve_feed(min_score=7.0, _fetch=lambda p, t: _FEED)
    ids = [i["id"] for i in items]
    assert ids == ["CVE-2026-0001", "CVE-2026-0002"]       # sorted desc, 5.0 filtered out
    assert items[0]["severity"] == "critical" and items[0]["score"] == 9.9


def test_cve_feed_offline_is_empty():
    def _boom(p, t):
        raise OSError("offline")
    assert cve_feed(_fetch=_boom) == []


# -- NVD CPE fallback matcher ------------------------------------------------
_CPE_DICT = {"products": [
    {"cpe": {"cpeName": "cpe:2.3:a:microsoft:internet_information_services:-:*:*:*:*:*:*:*"}},
]}
_CPE_CVES = {"vulnerabilities": [
    {"cve": {"id": "CVE-2015-1635",
             "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]},
             "descriptions": [{"lang": "en", "value": "HTTP.sys RCE in IIS."}]}},
]}


def test_resolve_cpe_picks_application_cpe():
    cpe = resolve_cpe("Microsoft IIS httpd", _fetch=lambda p, t: _CPE_DICT)
    assert cpe == {"part": "a", "vendor": "microsoft", "product": "internet_information_services"}


def test_cpe_cve_match_returns_cves_for_version():
    out = cpe_cve_match("Microsoft IIS httpd", "10.0",
                        _fetch_cpe=lambda p, t: _CPE_DICT, _fetch_cve=lambda vms, t: _CPE_CVES)
    assert out and out[0]["cve_id"] == "CVE-2015-1635"
    assert out[0]["severity"] == "critical"


def test_cpe_cve_match_requires_version():
    # No usable version → no query (matching a whole product is too broad).
    assert cpe_cve_match("Microsoft IIS httpd", "", _fetch_cpe=lambda p, t: _CPE_DICT) == []


def test_cpe_cve_match_offline_is_empty():
    def _boom(*a):
        raise OSError("offline")
    assert cpe_cve_match("x", "1.0", _fetch_cpe=_boom) == []


# -- OS-CPE matcher precision gate (Fix #1) ----------------------------------
_OS_CPE_DICT = {"products": [
    {"cpe": {"cpeName": "cpe:2.3:o:microsoft:windows_server_2022:-:*:*:*:*:*:*:*"}},
]}
# One genuine OS vuln (OS CPE is vulnerable:true) and one app-on-OS false positive
# (the OS CPE is only a vulnerable:false 'running on' platform for a third-party app).
_OS_CPE_CVES = {"vulnerabilities": [
    {"cve": {"id": "CVE-2024-0001",
             "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]},
             "descriptions": [{"lang": "en", "value": "Windows SMB RCE."}],
             "configurations": [{"nodes": [{"operator": "OR", "cpeMatch": [
                 {"vulnerable": True,
                  "criteria": "cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*"}]}]}]}},
    {"cve": {"id": "CVE-2023-38545",   # curl, running on Windows — must be dropped
             "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]},
             "descriptions": [{"lang": "en", "value": "curl SOCKS5 heap overflow."}],
             "configurations": [{"operator": "AND", "nodes": [
                 {"cpeMatch": [{"vulnerable": True,
                                "criteria": "cpe:2.3:a:haxx:curl:*:*:*:*:*:*:*:*"}]},
                 {"cpeMatch": [{"vulnerable": False,
                                "criteria": "cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*"}]}]}]}},
]}


def test_os_cpe_match_keeps_only_os_vulnerable_component():
    from vapt_agents.cve import os_cpe_cve_match
    out = os_cpe_cve_match("Windows Server 2022",
                           _fetch_cpe=lambda p, t: _OS_CPE_DICT,
                           _fetch_cve=lambda vms, t: _OS_CPE_CVES)
    ids = [m["cve_id"] for m in out]
    assert ids == ["CVE-2024-0001"]              # the real OS vuln kept
    assert "CVE-2023-38545" not in ids           # curl-on-Windows noise dropped


# -- vulners normalizer ------------------------------------------------------
_VULNERS_XML = """<host><ports>
<port protocol="tcp" portid="80"><service name="http" product="Apache httpd" version="2.4.49"/>
<script id="vulners" output="
  cpe:/a:apache:http_server:2.4.49:
    CVE-2021-42013  9.8  https://vulners.com/cve/CVE-2021-42013  *EXPLOIT*
    CVE-2021-41773  7.5  https://vulners.com/cve/CVE-2021-41773
"/></port>
</ports></host>"""


def test_vulners_parses_cves_with_severity_and_port():
    obs = normalize("nmap_vuln", [{"stdout": _VULNERS_XML}])
    by = {o.detail["cve"]: o for o in obs}
    assert by["CVE-2021-42013"].severity == "critical"
    assert by["CVE-2021-42013"].detail["exploit"] is True
    assert by["CVE-2021-42013"].detail["port"] == "80"
    assert by["CVE-2021-41773"].severity == "high"
    assert "CVSS" in by["CVE-2021-41773"].title


def test_nmap_vuln_tool_argv():
    argv = REGISTRY.get("nmap_vuln").build_argv({"target": "10.0.0.1", "ports": "80,443"})
    assert "-sV" in argv and argv[argv.index("--script") + 1] == "vulners"


# -- enrichment of CVE findings ---------------------------------------------
@pytest.fixture()
def db(tmp_path):
    init_engine(f"sqlite:///{tmp_path}/cve.db")
    Base.metadata.create_all(dbmod.get_engine())
    s = dbmod.SessionLocal()
    p = Project(name="P"); s.add(p); s.flush()
    e = Engagement(project_id=p.id, name="L", testing_mode="black_box", target_type="network")
    s.add(e); s.flush()
    r = Run(engagement_id=e.id, thread_id="t", status="running"); s.add(r); s.flush()
    s.commit()
    yield s, r.id
    s.close()


def test_enrich_cve_findings_sets_description_and_severity(db):
    s, run_id = db
    f = Finding(run_id=run_id, title="CVE-2021-41773 (CVSS 7.5)", status="candidate", severity="high")
    s.add(f); s.flush()
    s.add(FindingObservation(finding_id=f.id, source_tool="nmap_vuln",
                             detail={"cve": "CVE-2021-41773", "cvss": 7.5}))
    s.commit()
    n = enrich_cve_findings(s, run_id, _fetch=lambda c, t: _NVD)
    assert n == 1
    s.refresh(f)
    assert f.severity == "critical"                 # NVD authoritative score wins
    assert "traversal" in (f.description or "").lower()


def test_nvd_cpe_findings_persist_and_dedupe(db):
    s, run_id = db
    # a service with a detected product+version, plus an existing vulners CVE to dedupe on
    svc = Finding(run_id=run_id, title="Open port 80 (http) — Microsoft IIS httpd 10.0",
                  status="candidate", severity="info")
    s.add(svc); s.flush()
    s.add(FindingObservation(finding_id=svc.id, source_tool="nmap_service_scan",
                             detail={"port": "80", "product_name": "Microsoft IIS httpd",
                                     "version": "10.0"}))
    existing = Finding(run_id=run_id, title="CVE-2015-1635", status="candidate", severity="critical")
    s.add(existing); s.flush()
    s.add(FindingObservation(finding_id=existing.id, source_tool="nmap_vuln",
                             detail={"cve": "CVE-2015-1635"}))
    s.commit()

    def _matcher(product, version):
        assert version == "10.0"
        return [
            {"cve_id": "CVE-2015-1635", "cvss": 9.8, "severity": "critical", "description": "dup"},
            {"cve_id": "CVE-2021-31166", "cvss": 9.8, "severity": "critical", "description": "HTTP.sys"},
        ]

    created = phases.nvd_cpe_findings(s, run_id, matcher=_matcher)
    assert created == 1                                    # the duplicate was skipped
    titles = [f.title for f in s.query(Finding).all()]
    assert any("CVE-2021-31166" in t and "port 80" in t for t in titles)
    # the new finding is recognised as a CVE candidate (gets the confirmation path)
    new_fid = next(f.id for f in s.query(Finding).all() if "CVE-2021-31166" in f.title)
    assert phases.cve_ref_for(s, new_fid) is not None


def test_open_ports_helper(db):
    s, run_id = db
    for port in ("80", "445", "3389"):
        fid_f = Finding(run_id=run_id, title=f"Open port {port}", status="candidate", severity="info")
        s.add(fid_f); s.flush()
        s.add(FindingObservation(finding_id=fid_f.id, source_tool="nmap_service_scan",
                                 detail={"port": port}))
    s.commit()
    assert set(phases.open_ports_from_findings(s, run_id)) == {"80", "445", "3389"}
