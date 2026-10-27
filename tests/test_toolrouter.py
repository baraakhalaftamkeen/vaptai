"""The service-driven tool router + the catalog-tool normalizers.

The router is the best-practice selection layer: given the services a scan discovered, it
picks the RIGHT non-destructive catalog tools and runs them through the governed harness
(deterministic, so the catalog is exercised even with the LLM planner offline). The
normalizers turn those tools' raw output into structured findings instead of generic excerpts.
"""
from __future__ import annotations

from datetime import UTC, datetime

import pytest
import vapt_persistence.db as dbmod
from langgraph.checkpoint.memory import MemorySaver
from vapt_agents import phases, toolrouter
from vapt_agents.normalize import Observation, normalize
from vapt_agents.runscope import RunScope
from vapt_domain.enums import PolicyClass, TestingMode
from vapt_domain.schemas import ToolResult
from vapt_harness import GovernedHarness
from vapt_orch.graph.engagement import build_engagement_graph
from vapt_persistence import Base, init_engine
from vapt_persistence.models import Engagement, Finding, FindingObservation, Project, Run
from vapt_tools import REGISTRY


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #
@pytest.fixture()
def db(tmp_path):
    init_engine(f"sqlite:///{tmp_path}/tr.db")
    Base.metadata.create_all(dbmod.get_engine())
    s = dbmod.SessionLocal()
    p = Project(name="P"); s.add(p); s.flush()
    e = Engagement(project_id=p.id, name="L", testing_mode="black_box", target_type="network")
    s.add(e); s.flush()
    r = Run(engagement_id=e.id, thread_id="t-tr", status="running"); s.add(r); s.flush()
    s.commit()
    yield s, r.id
    s.close()


def _svc(s, run_id, port, service):
    f = Finding(run_id=run_id, title=f"Open port {port} ({service})", status="candidate", severity="info")
    s.add(f); s.flush()
    s.add(FindingObservation(finding_id=f.id, source_tool="nmap_service_scan",
                             detail={"port": port, "service": service}))
    s.flush()


class _AllAvail:
    """Stands in for the harness during selection tests: every tool is 'installed'."""
    def __init__(self, available=None):
        self._avail = available  # None → all available; else a set of tool_ids

    def tool_available(self, tool_id, args):
        return True if self._avail is None else tool_id in self._avail


def _scope(run_id, target="10.0.0.47", domains=None):
    return RunScope(run_id=run_id, testing_mode=TestingMode.BLACK_BOX, target=target,
                    domains=domains or [], ip_cidrs=[],
                    allowed_action_classes=[PolicyClass.P0_PASSIVE, PolicyClass.P1_LOW_IMPACT],
                    signed_profile=True)


# --------------------------------------------------------------------------- #
# Selection
# --------------------------------------------------------------------------- #
def test_web_services_select_web_tools(db):
    s, run_id = db
    _svc(s, run_id, "80", "http"); s.commit()
    ids = {t for t, _, _ in toolrouter.route_actions(s, _scope(run_id), _AllAvail())}
    for expect in ("whatweb", "katana", "nikto", "shcheck", "cmseek", "wafw00f", "feroxbuster"):
        assert expect in ids, (expect, ids)
    # no SSH/SMB/TLS services discovered → those tools are NOT selected
    assert not ({"ssh_audit", "smbmap", "enum4linux_ng", "sslyze"} & ids)


def test_service_specific_selection(db):
    s, run_id = db
    for port, svc in [("22", "ssh"), ("445", "microsoft-ds"), ("389", "ldap"),
                      ("25", "smtp"), ("443", "https")]:
        _svc(s, run_id, port, svc)
    s.commit()
    ids = {t for t, _, _ in toolrouter.route_actions(s, _scope(run_id), _AllAvail())}
    assert "ssh_audit" in ids                         # 22/ssh
    assert {"smbmap", "enum4linux_ng"} <= ids         # 445
    assert "ldapsearch_base" in ids                   # 389
    assert "swaks_relay" in ids                        # 25
    assert "sslyze" in ids                             # 443 TLS


def test_only_installed_tools_are_routed(db):
    s, run_id = db
    _svc(s, run_id, "80", "http"); s.commit()
    ids = {t for t, _, _ in toolrouter.route_actions(s, _scope(run_id), _AllAvail({"nikto", "whatweb"}))}
    assert ids == {"nikto", "whatweb"}                # the rest no-op (binary absent)


def test_web_target_scheme_and_port(db):
    s, run_id = db
    _svc(s, run_id, "8443", "https-alt"); s.commit()
    acts = {t: a for t, a, _ in toolrouter.route_actions(s, _scope(run_id), _AllAvail())}
    assert acts["whatweb"]["scheme"] == "https" and acts["whatweb"]["port"] == "8443"


def test_subdomain_takeover_only_for_named_domains(db):
    s, run_id = db
    _svc(s, run_id, "80", "http"); s.commit()
    ip_ids = {t for t, _, _ in toolrouter.route_actions(s, _scope(run_id, target="10.0.0.47"), _AllAvail())}
    assert "subzy" not in ip_ids                       # IP target → no takeover check
    dom_ids = {t for t, _, _ in
               toolrouter.route_actions(s, _scope(run_id, target="example.com", domains=["example.com"]), _AllAvail())}
    assert "subzy" in dom_ids


def test_limit_is_bounded(db):
    s, run_id = db
    for port, svc in [("80", "http"), ("22", "ssh"), ("445", "microsoft-ds"),
                      ("389", "ldap"), ("25", "smtp"), ("443", "https")]:
        _svc(s, run_id, port, svc)
    s.commit()
    acts = toolrouter.route_actions(s, _scope(run_id), _AllAvail(), limit=5)
    assert len(acts) == 5


# --------------------------------------------------------------------------- #
# Normalizers
# --------------------------------------------------------------------------- #
def _sev(obs, text):
    return next(o.severity for o in obs if text.lower() in o.title.lower())


def test_nikto_normalizer():
    out = "\n".join([
        "- Nikto v2.5.0",
        "+ Target IP: 10.0.0.47",
        "+ Server: Apache/2.4.49",
        "+ /: The anti-clickjacking X-Frame-Options header is not present.",
        "+ Apache/2.4.49 appears to be outdated",
        "+ OSVDB-3233: /icons/README: Apache default file found.",
        "+ /admin/: Directory indexing found.",
    ])
    obs = normalize("nikto", [{"stdout": out}])
    titles = " ".join(o.title.lower() for o in obs)
    assert "server:" not in titles and "target ip" not in titles      # banner lines skipped
    assert _sev(obs, "outdated") == "medium"
    assert _sev(obs, "default file") == "medium"                       # OSVDB
    assert _sev(obs, "x-frame-options") == "low"


def test_wpscan_normalizer():
    out = "\n".join([
        "[+] WordPress version 5.2 identified (Insecure).",
        "[!] 3 vulnerabilities identified:",
        "[!] Title: WordPress <= 5.2 - Stored XSS",
    ])
    obs = normalize("wpscan", [{"stdout": out}])
    assert any(o.severity == "medium" and "stored xss" in o.title.lower() for o in obs)
    assert any(o.severity == "info" and "5.2" in o.title for o in obs)


def test_sslyze_normalizer():
    out = "\n".join([
        " * TLS 1.0 Cipher Suites:",
        "     The server accepted the following 3 cipher suites:",
        "        TLS_RSA_WITH_RC4_128_SHA",
        " * TLS 1.2 Cipher Suites:",
        "     The server accepted the following 5 cipher suites:",
        "        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    ])
    obs = normalize("sslyze", [{"stdout": out}])
    assert any("tls 1.0" in o.title.lower() and o.severity == "medium" for o in obs)
    assert any("rc4" in o.title.lower() for o in obs)
    # A clean modern protocol is not flagged.
    assert not any("tls 1.2" in o.title.lower() for o in obs)


def test_whatweb_normalizer():
    out = "http://10.0.0.47 [200 OK] Apache[2.4.49], PHP[7.4.3], WordPress[5.2], IP[10.0.0.47], Title[Blog]"
    obs = normalize("whatweb", [{"stdout": out}])
    assert len(obs) == 1 and obs[0].severity == "info"
    techs = obs[0].detail["technologies"]
    assert any("Apache" in t for t in techs) and any("WordPress" in t for t in techs)
    assert not any("Title" in t or "IP" in t for t in techs)          # only real tech tokens


def test_katana_normalizer():
    out = "\n".join(["http://h/a", "http://h/b", "http://h/a", "not-a-url", "https://h/c"])
    obs = normalize("katana", [{"stdout": out}])
    assert len(obs) == 1 and obs[0].detail["count"] == 3               # deduped, url-only


def test_shcheck_normalizer():
    out = "\n".join([
        "[*] Missing security header: X-Frame-Options",
        "[*] Missing security header: Content-Security-Policy",
    ])
    obs = normalize("shcheck", [{"stdout": out}])
    assert len(obs) == 2 and all(o.severity == "low" for o in obs)


def test_feroxbuster_normalizer():
    out = "\n".join(["http://h/admin", "http://h/login", "http://h/admin", "noise"])
    obs = normalize("feroxbuster", [{"stdout": out}])
    assert len(obs) == 1 and obs[0].detail["count"] == 2


def test_wafw00f_normalizer():
    on = normalize("wafw00f", [{"stdout": "The site http://h is behind Cloudflare (Cloudflare Inc.) WAF."}])
    assert len(on) == 1 and "cloudflare" in on[0].title.lower()
    off = normalize("wafw00f", [{"stdout": "No WAF detected by the generic detection"}])
    assert len(off) == 1 and "no waf" in off[0].title.lower()


def test_cmseek_normalizer():
    # Detected CMS → one info finding.
    hit = normalize("cmseek", [{"stdout": "Result: CMS Detected\nCMS ID: wordpress\nVersion: 5.2"}])
    assert len(hit) == 1 and "wordpress" in hit[0].title.lower()
    # No CMS (plain IIS) → nothing, not a generic 'cmseek output' finding.
    miss = normalize("cmseek", [{"stdout": "Could not detect a CMS on the target."}])
    assert miss == []


def test_smbmap_normalizer():
    out = "\n".join([
        "\tDisk\tPermissions\tComment",
        "\tADMIN$\tNO ACCESS",
        "\tC$\tNO ACCESS",
        "\tIPC$\tREAD ONLY",
        "\tbackups\tREAD, WRITE",
    ])
    obs = normalize("smbmap", [{"stdout": out}])
    # NO ACCESS dropped; IPC$ low; backups (writable) medium
    assert {o.severity for o in obs} == {"low", "medium"}
    assert any(o.severity == "medium" and "backups" in o.title for o in obs)
    assert not any("NO ACCESS" in o.title for o in obs)


# --------------------------------------------------------------------------- #
# Dedupe — a re-entrant probe (re-running a step after a mid-node approval
# interrupt) must not persist duplicate findings.
# --------------------------------------------------------------------------- #
def test_persist_candidate_dedupes_repeat(db):
    s, run_id = db
    o = Observation("host_scripts", "RDP NTLM/host info (3389)", "info", {"port": "3389"})
    f1 = phases.persist_candidate(s, run_id, o)
    f2 = phases.persist_candidate(s, run_id, o)   # same step re-ran on resume
    s.commit()
    assert f1.id == f2.id
    assert s.query(Finding).filter(Finding.title == "RDP NTLM/host info (3389)").count() == 1
    # a genuinely different observation still creates its own row
    phases.persist_candidate(s, run_id, Observation("host_scripts", "SMB signing required (445)", "info", {}))
    s.commit()
    assert s.query(Finding).count() == 2


# --------------------------------------------------------------------------- #
# End-to-end: the graph routes a web tool and persists its structured finding
# --------------------------------------------------------------------------- #
class _RouteBroker:
    def execute(self, tool_id, args):
        now = datetime.now(UTC)
        if tool_id == "nmap_service_scan":
            out = ('<port protocol="tcp" portid="8080"><state state="open"/>'
                   '<service name="http-proxy"/></port>')
        elif tool_id == "nikto":
            out = "+ Apache/2.4.49 appears to be outdated\n+ OSVDB-3233: default file found."
        else:
            out = ""
        return ToolResult(outcome="ok", exit_code=0, started_at=now, finished_at=now,
                          tool_version="stub", observations=[{"stdout": out}])


def test_graph_routes_and_persists_nikto(db):
    s, run_id = db
    scope = _scope(run_id, target="example.com", domains=["example.com"])
    graph = build_engagement_graph(db=s, scope=scope,
                                   harness=GovernedHarness(REGISTRY, broker=_RouteBroker()),
                                   gateway=None, checkpointer=MemorySaver())
    cfg = {"configurable": {"thread_id": "t-tr"}}
    out = graph.invoke({"schema_version": 1, "run_id": run_id, "thread_id": "t-tr",
                        "scope_ref": "example.com"}, cfg)
    s.commit()
    assert out["phase"] == "report"
    titles = [f.title for f in s.query(Finding).all()]
    assert any(t.startswith("Nikto:") and "outdated" in t.lower() for t in titles), titles
