"""Tier-1 web coverage + validation-confirmation fixes.

Covers:
  * `nuclei_dast` argv builder (seeds → per-URL fuzz targets; off-host/option-like rejected).
  * `arjun` normalizer turning discovered params into parameterised seed URLs (`detail.sample`),
    which `webvuln_seed_urls` harvests to feed the active scanners.
  * validate confirmation: a service/port finding is confirmable by a reachability re-probe,
    but an active-scanner *vulnerability* finding is NOT — it stays a candidate rather than
    being over-claimed as confirmed.
"""
from __future__ import annotations

import pytest
import vapt_persistence.db as dbmod
from vapt_agents import phases
from vapt_agents.normalize import normalize
from vapt_agents.runscope import RunScope
from vapt_domain.enums import PolicyClass, TestingMode
from vapt_harness import GovernedHarness
from vapt_persistence import Base, init_engine
from vapt_persistence.models import Engagement, Finding, FindingObservation, Project, Run
from vapt_tools import REGISTRY


# -- nuclei_dast argv builder -------------------------------------------------
def test_nuclei_dast_base_url_without_seeds():
    spec = REGISTRY.get("nuclei_dast")
    argv = spec.build_argv({"target": "example.com", "scheme": "http", "port": "5000"})
    assert argv[0] == "nuclei" and "-dast" in argv
    assert "http://example.com:5000" in argv          # fuzz the base URL when no seeds


def test_nuclei_dast_fuzzes_each_seed_and_filters_scope():
    spec = REGISTRY.get("nuclei_dast")
    seeds = [
        "http://example.com/search?q=1",          # in scope -> kept
        "http://example.com/order?id=1",           # in scope -> kept
        "http://evil.com/x?p=1",                    # off host -> dropped
        "-oG/etc/passwd",                            # option-like / not a URL -> dropped
    ]
    argv = spec.build_argv({"target": "example.com", "scheme": "http", "seeds": seeds})
    us = [argv[i + 1] for i, a in enumerate(argv) if a == "-u"]
    assert "http://example.com/search?q=1" in us
    assert "http://example.com/order?id=1" in us
    assert not any("evil.com" in u for u in us)
    assert not any("/etc/passwd" in u for u in us)


def test_nuclei_dast_rejects_bad_severity():
    spec = REGISTRY.get("nuclei_dast")
    with pytest.raises(ValueError):
        spec.build_argv({"target": "example.com", "severity": "pwned"})


# -- arjun normalizer (parses arjun's console text, incl. ANSI colour) --------
def test_arjun_params_become_seed_urls():
    # Mimics real arjun 2.2.7 stdout (with ANSI codes): a "Scanning" line + "Parameters found".
    out = ("\x1b[92m arjun v2.2.7\x1b[0m\n"
           "\x1b[97m[*]\x1b[0m Scanning 0/1: http://example.com/search\n"
           "\x1b[32m[+]\x1b[0m Parameters found: q, sort\n")
    obs = normalize("arjun", [{"stdout": out}])
    assert obs and isinstance(obs[0].detail.get("sample"), list)
    sample = obs[0].detail["sample"]
    assert "http://example.com/search?q=1" in sample
    assert "http://example.com/search?sort=1" in sample


def test_arjun_json_stdout_also_parses():
    out = '{"http://example.com/order": {"method": "GET", "params": ["id"]}}'
    obs = normalize("arjun", [{"stdout": out}])
    assert "http://example.com/order?id=1" in (obs[0].detail.get("sample") or [])


def test_arjun_no_params_is_safe_info():
    out = ("[*] Scanning 0/1: http://example.com/\n"
           "[!] URL doesn't seem to be a webpage. Skipping.\n")
    obs = normalize("arjun", [{"stdout": out}])
    assert obs and "sample" not in obs[0].detail      # nothing to seed, but no crash


# -- arjun built-in targets a specific endpoint URL --------------------------
def test_arjun_builtin_targets_explicit_endpoint():
    spec = REGISTRY.get("arjun")
    argv = spec.build_argv({"target": "example.com", "url": "http://example.com:5000/search"})
    assert argv[0] == "arjun"
    assert "http://example.com:5000/search" in argv   # probes the ROUTE, not just the root


def test_arjun_builtin_rejects_offscope_url():
    spec = REGISTRY.get("arjun")
    with pytest.raises(ValueError):
        spec.build_argv({"target": "example.com", "url": "http://evil.com/x"})


def test_arjun_builtin_falls_back_to_root():
    spec = REGISTRY.get("arjun")
    argv = spec.build_argv({"target": "example.com", "scheme": "http", "port": "5000"})
    assert "http://example.com:5000" in argv


# -- validation confirmation semantics ---------------------------------------
@pytest.fixture()
def db(tmp_path):
    init_engine(f"sqlite:///{tmp_path}/t1.db")
    Base.metadata.create_all(dbmod.get_engine())
    s = dbmod.SessionLocal()
    p = Project(name="P"); s.add(p); s.flush()
    e = Engagement(project_id=p.id, name="L", testing_mode="black_box", target_type="network")
    s.add(e); s.flush()
    r = Run(engagement_id=e.id, thread_id="t", status="running"); s.add(r); s.flush()
    s.commit()
    yield s, r.id
    s.close()


class _OkBroker:
    """Broker whose re-probe always executes OK (so reachability confirmation COULD fire)."""
    def execute(self, tool_id, args):
        from datetime import UTC, datetime
        from vapt_domain.schemas import ToolResult
        now = datetime.now(UTC)
        return ToolResult(outcome="ok", exit_code=0, started_at=now, finished_at=now,
                          tool_version="stub", observations=[{"stdout": "http://h [200]"}])


def _scope(run_id):
    return RunScope(run_id=run_id, testing_mode=TestingMode.BLACK_BOX, target="h",
                    domains=["h"], ip_cidrs=[],
                    allowed_action_classes=[PolicyClass.P0_PASSIVE, PolicyClass.P1_LOW_IMPACT],
                    signed_profile=True)


def _finding(s, run_id, title, source_tool):
    f = Finding(run_id=run_id, title=title, status="candidate", severity="high")
    s.add(f); s.flush()
    s.add(FindingObservation(finding_id=f.id, source_tool=source_tool, detail={"port": "80"}))
    s.flush()
    return f.id


def test_discovered_endpoint_urls_harvests_routes_not_root(db):
    s, run_id = db
    # a katana-style finding whose sample holds discovered routes on the :5000 app
    f = Finding(run_id=run_id, title="Crawl discovered endpoint(s)", status="candidate",
                severity="info")
    s.add(f); s.flush()
    s.add(FindingObservation(finding_id=f.id, source_tool="katana", detail={"sample": [
        "http://h:5000/", "http://h:5000/search", "http://h:5000/order",
        "http://h:8080/other",                       # different port -> excluded
    ]}))
    s.commit()
    scope = _scope(run_id)
    eps = phases.discovered_endpoint_urls(s, scope, base_url="http://h:5000")
    assert "http://h:5000/search" in eps and "http://h:5000/order" in eps
    assert "http://h:5000/" not in eps               # bare root excluded
    assert not any(":8080" in u for u in eps)        # other netloc excluded


def test_service_finding_confirms_but_vuln_finding_stays_candidate(db):
    s, run_id = db
    svc = _finding(s, run_id, "Open port 80 (http)", "nmap_service_scan")
    vuln = _finding(s, run_id, "wapiti: SQL Injection at /auth/login (param: password)", "wapiti")
    s.commit()
    h = GovernedHarness(REGISTRY, broker=_OkBroker())

    assert phases.validate_candidate(s, _scope(run_id), h, svc) is True
    assert s.get(Finding, svc).status == "confirmed"

    # Reachability must NOT confirm a vulnerability finding — it stays an unverified candidate.
    assert phases.validate_candidate(s, _scope(run_id), h, vuln) is False
    assert s.get(Finding, vuln).status == "candidate"
