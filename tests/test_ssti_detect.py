"""SSTI confirmation path (`ssti_detect` built-in).

Covers:
  * builder: in-scope URL only; no exploitation flags (`--os-cmd` / `--os-shell` / `--eval`);
    POST data validated; session cookie flows via VAPT_WEB_LOGIN_COOKIE.
  * normalizer: a real SSTImap hit → one high-severity CONFIRMED-proof observation; a miss
    → empty list (no noise).
  * manifest/catalog invariant: SCAN agent gets `ssti_detect` but NOT `sstimap`.
  * proof-promotion: a sstimap-confirmed finding auto-promotes to CONFIRMED in
    `validate_candidate`, bypassing the reachability re-probe.
  * webvuln helper: `wapiti_xss_targets` extracts (route, param) pairs from wapiti findings.
"""
from __future__ import annotations

import pytest
import vapt_persistence.db as dbmod
from vapt_agents import manifests, phases
from vapt_agents.normalize import normalize
from vapt_agents.runscope import RunScope
from vapt_domain.enums import AgentRole, PolicyClass, TestingMode
from vapt_harness import GovernedHarness
from vapt_persistence import Base, init_engine
from vapt_persistence.models import Engagement, Finding, FindingObservation, Project, Run
from vapt_tools import REGISTRY


# -- builder -----------------------------------------------------------------
def test_ssti_detect_builder_argv_safe():
    argv = REGISTRY.get("ssti_detect").build_argv(
        {"target": "example.com", "url": "http://example.com:5000/admin/announcement?content=1"})
    assert argv[0] == "sstimap"
    assert "http://example.com:5000/admin/announcement?content=1" in argv
    assert "--level" in argv
    # Detection ONLY — any exploitation flag would be unsafe:
    for forbidden in ("--os-cmd", "--os-shell", "--eval", "-X", "--upload", "-U"):
        assert forbidden not in argv


def test_ssti_detect_rejects_offscope_url():
    with pytest.raises(ValueError):
        REGISTRY.get("ssti_detect").build_argv(
            {"target": "example.com", "url": "http://evil.com/x?a=1"})


def test_ssti_detect_rejects_malformed_post_data():
    with pytest.raises(ValueError):
        REGISTRY.get("ssti_detect").build_argv(
            {"target": "example.com", "url": "http://example.com/x",
             "data": "name=val; drop table users"})


def test_ssti_detect_accepts_well_formed_post_data():
    argv = REGISTRY.get("ssti_detect").build_argv(
        {"target": "example.com", "url": "http://example.com/x", "data": "content=hi&id=1"})
    assert "-d" in argv and "content=hi&id=1" in argv


def test_ssti_detect_injects_cookie(monkeypatch):
    monkeypatch.setenv("VAPT_WEB_LOGIN_COOKIE", "sid=abc123")
    argv = REGISTRY.get("ssti_detect").build_argv(
        {"target": "example.com", "url": "http://example.com/x"})
    assert "-C" in argv and "sid=abc123" in argv


def test_ssti_detect_passes_engine_hint():
    """When the caller supplies a validated engine from captured tech data, sstimap
    gets `-e <engine>` so it skips every other engine plugin. No engine arg = no `-e`."""
    argv = REGISTRY.get("ssti_detect").build_argv(
        {"target": "example.com", "url": "http://example.com/x", "engine": "Jinja2"})
    assert "-e" in argv and "Jinja2" in argv
    # No engine arg → no `-e` flag (full probe)
    argv2 = REGISTRY.get("ssti_detect").build_argv(
        {"target": "example.com", "url": "http://example.com/x"})
    assert "-e" not in argv2


def test_ssti_detect_rejects_bad_engine_name():
    """engine must be a simple identifier (no shell/argv injection)."""
    with pytest.raises(ValueError):
        REGISTRY.get("ssti_detect").build_argv(
            {"target": "example.com", "url": "http://example.com/x", "engine": "-oG/etc/passwd"})
    with pytest.raises(ValueError):
        REGISTRY.get("ssti_detect").build_argv(
            {"target": "example.com", "url": "http://example.com/x", "engine": "Jinja2;ls"})


# -- normalizer --------------------------------------------------------------
def test_sstimap_normalizer_confirms_a_hit():
    out = (
        "[*] Scanning url: http://example.com/admin/announcement?content=1\n"
        "[*] Testing if Query parameter 'content' is injectable\n"
        "[+] SSTImap identified the following injection point:\n"
        "    Engine: Jinja2\n"
        "    Language: python\n"
    )
    obs = normalize("ssti_detect", [{"stdout": out}])
    assert obs and len(obs) == 1
    assert obs[0].severity == "critical"
    assert obs[0].detail.get("confirmed") is True
    assert obs[0].detail.get("engine", "").lower() == "jinja2"
    assert obs[0].detail.get("param") == "content"


def test_sstimap_normalizer_miss_is_empty():
    # A sstimap miss produces zero actionable SSTI findings. The diagnostic observation
    # we emit at info severity (so operators see WHY nothing matched) is explicitly
    # permitted here; the invariant is "no critical/high claim without proof".
    out = "[*] Testing ...\n[-] Tested parameters appear to be not injectable.\n"
    obs = normalize("ssti_detect", [{"stdout": out}])
    assert [o for o in obs if o.severity != "info"] == []


def test_sstimap_normalizer_error_output_is_empty():
    out = "[-] Error: max retries exceeded for a connection.\n"
    obs = normalize("ssti_detect", [{"stdout": out}])
    assert [o for o in obs if o.severity != "info"] == []


# -- manifest + catalog invariant --------------------------------------------
def test_scan_manifest_offers_ssti_detect_not_sstimap():
    assert "ssti_detect" in manifests.SCAN.allowed_tool_ids
    assert "sstimap" not in manifests.SCAN.allowed_tool_ids   # exploitation stays ATTACK-only


def test_catalog_sstimap_stays_attack_only():
    assert REGISTRY.get("sstimap").allowed_agents == [AgentRole.ATTACK]


# -- proof-promotion ---------------------------------------------------------
@pytest.fixture()
def db(tmp_path):
    init_engine(f"sqlite:///{tmp_path}/ssti.db")
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
    def execute(self, tool_id, args):
        from datetime import UTC, datetime
        from vapt_domain.schemas import ToolResult
        now = datetime.now(UTC)
        return ToolResult(outcome="ok", exit_code=0, started_at=now, finished_at=now,
                          tool_version="stub", observations=[{"stdout": "ok"}])


def _scope(run_id):
    return RunScope(run_id=run_id, testing_mode=TestingMode.BLACK_BOX, target="h",
                    domains=["h"], ip_cidrs=[],
                    allowed_action_classes=[PolicyClass.P0_PASSIVE, PolicyClass.P1_LOW_IMPACT],
                    signed_profile=True)


def test_sstimap_proof_finding_promotes_to_confirmed(db):
    s, run_id = db
    f = Finding(run_id=run_id, title="SSTI confirmed (param content, engine Jinja2)",
                status="candidate", severity="critical")
    s.add(f); s.flush()
    s.add(FindingObservation(finding_id=f.id, source_tool="sstimap",
                             detail={"confirmed": True, "engine": "Jinja2", "param": "content"}))
    s.commit()
    h = GovernedHarness(REGISTRY, broker=_OkBroker())
    assert phases.validate_candidate(s, _scope(run_id), h, f.id) is True
    assert s.get(Finding, f.id).status == "confirmed"


# -- engine inference from CAPTURED httpx data (no hardcoding) --------------
def test_httpx_normalizer_captures_server_and_tech():
    out = "http://host:5000 [200] [DineHub] [Werkzeug/3.0.1] [Flask,Jinja,Python]\n"
    obs = normalize("http_probe", [{"stdout": out}])
    assert obs and obs[0].detail.get("status") == "200"
    assert obs[0].detail.get("server") == "Werkzeug/3.0.1"
    assert "Flask" in obs[0].detail.get("tech", [])
    assert "Jinja" in obs[0].detail.get("tech", [])


def test_infer_template_engine_from_wappalyzer_flask(db):
    """Flask in the Wappalyzer tech list ⇒ sstimap engine Jinja2 (no guessing — Flask
    uses Jinja2 by default and this is the token we actually captured)."""
    s, run_id = db
    f = Finding(run_id=run_id, title="HTTP service: http://h:5000 [200]", status="candidate",
                severity="info")
    s.add(f); s.flush()
    s.add(FindingObservation(finding_id=f.id, source_tool="http_probe",
                             detail={"tech": ["Flask", "Python", "Nginx"]}))
    s.commit()
    assert phases.infer_template_engine(s, run_id) == "Jinja2"


def test_infer_template_engine_from_server_banner_werkzeug(db):
    s, run_id = db
    f = Finding(run_id=run_id, title="HTTP service: http://h:5000 [200]", status="candidate",
                severity="info")
    s.add(f); s.flush()
    s.add(FindingObservation(finding_id=f.id, source_tool="http_probe",
                             detail={"server": "Werkzeug/3.0.1"}))
    s.commit()
    assert phases.infer_template_engine(s, run_id) == "Jinja2"


def test_infer_template_engine_ambiguous_returns_none(db):
    """A generic PHP/Node/Nginx banner says nothing about the template engine — we must
    NOT guess (that would be hardcoding by proxy). None → sstimap probes all engines."""
    s, run_id = db
    f = Finding(run_id=run_id, title="HTTP service: http://h [200]", status="candidate",
                severity="info")
    s.add(f); s.flush()
    s.add(FindingObservation(finding_id=f.id, source_tool="http_probe",
                             detail={"server": "nginx/1.24", "tech": ["Nginx", "PHP", "jQuery"]}))
    s.commit()
    assert phases.infer_template_engine(s, run_id) is None


def test_infer_template_engine_no_data_returns_none(db):
    """Nothing captured ⇒ None (sstimap falls back to full engine probe)."""
    s, run_id = db
    assert phases.infer_template_engine(s, run_id) is None


# -- wapiti_xss_targets helper -----------------------------------------------
def test_wapiti_xss_targets_defaults_to_get_when_method_missing(db):
    s, run_id = db
    # Seed a wapiti reflected-XSS finding + an http_probe finding so the helper can rebuild the URL
    s.add(Finding(run_id=run_id, title="HTTP service: http://h:5000 [200] [DineHub]",
                  status="confirmed", severity="info"))
    xss = Finding(run_id=run_id,
                  title="wapiti: Reflected Cross Site Scripting at /admin/announcement (param: content)",
                  status="candidate", severity="medium")
    s.add(xss); s.flush()
    s.add(FindingObservation(finding_id=xss.id, source_tool="wapiti", detail={}))
    s.commit()
    targets = phases.wapiti_xss_targets(s, run_id)
    assert ("http://h:5000/admin/announcement", "content", "GET") in targets


def test_wapiti_xss_targets_preserves_post_method_from_wapiti_detail(db):
    """When wapiti's observation records method=POST (as it does for form vectors), the
    helper surfaces POST so the plan sends sstimap `-d body` instead of `-u url?param=1` —
    this is how /admin/announcement (an admin POST form) gets probed correctly."""
    s, run_id = db
    s.add(Finding(run_id=run_id, title="HTTP service: http://h:5000 [200] [DineHub]",
                  status="confirmed", severity="info"))
    xss = Finding(run_id=run_id,
                  title="wapiti: Reflected Cross Site Scripting at /admin/announcement (param: content)",
                  status="candidate", severity="medium")
    s.add(xss); s.flush()
    s.add(FindingObservation(finding_id=xss.id, source_tool="wapiti",
                             detail={"method": "POST", "parameter": "content",
                                     "path": "/admin/announcement"}))
    s.commit()
    targets = phases.wapiti_xss_targets(s, run_id)
    assert ("http://h:5000/admin/announcement", "content", "POST") in targets


def test_ssti_detect_builds_post_body_from_data_arg():
    """When the plan supplies `data=content=1` (because wapiti said POST), the builder emits
    `-d content=1` instead of putting the param in the URL — this is the gap that caused
    /admin/announcement to be probed with GET and miss the real POST-only SSTI."""
    argv = REGISTRY.get("ssti_detect").build_argv(
        {"target": "example.com", "url": "http://example.com:5000/admin/announcement",
         "data": "content=1"})
    assert "-d" in argv and "content=1" in argv
    # URL has no query string in POST mode (we don't rewrite it with ?param=1)
    assert "http://example.com:5000/admin/announcement" in argv
    assert "?content=" not in " ".join(argv)
