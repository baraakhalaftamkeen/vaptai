"""dalfox XSS fuzzer (reflected + DOM via headless Chrome).

Covers:
  * builder: argv safety (in-scope URL only, pinned param validated, cookie flows via
    `_web_login_cookie()`), absolute `~/go/bin/dalfox` fallback so the tool is reachable
    without PATH surgery;
  * normalizer: Verified ('V') hit → confirmed-style observation (auto-promotes via proof
    path); Reflected ('R') hit → candidate; Grep ('G') and unknown types ignored;
    non-JSON output → no findings;
  * manifest/catalog invariant: SCAN agent gets `dalfox`;
  * proof-promotion: a dalfox-confirmed finding auto-promotes to CONFIRMED through the
    `validate_candidate` proof path (same mechanism as sstimap / web_param_probe).
"""
from __future__ import annotations

import json

import pytest
import vapt_persistence.db as dbmod
from vapt_agents import manifests, phases
from vapt_agents.normalize import normalize
from vapt_agents.runscope import RunScope
from vapt_domain.enums import PolicyClass, TestingMode
from vapt_harness import GovernedHarness
from vapt_persistence import Base, init_engine
from vapt_persistence.models import Engagement, Finding, FindingObservation, Project, Run
from vapt_tools import REGISTRY


# -- builder ----------------------------------------------------------------
def test_dalfox_builder_argv_safe():
    argv = REGISTRY.get("dalfox").build_argv(
        {"target": "example.com", "url": "http://example.com:5000/search"})
    assert argv[0].endswith("dalfox")
    assert argv[1] == "url"
    assert "http://example.com:5000/search" in argv
    assert "--format" in argv and "json" in argv
    # non-interactive, no colored output. (--silence was removed in v1.1 — it
    # suppressed JSON output on fast exits in dalfox 2.13.0.)
    assert "--no-color" in argv
    assert "--silence" not in argv


def test_dalfox_rejects_offscope_url():
    with pytest.raises(ValueError):
        REGISTRY.get("dalfox").build_argv(
            {"target": "example.com", "url": "http://evil.com/x"})


def test_dalfox_requires_http_url():
    with pytest.raises(ValueError):
        REGISTRY.get("dalfox").build_argv(
            {"target": "example.com", "url": "ftp://example.com/x"})


def test_dalfox_rejects_option_like_url():
    with pytest.raises(ValueError):
        REGISTRY.get("dalfox").build_argv(
            {"target": "example.com", "url": "--help"})


def test_dalfox_accepts_pinned_param():
    argv = REGISTRY.get("dalfox").build_argv(
        {"target": "example.com", "url": "http://example.com/search", "param": "q"})
    assert "-p" in argv and "q" in argv


def test_dalfox_rejects_bad_param():
    with pytest.raises(ValueError):
        REGISTRY.get("dalfox").build_argv(
            {"target": "example.com", "url": "http://example.com/search",
             "param": "q; rm -rf /"})


# -- normalizer -------------------------------------------------------------
def test_normalizer_verified_hit_marks_confirmed():
    out = json.dumps([
        {"type": "V", "method": "GET",
         "data": "http://h/search?q=<svg%20onload=alert(1)>",
         "param": "q", "payload": "<svg onload=alert(1)>",
         "cwe": "CWE-79", "severity": "H",
         "evidence": "payload executed in browser"},
    ])
    obs = normalize("dalfox", [{"stdout": out}])
    assert len(obs) == 1
    assert obs[0].severity == "high"
    assert obs[0].detail.get("confirmed") is True
    assert obs[0].detail.get("kind") == "verified"
    assert "confirmed" in obs[0].title


def test_normalizer_reflected_hit_is_candidate():
    out = json.dumps([
        {"type": "R", "method": "GET",
         "data": "http://h/search?q=foo",
         "param": "q", "payload": "foo",
         "cwe": "CWE-79", "severity": "M"},
    ])
    obs = normalize("dalfox", [{"stdout": out}])
    assert len(obs) == 1
    assert obs[0].detail.get("confirmed") is False
    assert obs[0].detail.get("kind") == "reflected"
    assert "candidate" in obs[0].title


def test_normalizer_drops_grep_and_unknown():
    out = json.dumps([
        {"type": "G", "data": "http://h/x", "param": "q", "severity": "L"},
        {"type": "X", "data": "http://h/y", "param": "q"},
    ])
    obs = normalize("dalfox", [{"stdout": out}])
    # No real findings are produced for G/unknown types. The diagnostic observation
    # (added so a 0-find run surfaces WHY) may be present at info severity; the
    # contract we care about here is "zero actionable XSS findings".
    assert [o for o in obs if o.severity != "info"] == []


def test_normalizer_dedupes_by_url_param():
    out = json.dumps([
        {"type": "V", "data": "http://h/x?q=1", "param": "q", "severity": "H"},
        {"type": "V", "data": "http://h/x?q=1", "param": "q", "severity": "H"},
    ])
    assert len(normalize("dalfox", [{"stdout": out}])) == 1


def test_normalizer_empty_output():
    # Non-JSON output → no diagnostic (couldn't even parse to confirm it was dalfox).
    assert normalize("dalfox", [{"stdout": "not json"}]) == []
    # Empty JSON array (common 0-find case) → one diagnostic observation so operators
    # see what dalfox did; no actionable XSS findings.
    obs = normalize("dalfox", [{"stdout": "[]"}])
    assert [o for o in obs if o.severity != "info"] == []


# -- manifest invariant -----------------------------------------------------
def test_scan_manifest_offers_dalfox():
    assert "dalfox" in manifests.SCAN.allowed_tool_ids


# -- proof-promotion --------------------------------------------------------
@pytest.fixture()
def db(tmp_path):
    init_engine(f"sqlite:///{tmp_path}/dalfox.db")
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


def test_dalfox_proof_promotes_to_confirmed(db):
    s, run_id = db
    f = Finding(run_id=run_id, title="XSS confirmed (param q)",
                status="candidate", severity="high")
    s.add(f); s.flush()
    s.add(FindingObservation(finding_id=f.id, source_tool="dalfox",
                             detail={"confirmed": True, "kind": "verified",
                                     "param": "q", "cwe": "CWE-79"}))
    s.commit()
    h = GovernedHarness(REGISTRY, broker=_OkBroker())
    assert phases.validate_candidate(s, _scope(run_id), h, f.id) is True
    assert s.get(Finding, f.id).status == "confirmed"
