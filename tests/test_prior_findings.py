"""phases.engagement_prior_findings() + summarize_prior_findings_for_llm() unit tests."""
from __future__ import annotations

import pytest

import vapt_persistence.db as dbmod
from vapt_agents.phases import (
    _normalize_finding_title,
    engagement_prior_findings,
    summarize_prior_findings_for_llm,
)
from vapt_agents.runscope import RunScope
from vapt_domain.enums import PolicyClass, TestingMode
from vapt_persistence import Base, init_engine
from vapt_persistence.models import (
    Engagement,
    Finding,
    FindingObservation,
    Project,
    Run,
)


# ---------- title normalization ----------

def test_normalize_strips_run_specific_noise():
    assert _normalize_finding_title("SSTI confirmed (param offer) (COPY 2)") \
        == "ssti confirmed (param offer)"
    assert _normalize_finding_title("SQL injection #42") \
        == "sql injection"
    assert _normalize_finding_title("  XSS   on   /search   ") \
        == "xss on /search"
    assert _normalize_finding_title("") == ""


# ---------- summarize for LLM ----------

def test_summarize_empty_returns_empty_string():
    assert summarize_prior_findings_for_llm([]) == ""


def test_summarize_renders_bullets_with_metadata():
    priors = [
        {"title": "SSTI confirmed on /admin/offer", "severity": "critical",
         "source_tool": "ssti_detect", "seen": 3, "last_seen": "2026-10-27T12:00:00"},
        {"title": "SQL injection on /auth/login", "severity": "high",
         "source_tool": "sqli_detect", "seen": 2, "last_seen": "2026-10-26"},
    ]
    out = summarize_prior_findings_for_llm(priors)
    assert "[critical]" in out and "SSTI confirmed on /admin/offer" in out
    assert "seen 3×" in out and "2026-10-27" in out and "via ssti_detect" in out
    assert "[high]" in out and "SQL injection on /auth/login" in out


def test_summarize_truncates_long_list_with_remainder_note():
    # 100 priors * ~80 chars = ~8KB; cap at 500 → should truncate.
    priors = [
        {"title": f"finding number {i} that is reasonably long",
         "severity": "info", "source_tool": "x", "seen": 1,
         "last_seen": "2026-10-27"} for i in range(100)
    ]
    out = summarize_prior_findings_for_llm(priors, cap_bytes=500)
    assert "+ " in out or "more older findings omitted" in out
    assert len(out.encode("utf-8")) <= 600  # cap + small overhead


# ---------- the DB-backed helper ----------

@pytest.fixture()
def db_with_engagement(tmp_path):
    """Fresh sqlite DB with one project + engagement + three runs attached."""
    init_engine(f"sqlite:///{tmp_path}/pf.db")
    Base.metadata.create_all(dbmod.get_engine())
    s = dbmod.SessionLocal()
    p = Project(name="P"); s.add(p); s.flush()
    eng = Engagement(project_id=p.id, name="EngA", testing_mode="black_box",
                     target_type="network")
    s.add(eng); s.flush()
    # Three runs under same engagement: r1 (oldest), r2, r3 (current).
    r1 = Run(engagement_id=eng.id, thread_id="t1", status="completed")
    r2 = Run(engagement_id=eng.id, thread_id="t2", status="completed")
    r3 = Run(engagement_id=eng.id, thread_id="t3", status="running")
    for r in (r1, r2, r3):
        s.add(r)
    s.flush()
    s.commit()
    yield s, eng.id, r1.id, r2.id, r3.id
    s.close()


def _add_finding(s, run_id, title, severity, source_tool, status="confirmed"):
    f = Finding(run_id=run_id, title=title, status=status, severity=severity)
    s.add(f); s.flush()
    s.add(FindingObservation(finding_id=f.id, source_tool=source_tool,
                             detail={"basis": "test"}))
    s.flush()
    return f.id


def _scope(run_id):
    return RunScope(run_id=run_id, testing_mode=TestingMode.BLACK_BOX,
                    target="172.25.188.23", domains=["t"], ip_cidrs=[],
                    allowed_action_classes=[PolicyClass.P1_LOW_IMPACT],
                    signed_profile=True)


def test_first_run_returns_empty(db_with_engagement):
    """No prior runs → empty list, never raises."""
    s, _eng, r1, _r2, _r3 = db_with_engagement
    # r1 is the oldest; before any findings exist, probe scope.r1 which has
    # no prior runs older than itself.
    result = engagement_prior_findings(s, _scope(r1))
    # r1 has r2 and r3 as "other" runs under the same engagement — but they
    # have NO findings yet, so the dedup/final list is empty.
    assert result == []


def test_collapses_duplicates_across_runs(db_with_engagement):
    """Same (title, severity, source_tool) across 2 prior runs → one entry
    with seen=2."""
    s, _eng, r1, r2, r3 = db_with_engagement
    _add_finding(s, r1, "SSTI confirmed on /admin/offer", "critical", "ssti_detect")
    _add_finding(s, r2, "SSTI confirmed on /admin/offer", "critical", "ssti_detect")
    _add_finding(s, r2, "SQL injection on /auth/login", "high", "sqli_detect")
    s.commit()

    priors = engagement_prior_findings(s, _scope(r3))
    assert len(priors) == 2
    ssti = next(p for p in priors if "SSTI" in p["title"])
    assert ssti["seen"] == 2
    assert ssti["severity"] == "critical"
    assert ssti["source_tool"] == "ssti_detect"
    sqli = next(p for p in priors if "SQL" in p["title"])
    assert sqli["seen"] == 1


def test_excludes_current_run_findings(db_with_engagement):
    """Findings from the CURRENT run must not appear in its own priors."""
    s, _eng, r1, _r2, r3 = db_with_engagement
    _add_finding(s, r1, "SSTI confirmed on /admin/offer", "critical", "ssti_detect")
    _add_finding(s, r3, "Current-run XSS on /search", "medium", "dalfox")
    s.commit()
    priors = engagement_prior_findings(s, _scope(r3))
    titles = [p["title"] for p in priors]
    assert "SSTI confirmed on /admin/offer" in titles
    assert "Current-run XSS on /search" not in titles


def test_crosses_engagement_boundary(tmp_path):
    """Findings from a DIFFERENT engagement under the same project must not
    leak into priors."""
    init_engine(f"sqlite:///{tmp_path}/pfx.db")
    Base.metadata.create_all(dbmod.get_engine())
    s = dbmod.SessionLocal()
    p = Project(name="P"); s.add(p); s.flush()
    e1 = Engagement(project_id=p.id, name="E1", testing_mode="black_box",
                    target_type="network")
    e2 = Engagement(project_id=p.id, name="E2", testing_mode="black_box",
                    target_type="network")
    s.add_all([e1, e2]); s.flush()
    r_e1_prior = Run(engagement_id=e1.id, thread_id="e1a", status="completed")
    r_e2_curr = Run(engagement_id=e2.id, thread_id="e2a", status="running")
    s.add_all([r_e1_prior, r_e2_curr]); s.flush()
    _add_finding(s, r_e1_prior.id, "LEAK from other engagement", "high", "x")
    s.commit()

    # From e2's current run, e1's finding must NOT appear.
    priors = engagement_prior_findings(s, _scope(r_e2_curr.id))
    assert priors == []
    s.close()


def test_respects_limit(db_with_engagement):
    """limit kwarg caps the output count."""
    s, _eng, r1, _r2, r3 = db_with_engagement
    for i in range(15):
        _add_finding(s, r1, f"finding {i}", "info", f"tool{i}")
    s.commit()
    priors = engagement_prior_findings(s, _scope(r3), limit=5)
    assert len(priors) == 5


def test_respects_min_severity(db_with_engagement):
    """min_severity filters out lower-severity priors."""
    s, _eng, r1, _r2, r3 = db_with_engagement
    _add_finding(s, r1, "info-level thing", "info", "nmap")
    _add_finding(s, r1, "medium thing", "medium", "nikto")
    _add_finding(s, r1, "critical thing", "critical", "ssti_detect")
    s.commit()
    high_only = engagement_prior_findings(s, _scope(r3), min_severity="high")
    titles = [p["title"] for p in high_only]
    assert "critical thing" in titles
    assert "medium thing" not in titles
    assert "info-level thing" not in titles
