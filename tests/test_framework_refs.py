"""Phase B — report framework-tag enrichment from the skill library.

Confirms:
  1. `framework_refs_for_tools` unions MITRE/CWE/OWASP tags from skills that
     reference the given tool_ids in their frontmatter `tools_available`.
  2. report.gather() attaches `framework_refs` to each finding dict (keyed off
     the observation `source_tool` set).
  3. render_html() surfaces the tags as inline chips below the finding title.
"""
from __future__ import annotations

import pytest

from vapt_persistence import Base, init_engine
import vapt_persistence.db as dbmod
from vapt_persistence.models import (
    Engagement, Finding, FindingObservation, Project, Run,
)
from vapt_skills import framework_refs_for_tools
from vapt_agents.report import gather, render_html


@pytest.fixture()
def db(tmp_path):
    init_engine(f"sqlite:///{tmp_path}/n.db")
    Base.metadata.create_all(dbmod.get_engine())
    s = dbmod.SessionLocal()
    p = Project(name="P"); s.add(p); s.flush()
    e = Engagement(project_id=p.id, name="L", testing_mode="black_box",
                   target_type="web"); s.add(e); s.flush()
    r = Run(engagement_id=e.id, thread_id="t", status="running"); s.add(r); s.flush()
    s.commit()
    yield s, r.id
    s.close()


# --------------------------------------------------------------------------- #
# framework_refs_for_tools unit tests
# --------------------------------------------------------------------------- #
def test_framework_refs_unions_tags_across_skills():
    # sqli_detect appears in scan-sqli-detection (CWE-89, A03:2021, T1190).
    refs = framework_refs_for_tools(["sqli_detect"])
    assert "T1190" in refs["mitre_attack"]
    assert "CWE-89" in refs["cwe"]
    assert "A03:2021" in refs["owasp"]


def test_framework_refs_empty_on_unknown_tool():
    # A tool_id no skill references yields empty lists (not missing keys —
    # callers can render blindly).
    refs = framework_refs_for_tools(["this_tool_is_not_in_any_skill"])
    assert refs == {"mitre_attack": [], "cwe": [], "owasp": []}


def test_framework_refs_empty_on_empty_input():
    refs = framework_refs_for_tools([])
    assert refs == {"mitre_attack": [], "cwe": [], "owasp": []}


def test_framework_refs_dedups_and_sorts():
    # Multiple tools that share a MITRE tag → one entry, sorted ASCII.
    refs = framework_refs_for_tools(["sqli_detect", "stored_xss_probe", "dalfox"])
    # Must be sorted and deduped.
    assert refs["mitre_attack"] == sorted(set(refs["mitre_attack"]))
    assert refs["cwe"] == sorted(set(refs["cwe"]))
    # XSS and SQLi tools both touch A03:2021 — must appear exactly once.
    assert refs["owasp"].count("A03:2021") <= 1


# --------------------------------------------------------------------------- #
# report.gather() integration
# --------------------------------------------------------------------------- #
def test_gather_attaches_framework_refs_to_findings(db):
    s, run_id = db
    f = Finding(run_id=run_id, title="SQL injection confirmed",
                severity="high", status="confirmed"); s.add(f); s.flush()
    s.add(FindingObservation(finding_id=f.id, source_tool="sqli_detect",
                             detail={"confirmed": True})); s.commit()
    data = gather(s, run_id)
    high = data.findings_by_sev.get("high", [])
    assert high, "expected the high-severity finding to be in the report data"
    refs = high[0].get("framework_refs")
    assert refs is not None, "framework_refs must be attached"
    assert "T1190" in refs["mitre_attack"]
    assert "CWE-89" in refs["cwe"]


def test_gather_attaches_empty_refs_when_no_matching_skill(db):
    s, run_id = db
    f = Finding(run_id=run_id, title="generic obs", severity="info",
                status="candidate"); s.add(f); s.flush()
    # A source_tool no skill references
    s.add(FindingObservation(finding_id=f.id, source_tool="unknown_tool",
                             detail={})); s.commit()
    data = gather(s, run_id)
    info = data.findings_by_sev.get("info", [])
    assert info and info[0]["framework_refs"] == {
        "mitre_attack": [], "cwe": [], "owasp": [],
    }


# --------------------------------------------------------------------------- #
# render_html() surfaces the tags as chips
# --------------------------------------------------------------------------- #
def test_render_html_emits_mitre_cwe_owasp_chips(db):
    s, run_id = db
    f = Finding(run_id=run_id, title="SQL injection confirmed on login",
                severity="high", status="confirmed"); s.add(f); s.flush()
    s.add(FindingObservation(finding_id=f.id, source_tool="sqli_detect",
                             detail={"confirmed": True})); s.commit()
    data = gather(s, run_id)
    html = render_html(data)
    assert "MITRE T1190" in html
    assert "CWE-89" in html
    assert "OWASP A03:2021" in html
    assert 'class="chip chip-mitre"' in html
    assert 'class="chip chip-cwe"' in html


def test_render_html_omits_chip_block_when_no_refs(db):
    s, run_id = db
    f = Finding(run_id=run_id, title="noise", severity="info",
                status="candidate"); s.add(f); s.flush()
    s.add(FindingObservation(finding_id=f.id, source_tool="unknown_tool",
                             detail={})); s.commit()
    data = gather(s, run_id)
    html = render_html(data)
    # The chip CSS classes should NOT appear in the body since no refs matched.
    # (The CSS declarations still appear in the <style> block — only check the
    # finding-body chips area.)
    body_section = html.split("<body>", 1)[-1]
    assert 'class="chip chip-mitre"' not in body_section
    assert 'class="chip chip-cwe"' not in body_section
