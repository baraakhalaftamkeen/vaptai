"""Report generation: untrusted tool output is HTML-escaped (no markup injection), the
report is persisted and reflects the findings, and the API exposes get / download /
regenerate / sign-off."""
from __future__ import annotations

import pytest
import vapt_persistence.db as dbmod
from fastapi.testclient import TestClient
from vapt_agents.report import build_and_store, gather, render_html
from vapt_persistence import Base, init_engine
from vapt_persistence.models import (
    Engagement,
    Finding,
    FindingObservation,
    Project,
    Run,
)


@pytest.fixture()
def db(tmp_path):
    init_engine(f"sqlite:///{tmp_path}/rep.db")
    Base.metadata.create_all(dbmod.get_engine())
    s = dbmod.SessionLocal()
    p = Project(name="P"); s.add(p); s.flush()
    e = Engagement(project_id=p.id, name="Lab", testing_mode="black_box", target_type="web")
    s.add(e); s.flush()
    r = Run(engagement_id=e.id, thread_id="t", status="completed"); s.add(r); s.flush()
    s.commit()
    yield s, r.id
    s.close()


def test_untrusted_finding_text_is_escaped(db):
    s, run_id = db
    f = Finding(run_id=run_id, title="<script>alert(1)</script> XSS in search",
                status="confirmed", severity="high", description="reflected <b>input</b>")
    s.add(f); s.flush()
    s.add(FindingObservation(finding_id=f.id, source_tool="nuclei",
                             detail={"file": "<img src=x>", "line": 1}))
    s.commit()

    report = build_and_store(s, run_id, summary="see <b>below</b>", remediation="encode output")
    s.commit()

    assert report.id and report.status == "draft"
    html = report.content
    # The raw script/markup never appears; its escaped form does.
    assert "<script>alert(1)" not in html
    assert "&lt;script&gt;alert(1)" in html
    assert "<img src=x>" not in html
    # Counts reflect the finding.
    assert report.stats["counts"]["confirmed"] == 1
    assert report.stats["counts"]["high"] == 1


def test_gather_groups_by_severity(db):
    s, run_id = db
    for sev in ("high", "low", "high"):
        f = Finding(run_id=run_id, title=f"f-{sev}", status="candidate", severity=sev)
        s.add(f)
    s.commit()
    data = gather(s, run_id)
    assert len(data.findings_by_sev["high"]) == 2
    assert len(data.findings_by_sev["low"]) == 1
    assert render_html(data, summary="", remediation="").startswith("<!doctype html>")


# ----------------------------- API flow ----------------------------------- #
@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("VAPT_DATABASE_URL", f"sqlite:///{tmp_path}/api.db")
    monkeypatch.setenv("VAPT_BOOTSTRAP_ADMIN_USER", "admin")
    monkeypatch.setenv("VAPT_BOOTSTRAP_ADMIN_PASSWORD", "pw12345")
    from vapt_api.config import get_settings

    get_settings.cache_clear()
    from vapt_api.main import create_app

    with TestClient(create_app()) as c:
        yield c


def test_report_api_flow(client):
    client.post("/api/v2/auth/session", json={"username": "admin", "password": "pw12345"})
    eng = client.post("/api/v2/engagements", json={
        "name": "Lab", "testing_mode": "black_box", "target_type": "web",
        "scope": {"domains": ["example.com"], "allowed_ports": [80]},
    })
    run = client.post("/api/v2/runs", json={"engagement_id": eng.json()["id"]})
    run_id = run.json()["id"]

    # No report yet.
    assert client.get(f"/api/v2/runs/{run_id}/report").status_code == 404

    # Generate one from current findings (zero is fine), then it is retrievable.
    gen = client.post(f"/api/v2/runs/{run_id}/report/regenerate")
    assert gen.status_code == 200, gen.text
    assert gen.json()["status"] == "draft"

    got = client.get(f"/api/v2/runs/{run_id}/report")
    assert got.status_code == 200 and got.json()["id"] == gen.json()["id"]

    # Download the HTML.
    dl = client.get(f"/api/v2/runs/{run_id}/report/download")
    assert dl.status_code == 200 and dl.headers["content-type"].startswith("text/html")
    assert "<!doctype html>" in dl.text

    # Sign off -> final (admin bypasses the reviewer-role check).
    so = client.post(f"/api/v2/runs/{run_id}/report/signoff")
    assert so.status_code == 200 and so.json()["status"] == "final"
    assert so.json()["signed_off_by"]
    # A second sign-off is a conflict.
    assert client.post(f"/api/v2/runs/{run_id}/report/signoff").status_code == 409
