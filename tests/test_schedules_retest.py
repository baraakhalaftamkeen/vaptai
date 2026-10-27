"""Schedules + retest (BAR-29): the retest diff classifies fixed/still-open/new; the
beat tick fires a due schedule into a queued run + outbox; the API creates/lists/deletes
schedules and starts a retest run linked to its prior run."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
import vapt_persistence.db as dbmod
from fastapi.testclient import TestClient
from vapt_agents.retest import compare_runs
from vapt_persistence import Base, init_engine
from vapt_persistence.models import Engagement, Finding, Outbox, Project, Run, Schedule


@pytest.fixture()
def db(tmp_path):
    init_engine(f"sqlite:///{tmp_path}/sr.db")
    Base.metadata.create_all(dbmod.get_engine())
    s = dbmod.SessionLocal()
    p = Project(name="P"); s.add(p); s.flush()
    e = Engagement(project_id=p.id, name="Lab", testing_mode="black_box", target_type="web")
    s.add(e); s.flush()
    yield s, e.id
    s.close()


def _run_with(s, eng_id, titles):
    r = Run(engagement_id=eng_id, thread_id="t", status="completed"); s.add(r); s.flush()
    for t in titles:
        s.add(Finding(run_id=r.id, title=t, status="confirmed", severity="high"))
    s.flush()
    return r.id


def test_compare_runs_classifies_changes(db):
    s, eng_id = db
    prior = _run_with(s, eng_id, ["A", "B"])
    current = _run_with(s, eng_id, ["B", "C"])
    s.commit()
    res = compare_runs(s, current, prior)
    assert res.counts == {"fixed": 1, "still_open": 1, "new": 1}
    assert [f["title"] for f in res.fixed] == ["A"]
    assert [f["title"] for f in res.still_open] == ["B"]
    assert [f["title"] for f in res.new] == ["C"]


def test_tick_fires_due_schedule(db, monkeypatch, tmp_path):
    s, eng_id = db
    # A schedule already due.
    s.add(Schedule(engagement_id=eng_id, cron="every 60m", interval_minutes=60,
                   enabled=True, next_fire_at=datetime.now(UTC) - timedelta(minutes=1)))
    s.commit()

    # Point the task layer at THIS database.
    import vapt_orch.tasks as tasks
    monkeypatch.setattr(tasks, "_engine_ready", True)

    out = tasks.tick_schedules()
    assert out["fired"] == 1
    # A queued run + an outbox start intent now exist.
    assert s.query(Run).filter_by(engagement_id=eng_id, status="queued").count() == 1
    assert s.query(Outbox).filter_by(topic="run.start").count() == 1
    # The schedule advanced.
    sch = s.query(Schedule).first()
    assert sch.last_fired_at is not None and sch.next_fire_at > datetime.now(UTC).replace(tzinfo=sch.next_fire_at.tzinfo)


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("VAPT_DATABASE_URL", f"sqlite:///{tmp_path}/api.db")
    monkeypatch.setenv("VAPT_BOOTSTRAP_ADMIN_USER", "admin")
    monkeypatch.setenv("VAPT_BOOTSTRAP_ADMIN_PASSWORD", "pw12345")
    from vapt_api.config import get_settings

    get_settings.cache_clear()
    from vapt_api.main import create_app

    with TestClient(create_app()) as c:
        c.post("/api/v2/auth/session", json={"username": "admin", "password": "pw12345"})
        yield c


def _engagement(client) -> str:
    return client.post("/api/v2/engagements", json={
        "name": "Lab", "testing_mode": "black_box", "target_type": "web",
        "scope": {"domains": ["example.com"], "allowed_ports": [80]},
    }).json()["id"]


def test_schedule_api_crud(client):
    eng_id = _engagement(client)
    created = client.post(f"/api/v2/engagements/{eng_id}/schedules", json={"interval_minutes": 60})
    assert created.status_code == 201, created.text
    sid = created.json()["id"]
    assert created.json()["next_fire_at"]  # scheduled forward

    listed = client.get(f"/api/v2/engagements/{eng_id}/schedules")
    assert listed.status_code == 200 and len(listed.json()) == 1

    assert client.delete(f"/api/v2/engagements/{eng_id}/schedules/{sid}").status_code == 204
    assert client.get(f"/api/v2/engagements/{eng_id}/schedules").json() == []


def test_retest_api_links_and_compares(client):
    eng_id = _engagement(client)
    first = client.post("/api/v2/runs", json={"engagement_id": eng_id}).json()["id"]

    # The original run isn't a retest of anything.
    assert client.get(f"/api/v2/runs/{first}/retest").status_code == 404

    # Start a retest; the new run links back to the first.
    rt = client.post(f"/api/v2/runs/{first}/retest")
    assert rt.status_code == 201, rt.text
    retest_id = rt.json()["id"]
    assert retest_id != first

    cmp = client.get(f"/api/v2/runs/{retest_id}/retest")
    assert cmp.status_code == 200
    assert cmp.json()["prior_run_id"] == first
    assert cmp.json()["counts"] == {"fixed": 0, "still_open": 0, "new": 0}
