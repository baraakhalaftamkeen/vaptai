"""Cancelling a run must reach a terminal state (not hang in 'cancelling'): it rejects
pending approvals and marks the run CANCELLED, and also rescues a run already stuck in
'cancelling'."""
from __future__ import annotations

import pytest


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("VAPT_DATABASE_URL", f"sqlite:///{tmp_path}/api.db")
    monkeypatch.setenv("VAPT_BOOTSTRAP_ADMIN_PASSWORD", "pw12345")
    from vapt_api.config import get_settings
    get_settings.cache_clear()
    from fastapi.testclient import TestClient
    from vapt_api.main import create_app
    with TestClient(create_app()) as c:
        c.post("/api/v2/auth/session", json={"username": "admin", "password": "pw12345"})
        yield c


def _make_paused_run_with_approval(status: str):
    """Create an engagement + a run in `status` with one pending approval, directly in the
    DB the API is using."""
    import vapt_persistence.db as dbmod
    from vapt_persistence.models import Approval, Engagement, Project, Run
    s = dbmod.SessionLocal()
    p = s.query(Project).first() or Project(name="P")
    if p.id is None:
        s.add(p); s.flush()
    e = Engagement(project_id=p.id, name="L", testing_mode="black_box", target_type="network")
    s.add(e); s.flush()
    r = Run(engagement_id=e.id, thread_id="t", status=status, phase="attack",
            cancellation_requested=False)
    s.add(r); s.flush()
    a = Approval(run_id=r.id, action_digest="d1", policy_class="p2_intrusive", state="pending")
    s.add(a); s.flush()
    s.commit()
    rid, aid = r.id, a.id
    s.close()
    return rid, aid


def _run_status(run_id):
    import vapt_persistence.db as dbmod
    from vapt_persistence.models import Approval, Run
    s = dbmod.SessionLocal()
    run = s.get(Run, run_id)
    appr_states = [a.state for a in s.query(Approval).filter_by(run_id=run_id)]
    out = (run.status, run.phase, appr_states)
    s.close()
    return out


def test_cancel_paused_run_finalizes_and_rejects_approval(client):
    run_id, _ = _make_paused_run_with_approval("awaiting_approval")
    r = client.post(f"/api/v2/runs/{run_id}/cancel")
    assert r.status_code == 200
    status, phase, appr_states = _run_status(run_id)
    assert status == "cancelled" and phase == "cancelled"
    assert appr_states == ["rejected"]          # pending approval rejected


def test_cancel_rescues_stuck_cancelling_run(client):
    run_id, _ = _make_paused_run_with_approval("cancelling")
    r = client.post(f"/api/v2/runs/{run_id}/cancel")
    assert r.status_code == 200
    status, _, _ = _run_status(run_id)
    assert status == "cancelled"                # no longer stuck


def test_cancel_is_idempotent_on_terminal(client):
    run_id, _ = _make_paused_run_with_approval("completed")
    r = client.post(f"/api/v2/runs/{run_id}/cancel")
    assert r.status_code == 200
    status, _, _ = _run_status(run_id)
    assert status == "completed"                # already terminal — untouched
