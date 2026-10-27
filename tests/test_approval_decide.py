"""The approval decide endpoint: approving updates the approval, enqueues a resume, and
returns the enriched 'what ran' detail — without the per-run event-seq crash."""
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


def _seed(client):
    # Create the engagement through the API so it lands in the default project the admin
    # is a member of (decide checks project membership). Then seed a paused run + approval.
    import vapt_persistence.db as dbmod
    from vapt_persistence.models import Approval, Run, ToolActionRecord
    r = client.post("/api/v2/engagements", json={
        "name": "L", "testing_mode": "black_box", "target_type": "network",
        "scope": {"ip_cidrs": ["172.25.188.23/32"]},
    })
    assert r.status_code == 201, r.text
    eng_id = r.json()["id"]

    s = dbmod.SessionLocal()
    run = Run(engagement_id=eng_id, thread_id="t", status="awaiting_approval", phase="attack")
    s.add(run); s.flush()
    a = Approval(run_id=run.id, action_digest="d1", policy_class="p1_low_impact", state="pending")
    s.add(a); s.flush()
    s.add(ToolActionRecord(run_id=run.id, tool_id="burp_request", profile_id="default",
                           args={"scheme": "http"}, target_ref="172.25.188.23",
                           action_digest="d1", idempotency_key="k1",
                           policy_class="p1_low_impact", state="proposed"))
    s.commit()
    ids = (run.id, a.id)
    s.close()
    return ids


def _resume_outbox(run_id):
    import vapt_persistence.db as dbmod
    from vapt_persistence.models import Outbox
    s = dbmod.SessionLocal()
    n = s.query(Outbox).filter_by(run_id=run_id, topic="run.resume").count()
    s.close()
    return n


def test_decide_approve_succeeds_and_enqueues_resume(client):
    run_id, appr_id = _seed(client)
    r = client.post(f"/api/v2/approvals/{appr_id}/decision", json={"decision": "approve"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["state"] in ("approved", "approved_batch")
    assert body["tool_id"] == "burp_request"       # enriched 'what ran'
    assert "172.25.188.23" in (body["target"] or "")
    assert _resume_outbox(run_id) == 1             # resume queued


def test_double_decide_second_is_conflict(client):
    _, appr_id = _seed(client)
    assert client.post(f"/api/v2/approvals/{appr_id}/decision", json={"decision": "approve"}).status_code == 200
    # A second decision on the same (now non-pending) approval is a clean 409, not a 500.
    assert client.post(f"/api/v2/approvals/{appr_id}/decision", json={"decision": "approve"}).status_code == 409
