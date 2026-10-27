"""End-to-end API test over the Week 1 vertical slice:
login -> create engagement -> create run (writes outbox) -> fetch run.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("VAPT_DATABASE_URL", f"sqlite:///{tmp_path}/api.db")
    monkeypatch.setenv("VAPT_BOOTSTRAP_ADMIN_USER", "admin")
    monkeypatch.setenv("VAPT_BOOTSTRAP_ADMIN_PASSWORD", "pw12345")
    # get_settings is cached; clear it so env takes effect.
    from vapt_api.config import get_settings

    get_settings.cache_clear()
    from vapt_api.main import create_app

    app = create_app()
    with TestClient(app) as c:
        yield c


def _login(client):
    r = client.post("/api/v2/auth/session", json={"username": "admin", "password": "pw12345"})
    assert r.status_code == 200, r.text
    return r


def test_health(client):
    assert client.get("/healthz").json()["status"] == "ok"


def test_login_required(client):
    assert client.get("/api/v2/engagements").status_code == 401


def test_full_slice(client):
    _login(client)

    me = client.get("/api/v2/auth/me").json()
    assert me["username"] == "admin"

    eng = client.post(
        "/api/v2/engagements",
        json={
            "name": "Lab web assessment",
            "testing_mode": "black_box",
            "target_type": "web",
            "scope": {"domains": ["example.com"], "allowed_ports": [80, 443]},
        },
    )
    assert eng.status_code == 201, eng.text
    eng_id = eng.json()["id"]

    run = client.post("/api/v2/runs", json={"engagement_id": eng_id})
    assert run.status_code == 201, run.text
    run_id = run.json()["id"]
    assert run.json()["status"] == "queued"

    got = client.get(f"/api/v2/runs/{run_id}")
    assert got.status_code == 200
    assert got.json()["engagement_id"] == eng_id


def test_invalid_login_rejected(client):
    r = client.post("/api/v2/auth/session", json={"username": "admin", "password": "wrong"})
    assert r.status_code == 401
