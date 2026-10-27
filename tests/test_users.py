"""User administration: admins create portal users, set roles, and deactivate; the
endpoints are admin-only and guard against self-lockout."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("VAPT_DATABASE_URL", f"sqlite:///{tmp_path}/users.db")
    monkeypatch.setenv("VAPT_BOOTSTRAP_ADMIN_USER", "admin")
    monkeypatch.setenv("VAPT_BOOTSTRAP_ADMIN_PASSWORD", "pw12345")
    from vapt_api.config import get_settings
    get_settings.cache_clear()
    from vapt_api.main import create_app
    with TestClient(create_app()) as c:
        yield c


def _login(c, username, password):
    return c.post("/api/v2/auth/session", json={"username": username, "password": password})


def test_admin_user_lifecycle(client):
    assert _login(client, "admin", "pw12345").status_code == 200

    # Admin sees at least themselves.
    users = client.get("/api/v2/users")
    assert users.status_code == 200
    assert any(u["username"] == "admin" and u["role"] == "admin" for u in users.json())

    # Create an analyst.
    created = client.post("/api/v2/users", json={
        "username": "alice", "password": "alicepw123", "role": "analyst"})
    assert created.status_code == 201, created.text
    alice_id = created.json()["id"]
    assert created.json()["role"] == "analyst" and created.json()["is_active"] is True

    # Duplicate username is a conflict.
    assert client.post("/api/v2/users", json={
        "username": "alice", "password": "x2345678", "role": "viewer"}).status_code == 409

    # Promote to lead, then deactivate.
    assert client.patch(f"/api/v2/users/{alice_id}", json={"role": "lead"}).json()["role"] == "lead"
    assert client.patch(f"/api/v2/users/{alice_id}", json={"is_active": False}).json()["is_active"] is False

    # Admin can't lock themselves out.
    me = client.get("/api/v2/auth/me").json()
    assert client.patch(f"/api/v2/users/{me['id']}", json={"is_active": False}).status_code == 400


def test_non_admin_cannot_manage_users(client):
    _login(client, "admin", "pw12345")
    client.post("/api/v2/users", json={"username": "bob", "password": "bobpw1234", "role": "analyst"})

    # Bob (analyst) may not list or create users.
    assert _login(client, "bob", "bobpw1234").status_code == 200
    assert client.get("/api/v2/users").status_code == 403
    assert client.post("/api/v2/users", json={
        "username": "mallory", "password": "mallory123", "role": "admin"}).status_code == 403


def test_password_and_role_validation(client):
    _login(client, "admin", "pw12345")
    assert client.post("/api/v2/users", json={
        "username": "shortpw", "password": "short", "role": "analyst"}).status_code == 422
    assert client.post("/api/v2/users", json={
        "username": "baduser", "password": "longenough1", "role": "superuser"}).status_code == 422
