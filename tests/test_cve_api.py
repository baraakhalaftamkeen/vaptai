"""CVE API: the feed and single-CVE lookup endpoints the CVEs page uses. NVD/KEV calls
are monkeypatched so CI never hits the network."""
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


def test_feed_endpoint(client, monkeypatch):
    import vapt_api.routers.cve as mod
    monkeypatch.setattr(mod, "cve_feed", lambda **kw: [
        {"id": "CVE-2026-0001", "score": 9.8, "severity": "critical",
         "published": "2026-10-10", "description": "RCE"},
    ])
    r = client.get("/api/v2/cve/feed?days=7&min_score=7")
    assert r.status_code == 200
    assert r.json()[0]["id"] == "CVE-2026-0001"


def test_lookup_endpoint_with_exploit(client, monkeypatch):
    import vapt_api.routers.cve as mod
    monkeypatch.setattr(mod, "lookup_cve", lambda cid: {
        "cve_id": "CVE-2021-41773", "cvss": 7.5, "vector": "CVSS:3.1/AV:N",
        "severity": "high", "description": "Path traversal", "references": ["https://x"]})
    monkeypatch.setattr(mod, "is_exploited", lambda cid, nvd_info=None: {
        "exploited": True, "basis": "CISA KEV — actively exploited in the wild"})
    r = client.get("/api/v2/cve/CVE-2021-41773")
    assert r.status_code == 200
    body = r.json()
    assert body["cvss"] == 7.5 and body["exploited"] is True and "KEV" in body["exploit_basis"]


def test_lookup_rejects_non_cve(client):
    assert client.get("/api/v2/cve/not-a-cve").status_code == 400


def test_lookup_404_when_unknown(client, monkeypatch):
    import vapt_api.routers.cve as mod
    monkeypatch.setattr(mod, "lookup_cve", lambda cid: {})
    assert client.get("/api/v2/cve/CVE-2000-9999").status_code == 404
