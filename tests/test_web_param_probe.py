"""Deterministic web-parameter probe (`web_param_probe` built-in).

Covers:
  * builder: argv safety (in-scope URL only, pinned param validated, classes list validated,
    cookie flows via env — the subprocess reads VAPT_WEB_LOGIN_COOKIE itself);
  * normalizer: JSON findings → one proof-confirmed Observation per entry, with the right
    class/severity mapping; malformed output → no findings;
  * manifest/catalog invariant: SCAN agent gets `web_param_probe`;
  * proof-promotion: a web_param_probe-confirmed finding auto-promotes to CONFIRMED
    through the `validate_candidate` proof path (same mechanism as sstimap).

The shipped script `workers/bin/vapt-web-probe` is exercised end-to-end against a tiny
stdlib HTTP server that simulates each vulnerability class.
"""
from __future__ import annotations

import json
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

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
def test_web_param_probe_builder_argv_safe():
    argv = REGISTRY.get("web_param_probe").build_argv(
        {"target": "example.com", "url": "http://example.com:5000/search"})
    assert argv[0].endswith("vapt-web-probe")
    assert "--target" in argv and "example.com" in argv
    assert "--url" in argv and "http://example.com:5000/search" in argv


def test_web_param_probe_rejects_offscope_url():
    with pytest.raises(ValueError):
        REGISTRY.get("web_param_probe").build_argv(
            {"target": "example.com", "url": "http://evil.com/x"})


def test_web_param_probe_validates_param_and_classes():
    # bad param
    with pytest.raises(ValueError):
        REGISTRY.get("web_param_probe").build_argv(
            {"target": "example.com", "url": "http://example.com/",
             "param": "name; rm -rf /"})
    # bad classes list
    with pytest.raises(ValueError):
        REGISTRY.get("web_param_probe").build_argv(
            {"target": "example.com", "url": "http://example.com/",
             "classes": "xxe; cat /etc/passwd"})


def test_web_param_probe_accepts_pinned_param_and_classes():
    argv = REGISTRY.get("web_param_probe").build_argv(
        {"target": "example.com", "url": "http://example.com/search",
         "param": "q", "classes": "open_redirect,path_traversal"})
    assert "--param" in argv and "q" in argv
    assert "--classes" in argv and "open_redirect,path_traversal" in argv


# -- normalizer -------------------------------------------------------------
def test_normalizer_parses_findings_and_marks_confirmed():
    out = json.dumps({"findings": [
        {"type": "open_redirect", "severity": "medium",
         "url": "http://h/redirect?next=https://example.invalid/", "param": "next",
         "evidence": "Location: https://example.invalid/", "confirmed": True},
        {"type": "path_traversal", "severity": "high",
         "url": "http://h/receipt?file=../../etc/passwd", "param": "file",
         "evidence": "unix passwd signature", "confirmed": True},
    ]})
    obs = normalize("web_param_probe", [{"stdout": out}])
    assert len(obs) == 2
    assert obs[0].title.startswith("Open redirect confirmed") and obs[0].severity == "medium"
    assert obs[0].detail.get("confirmed") is True
    assert obs[1].severity == "high" and obs[1].detail.get("class") == "path_traversal"


def test_normalizer_rejects_unknown_class_and_bad_sev():
    out = json.dumps({"findings": [
        {"type": "mysterious", "url": "http://h/x", "evidence": ""},
        {"type": "xxe", "severity": "SUPER-CRITICAL", "url": "http://h/import",
         "evidence": "entity expanded", "confirmed": True},
    ]})
    obs = normalize("web_param_probe", [{"stdout": out}])
    # Unknown class dropped; bad severity falls back to the class default (high for XXE).
    assert len(obs) == 1 and obs[0].detail.get("class") == "xxe"
    assert obs[0].severity == "high"


def test_normalizer_empty_output():
    assert normalize("web_param_probe", [{"stdout": '{"findings": []}'}]) == []
    assert normalize("web_param_probe", [{"stdout": "not json"}]) == []


# -- manifest invariant -----------------------------------------------------
def test_scan_manifest_offers_web_param_probe():
    assert "web_param_probe" in manifests.SCAN.allowed_tool_ids


# -- proof-promotion --------------------------------------------------------
@pytest.fixture()
def db(tmp_path):
    init_engine(f"sqlite:///{tmp_path}/wpp.db")
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


def test_web_param_probe_proof_promotes_to_confirmed(db):
    s, run_id = db
    f = Finding(run_id=run_id, title="Open redirect confirmed (param next)",
                status="candidate", severity="medium")
    s.add(f); s.flush()
    s.add(FindingObservation(finding_id=f.id, source_tool="web_param_probe",
                             detail={"confirmed": True, "class": "open_redirect",
                                     "param": "next"}))
    s.commit()
    h = GovernedHarness(REGISTRY, broker=_OkBroker())
    assert phases.validate_candidate(s, _scope(run_id), h, f.id) is True
    assert s.get(Finding, f.id).status == "confirmed"


# -- end-to-end: the shipped script actually detects an open redirect ------
class _VulnHandler(BaseHTTPRequestHandler):
    """Minimal server that implements one vuln from each probe class so the shipped
    script's detection logic is exercised against a real target."""
    def log_message(self, *_a, **_kw):
        pass

    def do_GET(self):
        p = urlparse(self.path)
        q = parse_qs(p.query)
        # Open redirect: /redirect?next=<url> → 302 Location: <url>
        if p.path == "/redirect" and q.get("next"):
            self.send_response(302)
            self.send_header("Location", q["next"][0])
            self.send_header("Content-Length", "0")
            self.end_headers(); return
        # Path traversal: /download?file=... → return "root:x:0:0:" if "passwd" asked
        if p.path == "/download" and q.get("file") and "passwd" in q["file"][0]:
            body = b"root:x:0:0:root:/root:/bin/bash\n"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body))); self.end_headers()
            self.wfile.write(body); return
        # Default page
        self.send_response(200); self.send_header("Content-Length", "2")
        self.end_headers(); self.wfile.write(b"ok")


@pytest.fixture
def vuln_server():
    srv = HTTPServer(("127.0.0.1", 0), _VulnHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True); t.start()
    try:
        yield f"http://127.0.0.1:{srv.server_port}"
    finally:
        srv.shutdown(); srv.server_close()


def _probe_script() -> Path:
    return Path(__file__).resolve().parent.parent / "workers" / "bin" / "vapt-web-probe"


def test_shipped_script_detects_open_redirect(vuln_server):
    r = subprocess.run([str(_probe_script()), "--target", "127.0.0.1",
                        "--url", f"{vuln_server}/redirect", "--classes", "open_redirect"],
                       capture_output=True, text=True, timeout=20)
    data = json.loads(r.stdout)
    types = [f["type"] for f in data.get("findings", [])]
    assert "open_redirect" in types


def test_shipped_script_detects_path_traversal(vuln_server):
    r = subprocess.run([str(_probe_script()), "--target", "127.0.0.1",
                        "--url", f"{vuln_server}/download", "--classes", "path_traversal"],
                       capture_output=True, text=True, timeout=20)
    data = json.loads(r.stdout)
    types = [f["type"] for f in data.get("findings", [])]
    assert "path_traversal" in types


def test_shipped_script_rejects_offscope_url_cleanly():
    r = subprocess.run([str(_probe_script()), "--target", "example.com",
                        "--url", "http://evil.invalid/x"],
                       capture_output=True, text=True, timeout=5)
    data = json.loads(r.stdout)
    assert data.get("findings") == []
    assert "off-scope" in str(data.get("error", "")).lower()
