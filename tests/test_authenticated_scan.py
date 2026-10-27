"""Authenticated-scanning path (Tier-3): session cookie flows into every web tool.

Covers the two seams the auth build introduces:
  * tool builders inject a `Cookie:` header from the VAPT_WEB_LOGIN_COOKIE env var;
  * the login helper parses a login form, POSTs creds, and returns the session cookie.

Does NOT exercise a live target — the helper is tested against a tiny stdlib HTTP server
that mimics a form login with CSRF + sets a session cookie on POST.
"""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

import pytest
from vapt_agents import web_login
from vapt_tools import REGISTRY


# -- builder cookie injection ------------------------------------------------
@pytest.fixture
def with_cookie(monkeypatch):
    monkeypatch.setenv("VAPT_WEB_LOGIN_COOKIE", "sid=abc123")


@pytest.fixture
def no_cookie(monkeypatch):
    monkeypatch.delenv("VAPT_WEB_LOGIN_COOKIE", raising=False)


def _argv(spec_id: str, args: dict) -> list[str]:
    return REGISTRY.get(spec_id).build_argv(args)


def test_nuclei_builder_injects_cookie_header(with_cookie):
    argv = _argv("nuclei_safe", {"target": "example.com", "scheme": "http"})
    assert "-H" in argv and "Cookie: sid=abc123" in argv


def test_nuclei_dast_builder_injects_cookie_header(with_cookie):
    argv = _argv("nuclei_dast", {"target": "example.com", "scheme": "http"})
    assert "-H" in argv and "Cookie: sid=abc123" in argv


def test_arjun_builder_injects_cookie_as_headers(with_cookie):
    argv = _argv("arjun", {"target": "example.com", "url": "http://example.com/search"})
    assert "--headers" in argv and "Cookie: sid=abc123" in argv


def test_wapiti_builder_injects_cookie_header(with_cookie):
    argv = _argv("wapiti", {"target": "example.com", "scheme": "http"})
    assert argv[-2] == "-H" and argv[-1] == "Cookie: sid=abc123"


def test_katana_catalog_tool_injects_cookie_header(with_cookie):
    argv = _argv("katana", {"target": "example.com", "scheme": "http"})
    assert "-H" in argv and "Cookie: sid=abc123" in argv


def test_feroxbuster_catalog_tool_injects_cookie_header(with_cookie):
    argv = _argv("feroxbuster", {"target": "example.com", "scheme": "http"})
    assert "-H" in argv and "Cookie: sid=abc123" in argv


def test_no_cookie_env_no_header_appended(no_cookie):
    for tid in ("nuclei_safe", "nuclei_dast", "wapiti", "katana", "feroxbuster"):
        argv = _argv(tid, {"target": "example.com", "scheme": "http", "url": "http://example.com/x"}
                     if tid == "arjun" else {"target": "example.com", "scheme": "http"})
        assert not any(a.startswith("Cookie:") for a in argv)


def test_malformed_cookie_is_rejected(monkeypatch):
    """A newline/null in the cookie must never make it into argv — defence in depth around
    the Cookie header we build. The tool just runs unauthenticated instead of crashing."""
    monkeypatch.setenv("VAPT_WEB_LOGIN_COOKIE", "a=b\r\nX-Evil: 1")
    argv = _argv("nuclei_safe", {"target": "example.com", "scheme": "http"})
    assert not any("Cookie" in a for a in argv)


# -- login helper against a tiny stdlib server (no network) ------------------
class _LoginHandler(BaseHTTPRequestHandler):
    """GET /login returns an HTML form with a hidden CSRF token.
    POST /login validates (user, pass, csrf) and Set-Cookie: sid=…"""
    _CSRF = "tok-xyz"

    def log_message(self, *_a, **_kw):  # silence
        pass

    def do_GET(self):
        html = (f'<html><body><form method="POST" action="/login">'
                f'<input type="hidden" name="csrf" value="{self._CSRF}">'
                f'<input type="text" name="username">'
                f'<input type="password" name="password">'
                f'</form></body></html>').encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(html)))
        self.end_headers()
        self.wfile.write(html)

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        form = parse_qs(self.rfile.read(length).decode())
        ok = (form.get("username") == ["alice"]
              and form.get("password") == ["s3cret"]
              and form.get("csrf") == [self._CSRF])
        self.send_response(302 if ok else 401)
        if ok:
            self.send_header("Set-Cookie", "sid=cafebabe; Path=/")
            self.send_header("Location", "/")
        self.send_header("Content-Length", "0")
        self.end_headers()


@pytest.fixture
def login_server():
    srv = HTTPServer(("127.0.0.1", 0), _LoginHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{srv.server_port}/login"
    finally:
        srv.shutdown()
        srv.server_close()


def test_login_helper_posts_form_and_returns_cookie(login_server):
    cookie = web_login.obtain_session_cookie(login_server, "alice", "s3cret")
    assert cookie and "sid=cafebabe" in cookie


def test_login_helper_returns_none_on_bad_credentials(login_server):
    assert web_login.obtain_session_cookie(login_server, "alice", "wrong") is None


def test_login_helper_fails_safe_on_missing_inputs():
    assert web_login.obtain_session_cookie("", "u", "p") is None
    assert web_login.obtain_session_cookie("http://x/", "", "p") is None
    assert web_login.obtain_session_cookie("http://x/", "u", "") is None


def test_login_helper_rejects_offscope_redirect():
    """If the login POST redirects us to a different host, the helper refuses to use the
    resulting cookie — guards against an authentication endpoint pointing at a 3rd-party IdP
    that would route tool traffic (with its cookie) off-scope."""
    class _Offscope(BaseHTTPRequestHandler):
        def log_message(self, *_a, **_kw):
            pass

        def do_GET(self):
            self.send_response(200); self.send_header("Content-Length", "0"); self.end_headers()

        def do_POST(self):
            self.send_response(302)
            self.send_header("Set-Cookie", "sid=x; Path=/")
            self.send_header("Location", "http://example.invalid/")
            self.send_header("Content-Length", "0"); self.end_headers()

    srv = HTTPServer(("127.0.0.1", 0), _Offscope)
    t = threading.Thread(target=srv.serve_forever, daemon=True); t.start()
    try:
        url = f"http://127.0.0.1:{srv.server_port}/login"
        # requests will fail the actual redirect (DNS invalid) → helper returns None.
        assert web_login.obtain_session_cookie(url, "a", "b") is None
    finally:
        srv.shutdown(); srv.server_close()
