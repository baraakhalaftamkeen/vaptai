"""Authenticated-scanning helper: POST credentials to a discovered login form and
return the resulting session cookie string ("name=value; name2=value2").

The webvuln phase caches that cookie once per run (via `web_credentials.set_web_cookie`)
so every subsequent tool (katana / arjun / nuclei / feroxbuster / sqli_detect / wapiti
re-runs) reuses it instead of re-posting the password. Credentials themselves live only
in Redis under the short-TTL slot; the cookie is derived state and treated the same way
(TTL, never persisted to SQL / outbox / checkpoint / ledger).

Fail-safe design — EVERY failure path returns None so an authentication issue degrades
the scan to UNAUTHENTICATED (same thing it did before) rather than crashing the graph:
  * login URL is not resolvable / off-scope
  * network error, redirect loop, timeout
  * server returns no session cookie (e.g. token-based auth, 2FA, CAPTCHA)
  * credentials are wrong (login form re-displayed, no new cookie set)

Nothing in the auth response is written to logs or the ledger — only "we did/didn't
obtain a cookie" is auditable upstream.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

# Common names of the username/password form fields, in preference order. The login
# helper probes GET /login first, parses any form with a password input, and uses the
# detected names; this list is the fallback when the form can't be parsed.
_USER_FIELD_HINTS = ("username", "user", "email", "login", "u", "name")
_PASS_FIELD_HINTS = ("password", "pass", "pwd", "p")

_INPUT_RE = re.compile(
    r"""<input\b[^>]*?\bname\s*=\s*["']([^"']+)["'][^>]*?\btype\s*=\s*["']([^"']+)["']"""
    r"""|<input\b[^>]*?\btype\s*=\s*["']([^"']+)["'][^>]*?\bname\s*=\s*["']([^"']+)["']""",
    re.IGNORECASE,
)
_FORM_ACTION_RE = re.compile(
    r"""<form\b[^>]*?\baction\s*=\s*["']([^"']*)["']""",
    re.IGNORECASE,
)


def _detect_form_fields(html: str) -> tuple[str, str]:
    """Best-effort parse of a login form: return (user_field, pass_field). Falls back to
    the most common names if the form isn't parseable. We intentionally avoid pulling in a
    full HTML parser dependency — a login form is a tiny, well-known structure."""
    user_field = ""
    pass_field = ""
    for m in _INPUT_RE.finditer(html or ""):
        # The regex has two alternatives; one branch populates groups (1,2), the other (3,4).
        name = (m.group(1) or m.group(4) or "").lower()
        itype = (m.group(2) or m.group(3) or "").lower()
        if itype == "password" and not pass_field:
            pass_field = name
        elif itype in ("text", "email") and not user_field:
            user_field = name
    if not user_field:
        for h in _USER_FIELD_HINTS:
            if h in (html or "").lower():
                user_field = h
                break
        else:
            user_field = _USER_FIELD_HINTS[0]
    if not pass_field:
        pass_field = _PASS_FIELD_HINTS[0]
    return user_field, pass_field


def _detect_form_action(html: str, login_url: str) -> str:
    """Resolve the form's action= against the login URL; if absent, post back to login_url."""
    m = _FORM_ACTION_RE.search(html or "")
    if not m or not m.group(1).strip():
        return login_url
    action = m.group(1).strip()
    return urljoin(login_url, action)


def obtain_session_cookie(login_url: str, username: str, password: str,
                          *, timeout_s: int = 15) -> str | None:
    """POST credentials to the discovered login URL and return a serialized Cookie string
    (e.g. "session=abc123; csrftoken=xyz") that other tools can send as a Cookie header.
    Returns None on any failure — never raises."""
    if not (login_url and username and password):
        return None
    if not login_url.lower().startswith(("http://", "https://")):
        return None
    try:
        import requests  # type: ignore
    except Exception:
        return None

    try:
        sess = requests.Session()
        # GET first so we pick up any CSRF/anti-forgery cookie the server sets.
        # Use the FINAL url after redirects (e.g. HTTP→HTTPS 301) so the POST
        # goes directly to the right scheme and nginx doesn't 301-downgrade it
        # from POST to GET (RFC 7231: user agents MAY change POST→GET on 301).
        effective_login_url = login_url
        try:
            r = sess.get(login_url, timeout=timeout_s, allow_redirects=True)
            html = r.text if r.ok else ""
            if r.url:
                effective_login_url = r.url
        except Exception:
            html = ""
        user_field, pass_field = _detect_form_fields(html)
        action = _detect_form_action(html, effective_login_url)
        # Pull any hidden fields (CSRF token etc.) so the POST matches what the browser would send.
        hidden = {}
        for m in _INPUT_RE.finditer(html):
            name = (m.group(1) or m.group(4) or "").strip()
            itype = (m.group(2) or m.group(3) or "").lower().strip()
            if name and itype == "hidden":
                # value extraction is best-effort — many forms set via JS
                vm = re.search(
                    rf"""<input\b[^>]*?\bname\s*=\s*["']{re.escape(name)}["'][^>]*?\bvalue\s*=\s*["']([^"']*)["']""",
                    html, re.IGNORECASE)
                hidden[name] = vm.group(1) if vm else ""

        data = {user_field: username, pass_field: password, **hidden}
        host_before = urlparse(effective_login_url).hostname
        resp = sess.post(action, data=data, timeout=timeout_s, allow_redirects=True)
        # Stay in-scope: the login must not redirect us off-host (a safety guard, not auth proof).
        if urlparse(resp.url).hostname != host_before:
            return None
        # Cookies exist on any POST (server always sets a session cookie), so cookie-presence
        # alone is not auth proof — a bad-creds response that re-renders the login form would
        # also carry a fresh session cookie.
        if not sess.cookies:
            return None

        def _is_login_path(u: str) -> bool:
            low = (u or "").lower()
            return any(w in low for w in ("/login", "/signin", "/sign_in", "/auth/log"))

        # A logout affordance is the single most reliable cross-app proof of an
        # authenticated session: authenticated pages expose a "Logout"/"Sign out"
        # link, unauthenticated pages a "Login"/"Sign in" one. This replaces the
        # old "does /login still show a password field?" heuristic, which
        # false-negatived on every app that renders the login form even when
        # logged in (DineHub does exactly this: GET /auth/login returns 200 with
        # the password input present whether or not you hold a valid session, so
        # the old check concluded "not logged in" for a perfectly good session).
        _LOGOUT_RE = re.compile(
            r"""href\s*=\s*["'][^"']*/(?:auth/)?(?:logout|signout|sign[_-]?out|log[_-]?out)\b"""
            r"""|>\s*(?:logout|log\s*out|sign\s*out)\s*<""",
            re.IGNORECASE)
        # An explicit bad-credentials alert is a hard failure signal — short-circuit
        # so a reflected login form never gets mistaken for success.
        _BADCREDS_RE = re.compile(
            r"""invalid\s+credentials|incorrect\s+(?:password|username|login)"""
            r"""|login\s+failed|authentication\s+failed|wrong\s+password"""
            r"""|user\s+not\s+found""",
            re.IGNORECASE)

        def _looks_authenticated(html: str) -> bool:
            return bool(html) and bool(_LOGOUT_RE.search(html))

        # Hard fail: the POST response itself says the credentials were rejected.
        if _BADCREDS_RE.search(resp.text or ""):
            return None

        login_ok = False
        # Signal A: did the POST produce a redirect to a non-login URL? (strong)
        if resp.history and any(h.status_code in (301, 302, 303, 307, 308)
                                 for h in resp.history):
            final_path = urlparse(resp.url).path or "/"
            if not _is_login_path(final_path):
                login_ok = True

        # Signal B: the POST RESPONSE BODY already shows an authenticated nav
        # (logout link). Many apps render the landing page inline after a 200
        # login rather than redirecting.
        if not login_ok and _looks_authenticated(resp.text or ""):
            login_ok = True

        # Signal C: fetch the SITE ROOT with the session and look for the logout
        # affordance. This is the robust verification — independent of whether the
        # login endpoint redirects or re-renders its own form. Only runs if A/B
        # didn't already confirm.
        if not login_ok:
            try:
                p = urlparse(login_url)
                root = f"{p.scheme}://{p.netloc}/"
                vr = sess.get(root, timeout=timeout_s, allow_redirects=True)
                if _looks_authenticated(vr.text or ""):
                    login_ok = True
            except Exception:
                pass

        # Signal D (legacy fallback): re-GET the login URL; a redirect AWAY from
        # the login path still counts. Kept for apps that bounce authenticated
        # users off /login.
        if not login_ok:
            try:
                verify = sess.get(login_url, timeout=timeout_s, allow_redirects=False)
                if verify.status_code in (301, 302, 303, 307, 308):
                    loc = verify.headers.get("Location", "")
                    if loc and not _is_login_path(loc):
                        login_ok = True
            except Exception:
                pass

        if not login_ok:
            return None
        # Serialize all cookies for in-scope hosts to a single Cookie header value.
        parts: list[str] = []
        for c in sess.cookies:
            # Only use host-scoped cookies (skip cross-site / unrelated ones).
            if c.domain and c.domain not in (host_before, f".{host_before}"):
                continue
            if c.name and c.value is not None:
                parts.append(f"{c.name}={c.value}")
        return "; ".join(parts) if parts else None
    except Exception:
        return None
