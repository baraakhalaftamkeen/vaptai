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
        # Preserve the original field name (servers may be case-sensitive, e.g. "userName").
        name = (m.group(1) or m.group(4) or "")
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

        # Two-step login support: if the first POST redirected to a page that
        # contains a password field (but we haven't set a session cookie yet),
        # the app uses a username-first flow (like XBEN-001-24, Microsoft,
        # Google). POST the password to this second form to complete login.
        if not sess.cookies or not any(c.value for c in sess.cookies):
            step2_html = resp.text or ""
            step2_pass_fields = [
                m for m in _INPUT_RE.finditer(step2_html)
                if (m.group(2) or m.group(3) or "").lower() == "password"
            ]
            if step2_pass_fields and resp.url != effective_login_url:
                s2_user_f, s2_pass_f = _detect_form_fields(step2_html)
                s2_action = _detect_form_action(step2_html, resp.url)
                s2_hidden = {}
                for m in _INPUT_RE.finditer(step2_html):
                    name = (m.group(1) or m.group(4) or "").strip()
                    itype = (m.group(2) or m.group(3) or "").lower().strip()
                    if name and itype == "hidden":
                        vm = re.search(
                            rf"""<input\b[^>]*?\bname\s*=\s*["']{re.escape(name)}["'][^>]*?\bvalue\s*=\s*["']([^"']*)["']""",
                            step2_html, re.IGNORECASE)
                        s2_hidden[name] = vm.group(1) if vm else ""
                s2_data = {s2_pass_f: password, **s2_hidden}
                if s2_user_f and s2_user_f != s2_pass_f:
                    s2_data[s2_user_f] = username
                resp = sess.post(s2_action, data=s2_data, timeout=timeout_s,
                                 allow_redirects=True)
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
            # The requests library may resolve "localhost" to "localhost.local",
            # so also accept domains that start with the target host.
            if c.domain and c.domain not in (host_before, f".{host_before}"):
                if not (host_before and c.domain.startswith(host_before)):
                    continue
            if c.name and c.value is not None:
                parts.append(f"{c.name}={c.value}")
        return "; ".join(parts) if parts else None
    except Exception:
        return None


_REG_PATH_HINTS = (
    "/register", "/signup", "/sign-up", "/sign_up",
    "/auth/register", "/auth/signup", "/account/register",
    "/accounts/register", "/user/register", "/users/register",
    "/api/register", "/api/signup", "/api/auth/register",
    "/create-account", "/join",
)

_REG_FIELD_RE = re.compile(
    r"""<input\b[^>]*?\bname\s*=\s*["']([^"']+)["'][^>]*?\btype\s*=\s*["']([^"']+)["']"""
    r"""|<input\b[^>]*?\btype\s*=\s*["']([^"']+)["'][^>]*?\bname\s*=\s*["']([^"']+)["']""",
    re.IGNORECASE,
)


def _detect_register_form(html: str, page_url: str
                          ) -> tuple[str, dict[str, str]] | None:
    """Parse a registration page for form action + field names.
    Returns (action_url, {field_name: field_type}) or None."""
    if not html:
        return None
    fields: dict[str, str] = {}
    has_password = False
    for m in _REG_FIELD_RE.finditer(html):
        name = (m.group(1) or m.group(4) or "").strip()
        itype = (m.group(2) or m.group(3) or "").lower().strip()
        if not name or itype in ("hidden", "submit", "button", "image"):
            continue
        fields[name] = itype
        if itype == "password":
            has_password = True
    if not has_password or len(fields) < 2:
        return None
    action = _detect_form_action(html, page_url)
    hidden = {}
    for m in _REG_FIELD_RE.finditer(html):
        name = (m.group(1) or m.group(4) or "").strip()
        itype = (m.group(2) or m.group(3) or "").lower().strip()
        if name and itype == "hidden":
            vm = re.search(
                rf"""<input\b[^>]*?\bname\s*=\s*["']{re.escape(name)}["'][^>]*?\bvalue\s*=\s*["']([^"']*)["']""",
                html, re.IGNORECASE)
            hidden[name] = vm.group(1) if vm else ""
    fields.update({k: "hidden" for k in hidden})
    return action, fields


def _guess_field_values(fields: dict[str, str], username: str, password: str
                        ) -> dict[str, str]:
    """Map detected field names to plausible registration values."""
    data: dict[str, str] = {}
    _user_names = {"username", "user", "login", "name", "user_name", "uname"}
    _email_names = {"email", "e-mail", "mail", "email_address", "user_email"}
    _pass_names = {"password", "pass", "pwd", "passwd", "user_password"}
    _confirm_names = {"password2", "confirm_password", "password_confirm",
                      "confirm", "pass2", "re_password", "password_confirmation",
                      "confirmPassword", "repassword"}
    _fname_names = {"first_name", "firstname", "fname", "first"}
    _lname_names = {"last_name", "lastname", "lname", "last"}
    for name, ftype in fields.items():
        low = name.lower().replace("-", "_")
        if ftype == "hidden":
            continue
        if low in _user_names or ftype == "text" and "user" in low:
            data[name] = username
        elif low in _email_names or ftype == "email":
            data[name] = f"{username}@test.local"
        elif low in _confirm_names:
            data[name] = password
        elif low in _pass_names or ftype == "password":
            data[name] = password
        elif low in _fname_names:
            data[name] = "Test"
        elif low in _lname_names:
            data[name] = "User"
        elif ftype in ("text", "tel"):
            data[name] = username
    return data


def try_self_register(base_url: str, *, timeout_s: int = 15
                      ) -> tuple[str, str, str] | None:
    """Attempt to self-register on the target app.
    Returns (login_url, username, password) on success, None on failure."""
    import secrets
    try:
        import requests  # type: ignore
    except Exception:
        return None

    username = f"vapttest{secrets.token_hex(4)}"
    password = f"VaptT3st!{secrets.token_hex(4)}"
    base = base_url.rstrip("/")

    try:
        sess = requests.Session()
        for path in _REG_PATH_HINTS:
            reg_url = base + path
            try:
                r = sess.get(reg_url, timeout=timeout_s, allow_redirects=True)
            except Exception:
                continue
            if r.status_code != 200:
                continue
            result = _detect_register_form(r.text, r.url)
            if not result:
                continue
            action, fields = result
            # Pull hidden field values from the actual page
            hidden_vals: dict[str, str] = {}
            for m in _REG_FIELD_RE.finditer(r.text):
                nm = (m.group(1) or m.group(4) or "").strip()
                tp = (m.group(2) or m.group(3) or "").lower().strip()
                if nm and tp == "hidden":
                    vm = re.search(
                        rf"""<input\b[^>]*?\bname\s*=\s*["']{re.escape(nm)}["'][^>]*?\bvalue\s*=\s*["']([^"']*)["']""",
                        r.text, re.IGNORECASE)
                    hidden_vals[nm] = vm.group(1) if vm else ""
            data = _guess_field_values(fields, username, password)
            data.update(hidden_vals)
            if not data:
                continue
            # POST the registration
            try:
                resp = sess.post(action, data=data, timeout=timeout_s,
                                 allow_redirects=True)
            except Exception:
                continue
            # Registration succeeded if: redirect to non-register page, or
            # 200/201 without error messages
            _ERR_RE = re.compile(
                r"already\s+exists|already\s+taken|already\s+registered"
                r"|invalid|error|failed|please\s+try\s+again",
                re.IGNORECASE)
            if resp.status_code in (200, 201, 302, 303):
                if _ERR_RE.search(resp.text or ""):
                    continue
                # Try to find the login URL from the same base
                _login_paths = ("/auth/login", "/login", "/signin",
                                "/sign-in", "/account/login", "/users/sign_in")
                for lp in _login_paths:
                    login_url = base + lp
                    cookie = obtain_session_cookie(login_url, username, password,
                                                   timeout_s=timeout_s)
                    if cookie:
                        return login_url, username, password
                # Also try email-based login
                cookie = obtain_session_cookie(
                    login_url, f"{username}@test.local", password,
                    timeout_s=timeout_s)
                if cookie:
                    return login_url, f"{username}@test.local", password
    except Exception:
        pass
    return None
