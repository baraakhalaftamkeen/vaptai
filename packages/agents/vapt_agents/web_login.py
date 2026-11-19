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

_REG_STEP_SUFFIXES = (
    "/step1", "/step1/", "/step/1", "/1",
    "/new", "/start", "/begin",
)

_LOGIN_PATH_HINTS = (
    "/auth/login", "/login", "/signin", "/sign-in",
    "/account/login", "/accounts/login", "/accounts/signin",
    "/users/sign_in", "/user/login", "/",
)

_REG_FIELD_RE = re.compile(
    r"""<input\b[^>]*?\bname\s*=\s*["']([^"']+)["'][^>]*?\btype\s*=\s*["']([^"']+)["']"""
    r"""|<input\b[^>]*?\btype\s*=\s*["']([^"']+)["'][^>]*?\bname\s*=\s*["']([^"']+)["']""",
    re.IGNORECASE,
)

_REG_KEYWORDS = frozenset({
    "register", "signup", "sign-up", "sign_up", "create-account",
    "create_account", "join", "new-account", "new_account", "enroll",
})

_REG_ERR_RE = re.compile(
    r"already\s+exists|already\s+taken|already\s+registered"
    r"|invalid|error|failed|please\s+try\s+again",
    re.IGNORECASE,
)

_SELECT_RE = re.compile(
    r'<select\b[^>]*?\bname\s*=\s*["\']([^"\']+)["\'][^>]*>(.*?)</select>',
    re.IGNORECASE | re.DOTALL,
)
_OPTION_VAL_RE = re.compile(
    r'<option\b[^>]*?\bvalue\s*=\s*["\']([^"\']*)["\']', re.IGNORECASE,
)


def _discover_registration_urls(sess, base_url: str, timeout_s: int) -> list[str]:
    """Crawl the target's homepage and login page to discover registration links.
    Looks for <a href="..."> where the href or the anchor text contains registration
    keywords. Returns a de-duplicated list of absolute URLs in discovery order."""
    urls: list[str] = []
    seen: set[str] = set()
    base_host = urlparse(base_url).hostname

    _ANCHOR_RE = re.compile(
        r'<a\b[^>]*\bhref\s*=\s*["\']([^"\']*)["\'][^>]*>(.*?)</a>',
        re.IGNORECASE | re.DOTALL,
    )

    pages = [base_url + "/"]
    for lp in ("/login", "/auth/login", "/signin"):
        pages.append(base_url + lp)

    for page_url in pages:
        try:
            r = sess.get(page_url, timeout=timeout_s, allow_redirects=True)
            if r.status_code != 200:
                continue
        except Exception:
            continue
        for m in _ANCHOR_RE.finditer(r.text):
            href = m.group(1).strip()
            text = re.sub(r'<[^>]+>', '', m.group(2)).strip().lower()
            if not href or href.startswith(('#', 'javascript:')):
                continue
            href_low = href.lower()
            hit = (any(kw in href_low for kw in _REG_KEYWORDS)
                   or any(kw.replace('-', ' ').replace('_', ' ') in text
                          for kw in _REG_KEYWORDS))
            if not hit:
                continue
            full = urljoin(r.url, href)
            if urlparse(full).hostname != base_host:
                continue
            if full not in seen:
                urls.append(full)
                seen.add(full)
    return urls


def _detect_register_form(html: str, page_url: str
                          ) -> tuple[str, dict[str, str]] | None:
    """Parse a registration page for form action + field names.
    Requires at least one password field and 2+ visible fields.
    Returns (action_url, {field_name: field_type}) or None."""
    return _detect_form(html, page_url, require_password=True, min_fields=2)


def _detect_any_form(html: str, page_url: str
                     ) -> tuple[str, dict[str, str]] | None:
    """Relaxed form detector for multi-step registration (later steps may lack
    a password field). Requires at least 1 visible field."""
    return _detect_form(html, page_url, require_password=False, min_fields=1)


def _detect_form(html: str, page_url: str, *,
                 require_password: bool, min_fields: int
                 ) -> tuple[str, dict[str, str]] | None:
    """Core form parser shared by the strict and relaxed detectors."""
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
    # Also pick up <select> elements (dropdowns like "is_premium", "role", etc.)
    for sm in _SELECT_RE.finditer(html):
        sel_name = sm.group(1).strip()
        if sel_name and sel_name not in fields:
            fields[sel_name] = "select"
    if require_password and not has_password:
        return None
    visible = {k: v for k, v in fields.items() if v != "hidden"}
    if len(visible) < min_fields:
        return None
    action = _detect_form_action(html, page_url)
    hidden: dict[str, str] = {}
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


def _guess_field_values(fields: dict[str, str], username: str, password: str,
                        html: str = "") -> dict[str, str]:
    """Map detected field names to plausible registration values.
    Handles inputs, selects, checkboxes, and radio buttons."""
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
        if low in _user_names or (ftype == "text" and "user" in low):
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
        elif ftype == "checkbox":
            data[name] = "on"
        elif ftype == "select":
            # Pick first non-empty option value from the HTML
            first_val = _first_select_option(html, name)
            data[name] = first_val if first_val else "1"
        elif ftype in ("text", "tel"):
            data[name] = username
        elif ftype == "number":
            data[name] = "1"
    return data


def _first_select_option(html: str, field_name: str) -> str:
    """Extract the first non-empty <option value> for a <select name=field_name>."""
    for sm in _SELECT_RE.finditer(html):
        if sm.group(1).strip() == field_name:
            for om in _OPTION_VAL_RE.finditer(sm.group(2)):
                val = om.group(1).strip()
                if val:
                    return val
    return ""


def _llm_map_fields(gateway, html: str, fields: dict[str, str],
                     username: str, password: str) -> dict[str, str] | None:
    """Use the LLM gateway to map form fields to registration values when
    heuristic mapping covers fewer than half the visible fields. Returns a
    field→value dict or None on failure. The gateway parameter is optional —
    callers that don't have an LLM gateway pass None and this is never called."""
    import json as _json
    try:
        visible = {k: v for k, v in fields.items() if v != "hidden"}
        form_area = html[:3000] if html else ""

        prompt = (
            "You are helping fill a web registration form to create a test account.\n"
            f"Form fields (name → type): {_json.dumps(visible)}\n\n"
            f"HTML context (first 3000 chars):\n{form_area}\n\n"
            "Map each field to a value for a test account:\n"
            f"- Username/login → \"{username}\"\n"
            f"- Email → \"{username}@test.local\"\n"
            f"- Password → \"{password}\"\n"
            "- First name → \"Test\", Last name → \"User\"\n"
            "- Phone → \"5551234567\"\n"
            "- Checkbox/boolean → \"on\" or \"true\"\n"
            "- Select/dropdown → first non-empty option value\n"
            "- Other → reasonable test value\n\n"
            "Return ONLY a JSON object mapping field names to string values."
        )
        resp = gateway.invoke(
            "fast",
            [{"role": "user", "content": prompt}],
            output_schema={
                "type": "object",
                "additionalProperties": {"type": "string"},
            },
        )
        if resp.parsed and isinstance(resp.parsed, dict):
            return {k: str(v) for k, v in resp.parsed.items()}
    except Exception:
        pass
    return None


def _try_register_at_url(sess, reg_url: str, base: str,
                          username: str, password: str, timeout_s: int,
                          gateway=None, max_steps: int = 5
                          ) -> tuple[str, str, str] | None:
    """Attempt registration at a single URL, handling multi-step flows.
    Returns (login_url, username, password) on success, None on failure."""
    import logging as _log_mod
    _lg = _log_mod.getLogger("vapt.web_login")
    try:
        r = sess.get(reg_url, timeout=timeout_s, allow_redirects=True)
    except Exception as _ge:
        _lg.debug("_try_register GET %s failed: %s", reg_url, _ge)
        return None
    if r.status_code != 200:
        return None

    current_url = r.url
    current_html = r.text

    for step in range(max_steps):
        if step == 0:
            form_result = _detect_register_form(current_html, current_url)
        else:
            form_result = _detect_any_form(current_html, current_url)
        if not form_result:
            _lg.debug("_try_register step=%d no form at %s", step, current_url)
            if step > 0:
                break
            return None

        action, fields = form_result
        data = _guess_field_values(fields, username, password, html=current_html)

        # LLM fallback: when heuristics mapped fewer than half the visible fields
        visible_count = sum(1 for v in fields.values() if v != "hidden")
        if gateway and visible_count > 0 and len(data) < (visible_count + 1) // 2:
            llm_data = _llm_map_fields(gateway, current_html, fields,
                                        username, password)
            if llm_data:
                for k, v in llm_data.items():
                    if k not in data and k in fields:
                        data[k] = v

        # Merge hidden fields
        for m in _REG_FIELD_RE.finditer(current_html):
            nm = (m.group(1) or m.group(4) or "").strip()
            tp = (m.group(2) or m.group(3) or "").lower().strip()
            if nm and tp == "hidden":
                vm = re.search(
                    rf"""<input\b[^>]*?\bname\s*=\s*["']{re.escape(nm)}["'][^>]*?\bvalue\s*=\s*["']([^"']*)["']""",
                    current_html, re.IGNORECASE)
                data[nm] = vm.group(1) if vm else ""

        if not data:
            _lg.debug("_try_register step=%d no data for %s", step, current_url)
            break

        try:
            resp = sess.post(action, data=data, timeout=timeout_s,
                             allow_redirects=True)
        except Exception as _pe:
            _lg.debug("_try_register POST %s failed: %s", action, _pe)
            break

        _lg.debug("_try_register step=%d POST %s -> %d url=%s",
                   step, action, resp.status_code, resp.url)

        if resp.status_code not in (200, 201, 302, 303):
            break
        if _REG_ERR_RE.search(resp.text or ""):
            _err_m = _REG_ERR_RE.search(resp.text or "")
            _lg.debug("_try_register step=%d err_re matched: %s",
                       step, _err_m.group() if _err_m else "")
            break

        # Multi-step: if the response has another form on a different URL, continue
        if resp.url != current_url:
            next_form = (_detect_register_form(resp.text, resp.url)
                         or _detect_any_form(resp.text, resp.url))
            if next_form:
                current_url = resp.url
                current_html = resp.text
                continue

        # Registration appears complete — try to log in
        _lg.debug("_try_register complete at step=%d, trying login", step)
        return _try_login_after_register(base, username, password, timeout_s)

    # Exhausted steps but may still have registered — try login
    _lg.debug("_try_register exhausted steps, trying login anyway")
    return _try_login_after_register(base, username, password, timeout_s)


def _try_login_after_register(base: str, username: str, password: str,
                               timeout_s: int) -> tuple[str, str, str] | None:
    """After a registration attempt, try logging in with common login paths."""
    for lp in _LOGIN_PATH_HINTS:
        login_url = base + lp
        cookie = obtain_session_cookie(login_url, username, password,
                                       timeout_s=timeout_s)
        if cookie:
            return login_url, username, password
    # Also try email-based login
    for lp in _LOGIN_PATH_HINTS:
        login_url = base + lp
        cookie = obtain_session_cookie(login_url, f"{username}@test.local",
                                       password, timeout_s=timeout_s)
        if cookie:
            return login_url, f"{username}@test.local", password
    return None


_last_registration_urls: list[str] = []


def get_last_registration_urls() -> list[str]:
    """Return registration URLs discovered during the last successful
    self-registration.  These are URLs that returned HTTP 200 and
    contained a form — useful for feeding into SSTI/injection scans
    since registration forms are often not linked from the main site."""
    return list(_last_registration_urls)


def try_self_register(base_url: str, *, timeout_s: int = 15,
                      gateway=None) -> tuple[str, str, str] | None:
    """Attempt to self-register on the target app.

    Discovery strategy:
    1. Crawl the homepage + login page for links containing registration keywords
    2. Probe well-known registration paths as fallback
    3. For each discovered URL, attempt multi-step registration with heuristic
       field mapping (and optional LLM fallback via gateway).

    Returns (login_url, username, password) on success, None on failure.
    """
    global _last_registration_urls
    _last_registration_urls = []
    import secrets
    try:
        import requests  # type: ignore
    except Exception:
        return None

    username = f"vapttest{secrets.token_hex(4)}"
    password = f"VaptT3st!{secrets.token_hex(4)}"
    base = base_url.rstrip("/")

    import logging as _log_mod
    _lg = _log_mod.getLogger("vapt.web_login")
    try:
        sess = requests.Session()

        # Phase 1: discover registration URLs from crawled links
        reg_urls = _discover_registration_urls(sess, base, timeout_s)
        _lg.info("self_register(%s) phase1 discovered=%d urls=%s",
                 base, len(reg_urls), reg_urls[:3])

        # Phase 2: append well-known paths that weren't already found.
        # Also probe step-suffixes but ONLY when the base path exists (non-404)
        # to avoid generating 100+ URLs that waste the run budget.
        seen = set(reg_urls)
        reachable: list[str] = []
        for path in _REG_PATH_HINTS:
            url = base + path
            if url not in seen:
                reg_urls.append(url)
                seen.add(url)
            try:
                _head = sess.head(base + path, timeout=3,
                                  allow_redirects=True)
                _base_exists = _head.status_code < 404
            except Exception:
                _base_exists = False
            if _base_exists:
                reachable.append(url)
                for suffix in _REG_STEP_SUFFIXES:
                    surl = base + path + suffix
                    if surl not in seen:
                        reg_urls.append(surl)
                        seen.add(surl)
                    try:
                        _sh = sess.head(surl, timeout=3,
                                        allow_redirects=True)
                        if _sh.status_code < 404:
                            reachable.append(surl)
                    except Exception:
                        pass

        _lg.info("self_register(%s) phase2 total=%d reachable=%d",
                 base, len(reg_urls), len(reachable))

        # Phase 3: try each URL with multi-step registration
        for reg_url in reg_urls:
            result = _try_register_at_url(sess, reg_url, base, username,
                                           password, timeout_s, gateway=gateway)
            if result:
                _lg.info("self_register(%s) OK via %s user=%s",
                         base, reg_url, result[1])
                _last_registration_urls = reachable or reg_urls[:20]
                return result
        _lg.info("self_register(%s) all %d urls failed", base, len(reg_urls))
    except Exception as _exc:
        _lg.warning("self_register(%s) exception: %s", base, _exc)
    return None


def probe_registration_ssti(base_url: str, reg_urls: list[str] | None = None,
                            *, timeout_s: int = 10) -> dict | None:
    """Walk the registration flow injecting a canary template expression
    into every text field.  Check each subsequent page for the rendered
    result.  Returns a dict describing the finding on success, None if
    no SSTI detected.

    Works for multi-step flows where the injection point (step N) and
    the rendering point (step N+k) are different URLs — a pattern that
    single-request tools like sstimap cannot detect.
    """
    import secrets
    try:
        import requests as _req
    except Exception:
        return None

    # Canary payloads for different template engines.
    # Django: {% widthratio A 1 B %} renders A*B (math via {{}} is invalid).
    # Jinja2/Twig: {{A*B}} renders the product directly.
    _canaries = [
        ("{% widthratio 7 1 7 %}", "49", "django"),
        ("{{" + "83*97" + "}}", "8051", "jinja2"),
    ]
    base = base_url.rstrip("/")

    urls = list(reg_urls or _last_registration_urls)
    if not urls:
        return None

    for canary_expr, canary_result, engine_hint in _canaries:
        for reg_url in urls:
            try:
                sess = _req.Session()
                r = sess.get(reg_url, timeout=timeout_s,
                             allow_redirects=True)
                if r.status_code != 200:
                    continue
                current_url = r.url
                current_html = r.text
                injection_url = ""

                for step in range(6):
                    if step == 0:
                        form_result = _detect_register_form(
                            current_html, current_url)
                    else:
                        form_result = _detect_any_form(
                            current_html, current_url)
                    if not form_result:
                        break
                    action, fields = form_result

                    data: dict[str, str] = {}
                    injected = False
                    for name, ftype in fields.items():
                        if ftype == "hidden":
                            vm = re.search(
                                rf'name="{re.escape(name)}"'
                                rf'[^>]*value="([^"]*)"',
                                current_html, re.I)
                            data[name] = vm.group(1) if vm else ""
                        elif ftype in ("text", "textarea"):
                            data[name] = canary_expr
                            injected = True
                        elif ftype == "email":
                            rnd = secrets.token_hex(4)
                            data[name] = f"ssti{rnd}@test.local"
                        elif ftype == "password":
                            data[name] = (
                                f"VaptT3st!{secrets.token_hex(4)}")
                        elif ftype in ("checkbox", "radio"):
                            data[name] = "on"
                        elif ftype == "select":
                            opts = re.findall(
                                r'<option[^>]*value="([^"]*)"',
                                current_html, re.I)
                            data[name] = opts[0] if opts else "1"
                        else:
                            data[name] = "1"

                    if injected and not injection_url:
                        injection_url = action

                    try:
                        resp = sess.post(action, data=data,
                                         timeout=timeout_s,
                                         allow_redirects=True)
                    except Exception:
                        break

                    body = resp.text or ""
                    if (canary_result in body
                            and canary_expr not in body):
                        return {
                            "confirmed": True,
                            "vuln": "ssti",
                            "injection_url": injection_url or action,
                            "render_url": resp.url,
                            "engine_hint": engine_hint,
                            "canary": (f"{canary_expr}"
                                       f"={canary_result}"),
                        }

                    if resp.status_code not in (200, 201, 302, 303):
                        break
                    if resp.url != current_url:
                        current_url = resp.url
                        current_html = resp.text
                        continue
                    break
            except Exception:
                continue
    return None
