---
id: scan-web-authenticated
title: Authenticated web scanning
phase: scan
target_kinds: [web]
when_to_use: >-
  The target has a login form (operator supplied creds or a login_url was
  discovered), and post-login routes carry most of the attack surface.
  Running web tools unauthenticated against such an app leaves the valuable
  routes invisible.
tools_available: [wapiti, nuclei_dast, arjun, feroxbuster, katana, dalfox]
auth_sensitive: true
mitre_attack: [T1078]
cwe: [CWE-287]
owasp: [A07:2021]
confidence: high
version: 1
---

## When to use
When creds are present in the Redis slot (`vapt:webcreds:<run_id>`) and a
login URL is detected during probe. The webvuln node runs `_ensure_cookie()`
once per run; the cookie is cached in `vapt:webcookie:<run_id>` with the
same TTL and clear semantics as the creds.

## Workflow (advisory)
1. `obtain_session_cookie(login_url, user, pass)` performs the login:
   GETs the login page → parses form fields + hidden CSRF → POSTs creds →
   serializes cookies to `name=value; name2=value2`. Rejects off-host
   post-redirect, token-free responses, and failed logins — ANY failure
   degrades to unauthenticated scan (fail-safe).
2. All web tools pick the cookie up through their builder: katana/nuclei/
   feroxbuster/wapiti use `-H "Cookie: ..."`, arjun uses `--headers`,
   sstimap uses `-C`.
3. One authenticated katana re-crawl per endpoint fires when `login_url`
   is detected (`webvuln-authcrawl-{tag}`), followed by a bounded
   authenticated arjun sub-sweep over newly-discovered routes.

## Verification
Ledger event `webvuln.authenticated {login_url, ok, note?}` makes the auth
outcome auditable. The event records neither the password nor the cookie.

## Known pitfalls
- Passing BOTH the Python-side cookie AND wapiti's native `--form-*` makes
  wapiti re-login mid-scan and discover far more routes than the cookie
  alone — this pushed port-5000 runs past 10 minutes. The governed builder
  uses cookie-only when the cookie is present, and native form-login only
  as fallback.
