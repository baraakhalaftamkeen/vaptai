---
id: scan-csrf-detection
title: Cross-site request forgery detection
phase: scan
target_kinds: [web]
when_to_use: >-
  Authenticated state-changing endpoints exist (login, password change,
  profile update, admin actions). CSRF scanning only has signal with an
  authenticated session; unauthenticated runs will see the login redirect
  and report nothing useful.
tools_available: [wapiti, nuclei_dast]
auth_sensitive: true
mitre_attack: [T1189]
cwe: [CWE-352]
owasp: [A01:2021]
confidence: medium
version: 1
---

## When to use
After `scan-web-authenticated` has stabilized a session cookie. Wapiti's
`csrf` module checks that each state-changing POST either carries a
synchronizer token or validates the Origin / Referer header.

## Workflow (advisory)
1. `wapiti` with modules including `csrf` (already in the governed set).
   Pair with the session cookie — unauthenticated runs cannot reach the
   state-changing surface.
2. `nuclei_dast` DAST templates for CSRF variants (missing SameSite, token
   predictability) complement wapiti's structural check.

## Verification
A CSRF candidate stays `candidate` until a replay of the exploit (one
cross-origin POST) proves the server accepted it without the token.
Reachability re-probes do not confirm CSRF — see `validate-reachability`.

## Known pitfalls
- SameSite=Lax on the session cookie mitigates most GET-based CSRF today;
  wapiti still flags the structural absence of a token. Both facts belong
  in the finding — the mitigation reduces severity but doesn't erase it.
