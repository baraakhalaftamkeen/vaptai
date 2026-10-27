---
id: scan-cors-misconfig
title: CORS misconfiguration
phase: scan
target_kinds: [web]
when_to_use: >-
  The target serves cross-origin API responses, OR a user complaint /
  bounty-category requires explicit CORS coverage. Common misconfigs are
  `Access-Control-Allow-Origin: *` + `Allow-Credentials: true` (the
  browser rejects this combination, but curl / server-to-server callers
  do not) and reflection of arbitrary Origin headers.
tools_available: [nuclei_safe, nuclei_dast, http_probe]
auth_sensitive: true
mitre_attack: [T1557]
cwe: [CWE-942]
owasp: [A05:2021]
confidence: medium
version: 1
---

## When to use
As part of the first authenticated scan, since authenticated endpoints
carry the real risk (an open CORS on a public endpoint rarely matters).

## Workflow (advisory)
1. `nuclei_safe` templates for CORS misconfigs (reflected origin, null
   origin acceptance, pre-flight passthrough).
2. `nuclei_dast` adds parameterised Origin header probes.
3. `http_probe` only confirms the response headers exist — it does not
   itself detect CORS misconfig.

## Verification
A reflected `Access-Control-Allow-Origin: <attacker>` with
`Allow-Credentials: true` is proof-confirmed. A wildcard without
credentials is lower severity (no browser-side leak path to authn data).

## Known pitfalls
- Setting `Access-Control-Allow-Origin: null` is as bad as `*` for
  authenticated contexts: sandboxed iframes have origin `null` and will
  be accepted. Don't downgrade a `null`-reflecting finding on the
  assumption that only the wildcard matters.
