---
id: scan-crlf-injection
title: CRLF / HTTP response-splitting injection
phase: scan
target_kinds: [web]
when_to_use: >-
  A parameter is reflected into a Set-Cookie, Location, or other response
  header. CRLF injection enables header forgery and (on vulnerable
  intermediaries) cache poisoning.
tools_available: [wapiti, nuclei_dast]
mitre_attack: [T1190]
cwe: [CWE-93, CWE-113]
owasp: [A03:2021]
confidence: medium
version: 1
---

## When to use
When reflected-in-header behavior is observed — common on
`/redirect?url=`, `/track?ref=`, and localized Set-Cookie endpoints.

## Workflow (advisory)
1. `wapiti` with the `crlf` module (already in the governed set) injects
   `\r\n` sequences and checks for header-injection reflection.
2. `nuclei_dast` adds response-splitting templates for cache-poisoning
   vectors.

## Verification
A response that carries a header the attacker injected (e.g. a forged
`Set-Cookie`) is proof-confirmed. Cache poisoning requires an upstream
CDN / proxy observation that V2 does not currently run.

## Known pitfalls
- Many HTTP/2-only backends strip raw `\r\n` at the frame boundary; the
  vuln only reproduces when the proxy downgrades to HTTP/1.1. Record
  the protocol used — a non-reproducing finding on HTTP/2 may still be
  valid on an HTTP/1.1 path.
