---
id: scan-xxe-detection
title: XML external entity injection
phase: scan
target_kinds: [web]
when_to_use: >-
  The target accepts XML in a request body (SOAP APIs, SAML endpoints,
  legacy ingestion routes, Office Open XML upload). Modern frameworks
  often ship XXE-safe parsers by default; legacy / in-house parsers do
  not, and this is where the exposure lives.
tools_available: [wapiti, web_param_probe]
auth_sensitive: true
mitre_attack: [T1190]
cwe: [CWE-611]
owasp: [A05:2021]
confidence: medium
version: 1
---

## When to use
When Content-Type `application/xml` or `text/xml` is accepted, or when a
`.xml`, `.svg`, `.docx` upload is in scope. SAML `AuthnRequest` endpoints
are a high-signal starting point.

## Workflow (advisory)
1. `wapiti` with the `xxe` module (already in the governed set) runs
   structural checks for external-entity resolution and parameter-entity
   abuse.
2. `web_param_probe` has a dedicated XXE class for XML-body endpoints —
   fires one targeted entity payload and parses the response for the
   file read indicator.

## Verification
A response that returns the content of `/etc/passwd` (or the
`SYSTEM "file:///..."` entity reflection) is proof-confirmed. Blind XXE
requires an out-of-band callback — not configured in V2 today.

## Known pitfalls
- Many XXE candidates come from SAML flows. Testing SAML without the
  engagement's IdP participation is likely to produce false positives
  (the IdP rejects the forged request upstream). Record the IdP posture
  before raising severity.
