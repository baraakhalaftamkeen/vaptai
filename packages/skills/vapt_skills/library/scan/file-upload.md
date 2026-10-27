---
id: scan-file-upload
title: Unrestricted file upload detection
phase: scan
target_kinds: [web]
when_to_use: >-
  The target has an upload endpoint (profile avatar, document attach,
  image resize, admin import). Unrestricted file upload is one of the
  highest-leverage web vulns — the extension check is often all that
  stops RCE.
tools_available: [wapiti, web_param_probe]
auth_sensitive: true
mitre_attack: [T1190]
cwe: [CWE-434]
owasp: [A08:2021]
confidence: medium
version: 1
---

## When to use
When content discovery or the authenticated crawl has surfaced a
multipart/form-data endpoint. Unauthenticated upload endpoints are rare;
scan with the session cookie.

## Workflow (advisory)
1. `wapiti` with the `upload` module runs structural checks (extension
   enforcement, content-type validation, double-extension bypass).
2. `web_param_probe` adds in-band proof for sensitive-content exposure on
   the uploaded file's served URL.

## Verification
A successful upload of a file whose extension / content-type was supposed
to be rejected is strong signal; executing the uploaded file (triggering
RCE) is NOT in scope for V2 — that's a Tier-2 attack-phase action.

## Known pitfalls
- Many apps accept the upload but serve it with `Content-Disposition:
  attachment`, which neutralizes browser-side XSS. Record the served
  response headers in the finding — they change severity.
