---
id: scan-security-headers
title: Security headers posture
phase: scan
target_kinds: [web]
when_to_use: >-
  Any web engagement — security-header posture is cheap to check and
  shows up in nearly every report. Missing CSP, HSTS, X-Frame-Options,
  Referrer-Policy, Permissions-Policy are the usual gaps.
tools_available: [shcheck, humble, nuclei_safe]
mitre_attack: []
cwe: [CWE-1021, CWE-693]
owasp: [A05:2021]
confidence: high
version: 1
---

## When to use
Early in the scan phase, before DAST. Low-cost, high-report-coverage.

## Workflow (advisory)
1. `shcheck` returns a per-header verdict for the base URL in one call.
2. `humble` adds the OWASP header baseline with a per-header grade.
3. `nuclei_safe` catches header-related known-CVE patterns.

## Verification
A missing header is confirmed by the response itself — no re-probe
required. A `Content-Security-Policy` that includes `unsafe-inline` or
`unsafe-eval` is a weaker finding than a missing CSP; render the actual
value in the report, not just "missing / present".

## Known pitfalls
- A CDN often STRIPS headers set by the origin. If `shcheck` returns
  "missing", confirm by requesting the origin directly (when scope
  allows) before raising severity.
