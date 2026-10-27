---
id: scan-idor-detection
title: IDOR / cross-tenant authorization bypass
phase: scan
target_kinds: [web]
when_to_use: >-
  The target has an authenticated multi-tenant surface (orders, receipts,
  user-scoped records) with numeric IDs in URLs, AND the operator supplied
  TWO credential sets at run creation. Without two sessions, this skill
  cannot run.
tools_available: [idor_probe]
auth_sensitive: true
mitre_attack: [T1078]
cwe: [CWE-639]
owasp: [A01:2021]
confidence: high
version: 1
---

## When to use
Only when two cookie slots exist (`vapt:webcookie:<run_id>:A` and `:B`).
The probe is deterministic — it rewrites numeric IDs across accounts and
flags cross-tenant access.

## Workflow (advisory)
1. Pass a comma-separated list of in-scope URLs with numeric IDs (per the
   probe's own `/\d{1,10}` filter). Off-scope and non-ID URLs are
   discarded, capping the per-invocation surface at 30 to avoid DoS.
2. The probe loads both cookies, requests each URL as each user, and
   compares. A 200 with different body for user B on user A's object is
   authz leak and emits `confirmed=True`.

## Verification
The normalizer promotes `confirmed=True` entries to proof-confirmed
findings. A 403/404 for user B is strong evidence of correct authz
enforcement — the probe records the negative for the coverage report.

## Known pitfalls
- Numeric IDs only (today). GUID / slug / opaque-id IDOR is not covered by
  this probe. If the app uses them, propose adding a slug-aware variant;
  do NOT try to repurpose `idor_probe` out of its argv contract.
- **Plan-order starvation.** The webvuln phase has a ~1-hour wall-clock
  budget (SCAN manifest `max_wall_seconds=3600`). If `idor_probe` is
  scheduled LATE in the plan (behind a long `web_param_probe` loop), the
  budget expires before it fires — the DineHub 2026-10-23 run hit this
  exactly. The orchestrator now hoists `idor_probe` early in the plan,
  right after the sqli/dalfox auth-and-form dispatchers.
- Discovery timing: the auth-crawl runs INSIDE webvuln, so numeric-ID
  routes like `/restaurant/N/menu` only appear in `discovered_endpoint_urls`
  AFTER the authenticated katana re-crawl. The probe reads from both
  `discovered_endpoint_urls` (cap=30) AND `webvuln_seed_urls` (cap=80) so
  auth-crawl findings surface even when ranked past the primary cap.
