---
id: scan-stored-xss-detection
title: Stored (persistent) XSS detection
phase: scan
target_kinds: [web]
when_to_use: >-
  The target has form endpoints that STORE user text and render it later on a
  different page — reviews, comments, feedback, profile bio, admin
  announcements. Dalfox POSTs the payload but only inspects the POST response;
  it cannot see what the server rendered on the view page. That's the specific
  blind spot `stored_xss_probe` closes.
tools_available: [stored_xss_probe, dalfox]
auth_sensitive: true
mitre_attack: [T1059.007]
cwe: [CWE-79, CWE-80]
owasp: [A03:2021]
confidence: high
version: 1
---

## When to use
After `recon-content-discovery` and `scan-web-authenticated` have surfaced
submit endpoints like `/restaurant/N/reviews`, `/feedback`, `/profile`,
`/admin/announcement`, `/comment`. Reflected XSS on these same endpoints is
`scan-xss-detection`'s job (dalfox handles it); stored XSS needs a two-step
POST + GET flow this skill covers.

## Workflow (advisory)
1. `stored_xss_probe` with:
   - `post_url` — the submit endpoint
   - `view_url` — the page that renders stored content (often the same
     endpoint after redirect, or a `/all` sibling for feedback-style lists,
     or the parent path for comment-style threads)
   - `param` — the field that carries user text (`name`, `message`,
     `comment`, `body` — pin via arjun's discovery when available)
2. The probe sends a UNIQUE canary (`vapt-xss-<uuid>`) inside a visible
   payload, GETs the view URL, and emits `confirmed=True` iff the canary
   appears in the view body.
3. `dalfox` on the same endpoints covers reflected + DOM XSS in parallel;
   the two tools are complementary, not redundant.

## Verification
A `confirmed=True` observation from `stored_xss_probe` IS proof — the server
stored our text verbatim and emitted it unescaped into another page. The
validator promotes it via `_PROOF_SOURCE_TOOLS` without needing a separate
re-probe. Browser-side execution is a separate question (CSP can neutralize
the payload at render time), but the server-side XSS primitive is confirmed.

## Known pitfalls
- **View-URL heuristic is approximate.** The orchestrator uses path-pattern
  rules (`/feedback` → `/feedback/all`, `/comment` → parent) which cover
  common Flask/Rails apps but miss unusual routing (`/review/POST` → stored
  at `/restaurant/{id}` where `{id}` is in the session). When the heuristic
  fails, the canary doesn't match and the finding stays info-only — not a
  false positive, just a coverage gap worth recording.
- **CSRF-protected forms need the hidden token** in `data=`. The probe
  accepts additional k=v fields via `data`; include the CSRF token when the
  form has one.
- **The payload is a visible string, not a JS execution harness.** This
  intentionally confirms the data-persistence path only. Browser-side
  execution requires `dalfox` with headless Chrome; the two layers answer
  different questions.
