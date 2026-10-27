---
id: scan-xss-methodology
title: XSS methodology — full taxonomy mapped to our tools
phase: scan
target_kinds: [web]
when_to_use: >-
  The target is a web app and the planner is deciding WHICH XSS classes to
  probe. This skill is the taxonomy map — read it when picking tools for an
  app that has forms, URL params, DOM-heavy JS, or an admin surface. Lets the
  LLM-webvuln planner reason about XSS across all five classes (reflected,
  stored, DOM, blind, CSP-bypass) in one pass instead of per-tool.
tools_available: [dalfox, nuclei_dast, wapiti, stored_xss_probe, csp_check, http_probe]
auth_sensitive: true
mitre_attack: [T1059.007, T1189]
cwe: [CWE-79, CWE-80, CWE-1021]
owasp: [A03:2021, A05:2021]
confidence: high
version: 1
---

## When to use
This is the orientation map, not a specific probe. When the LLM-webvuln
planner reads it, it should pick tools from the five-class matrix below
rather than defaulting to "run dalfox on everything."

## The five classes and our tool coverage

| Class | Where it lives | Our tool(s) | Dispatch rule |
|---|---|---|---|
| **Reflected** | URL params → immediate response | `dalfox`, `nuclei_dast` (DAST templates), `wapiti` (xss / permanentxss modules) | fires on arjun-discovered params + wapiti XSS targets |
| **Stored** | POST → DB → render on another page | `stored_xss_probe` (visible canary) | fires on `is_post_sink_route()` endpoints — reviews / comments / profile / admin forms |
| **DOM** | Client-side JS sinks (`innerHTML`, `document.write`, URL hash → `eval`) | `dalfox` headless Chrome pass | fires on same endpoint set as reflected |
| **Blind** | Payload fires in admin / backend browser the attacker never sees | `stored_xss_probe` OAST canary (uses interactsh) | fires alongside stored — one POST plants both canaries |
| **CSP posture** | Weak policy makes the above classes exploitable even when the sink is "sanitized" | `csp_check` | fires once per web base early in the plan |

## Workflow (advisory)
1. **Fingerprint first.** `recon-web-fingerprint` identifies the framework
   (React / Vue / Angular / Flask-Jinja / etc). The LLM-webvuln planner
   should bias downstream dispatch to the framework's known sinks (see
   "Framework-specific sinks" below).
2. **CSP posture** (`csp_check`) runs once per web base. A weak CSP
   (`unsafe-inline`, `unsafe-eval`, wildcards, missing `strict-dynamic`,
   missing `require-trusted-types-for`) multiplies the severity of any
   reflected/stored/DOM finding below.
3. **Reflected XSS** (`dalfox`, `nuclei_dast`, `wapiti`) on discovered
   param URLs. Dalfox's `-p` pin from arjun's output cuts runtime 10×.
4. **Stored + Blind XSS** (`stored_xss_probe`) on form endpoints. One
   invocation posts BOTH a visible-string canary and an OAST
   (`<img src="{interactsh}">`) canary, then GETs the view URL and polls
   OAST for ~8 seconds. Blind-only hits mean a backend render surface
   (admin viewer, email digest) the GET pass couldn't reach.
5. **DOM XSS** — dalfox's headless Chrome pass observes payload execution
   in a real JS environment. The only tool we have that sees DOM sinks.

## Verification
- `dalfox` Verified (`V`) hit → proof-confirmed (headless browser observed
  the payload fire).
- `stored_xss_probe` `confirmed=True` (either visible canary matched OR
  OAST callback fired) → proof-confirmed via `_PROOF_SOURCE_TOOLS`.
- `csp_check` weaknesses are REPORT-GRADE, NOT exploit confirmations.
  Deliberately NOT in `_PROOF_SOURCE_TOOLS` — a weak CSP is strong context
  for the operator, not a vuln on its own.

## Framework-specific sinks (planner should bias toward these)
- **React:** `dangerouslySetInnerHTML`, `use()` hook with unsanitized data
- **Vue:** `v-html`, dynamic component names
- **Svelte:** `{@html ...}`, runes with HTML content
- **Angular:** `bypassSecurityTrust*`, `[innerHTML]` binding
- **Next.js:** `next/script strategy="beforeInteractive"`, Server Actions
  with unvalidated input
- **Flask / Jinja2:** server-side `{{ var | safe }}` (where our
  `scan-ssti-detection` covers the related SSTI case)

## Known coverage gaps (planner should NOT silently claim coverage of these)
- **DOM clobbering** — not covered. Rare but devastating when it exists.
  Needs a dedicated probe that injects `<form id="X">` sibling tags and
  checks if JS code using `document.getElementById('X')` picks up the
  attacker-controlled node.
- **Prototype-pollution → XSS chain** — not covered. Common on apps using
  `Object.assign` / deep-merge on JSON input. The polluted prototype can
  seed `innerHTML` sinks later.
- **mXSS (mutation XSS)** — valid HTML that MUTATES when parsed by the
  browser, bypassing WAF + DOMPurify through parsing quirks. Dalfox's
  payload set has some but not comprehensive.
- **Service Worker XSS** — persistent-attack technique via malicious SW
  registration. Scanner value is bounded; the vuln is a sign of a worse
  underlying XSS primitive which we'd catch via the above classes anyway.
- **Mobile WebView XSS (Android `addJavascriptInterface`, iOS WKWebView
  `evaluateJavaScript`)** — mobile is explicitly out of V2 scope.

## Known pitfalls
- **Alert-based detection is unreliable.** Chrome / Firefox / Safari may
  suppress `alert`/`confirm`/`prompt` in cross-origin iframes or
  background tabs. Our tools favor side-effect detection (DOM mutation,
  OAST callback, canary string in body) over alert boxes for this reason.
- **CSP `report-only` ≠ enforced.** The `csp_check` tool distinguishes
  the two — a strict Report-Only policy with weak enforced policy is a
  common pattern that looks safe to a surface reader. Record which one
  carried the weakness.
- **Blind-XSS poll is time-bounded.** `stored_xss_probe` polls OAST for
  ~8 seconds after the view-URL GET. Async render paths (nightly email
  digests, cron'd log viewers) fire LATER — out of scope for a single
  probe run. Record as a coverage gap; a longer-cadence re-run would
  catch them.
