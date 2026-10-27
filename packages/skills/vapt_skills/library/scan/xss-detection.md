---
id: scan-xss-detection
title: XSS detection (reflected + DOM)
phase: scan
target_kinds: [web]
when_to_use: >-
  Discovered parameter URLs exist, especially endpoints that echo user input
  into HTML (`/search`, `/feedback`, `/review`) or into JS sinks (`#hash`
  routers, `innerHTML` templates). V2 covers reflected AND DOM XSS; the
  server-side scanners alone miss DOM sinks.
tools_available: [wapiti, nuclei_dast, dalfox]
auth_sensitive: true
mitre_attack: [T1059.007]
cwe: [CWE-79]
owasp: [A03:2021]
confidence: high
version: 1
---

## When to use
After param discovery. `dalfox` closes the DOM-XSS gap the other scanners
have — it launches headless Chrome and observes payload execution in a real
JS environment.

## Workflow (advisory)
1. `wapiti` catches reflected XSS (modules `xss,permanentxss`).
2. `nuclei_dast` runs reflected-XSS DAST templates on seed URLs.
3. `dalfox` on each specific URL where upstream (arjun / wapiti) pinned a
   suspect parameter — use `-p` to restrict dalfox to that param so it
   finishes fast. Follow redirects + cookie are already set by the builder;
   `--cookie-from-raw` loads the cookie into the headless Chrome jar so
   authenticated DOM passes don't 302 to login.

## Verification
A dalfox `Verified` (`V`) hit is a proof-confirmed finding (same mechanism
as sstimap). A `Reflected` (`R`) hit is strong-signal but still `candidate`.

## Known pitfalls
- `dalfox --silence` can suppress JSON output on fast exits (observed as
  mysterious 0.5s terminations on DineHub). The governed builder leaves it
  OFF; the banner lines dalfox prints are tolerable noise.
- Stored XSS needs POST support. The builder accepts `method=post` +
  `data=...` for discovered form endpoints — without it, dalfox always GETs
  and misses stored sinks entirely.
