---
id: recon-web-fingerprint
title: Fingerprint the web stack before scanning
phase: recon
target_kinds: [web]
when_to_use: >-
  The scope target responds on an HTTP(S) port and the planner has not yet
  observed its tech stack. Fingerprinting first lets later phases pick the
  right template engine, CMS modules, and param-discovery depth.
tools_available: [http_probe, whatweb, wafw00f]
mitre_attack: [T1595.002]
owasp: []
confidence: high
version: 1
---

## When to use
Run before any payload-sending scanner. The Server banner, title, and tech list
drive downstream decisions — notably `scan-ssti-detection`, which uses the
detected template engine to narrow sstimap's plugin set from 25+ to one.

## Workflow (advisory)
1. Prefer `http_probe` (ProjectDiscovery httpx) first — it emits status, title,
   Server banner and Wappalyzer tech list in one bounded call. Already P1.
2. `whatweb` fills in CMS specifics the httpx tech-detect misses (plugin
   versions on WordPress/Joomla/Drupal); run only if a CMS is suspected.
3. `wafw00f` is only useful when a WAF is suspected — it adds latency and
   little signal on obviously-no-WAF lab targets.

## Verification
- A successful fingerprint carries a non-empty Server banner OR tech list. An
  empty response with status 200 usually means a reverse-proxy stripped the
  banner — note this and continue (do NOT retry forever).

## Known pitfalls
- The binary `httpx` on PATH is often the Python httpx library's CLI, which
  silently takes over. VAPT ships `VAPT_HTTPX_BIN` for exactly this reason;
  the governed builder respects it.
