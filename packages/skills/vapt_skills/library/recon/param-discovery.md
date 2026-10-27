---
id: recon-param-discovery
title: Hidden-parameter discovery per endpoint
phase: recon
target_kinds: [web]
when_to_use: >-
  Discovered routes exist from the crawl / content walk, and the next phase
  wants to fuzz parameters. Arjun probes each endpoint individually; the site
  root rarely carries meaningful params, so point arjun at the specific URL.
tools_available: [arjun]
auth_sensitive: true
mitre_attack: [T1190]
owasp: [A03:2021]
confidence: high
version: 1
---

## When to use
Immediately after content discovery, once there is a list of in-scope routes.
Discovered param URLs become seeds for `scan-web-dast` (wapiti --start +
nuclei_dast -u).

## Workflow (advisory)
1. For each discovered endpoint URL, invoke `arjun` with the full `url=`
   argument (not just the host). The built-in spec rejects off-host URLs.
2. Collect the `Parameters found:` text; the normalizer parses the console
   output, not JSON.
3. Pass parameterised seed URLs forward to the fuzzers.

## Known pitfalls (recorded from DineHub debugging)
- **`arjun -oJ /dev/stdout` writes NO JSON** (verified against arjun 2.2.7).
  Do not re-add the flag. The console `Parameters found: a, b` + the
  `Scanning N/M:` lines ARE the output we parse.
- **Arjun skips non-HTML / 302 responses** with "URL doesn't seem to be a
  webpage. Skipping." Routes that redirect to `/auth/login` unauthenticated
  (common for `/order`, `/admin/*`, JSON APIs) are silently skipped. Fix is
  authenticated discovery — see `scan-web-authenticated`.
- **Manifest budget starvation**: the probe phase runs under one SCAN
  `ManifestGuard` with `max_iterations=64`. The arjun sweep runs last; if the
  earlier probe sub-steps overshoot their share, arjun never fires and the
  symptom is "no params found" on a target that clearly has them.
