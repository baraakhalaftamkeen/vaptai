---
id: scan-nikto-sweep
title: Nikto baseline web-server audit
phase: scan
target_kinds: [web]
when_to_use: >-
  The target web server is one Nikto's checks still cover well — IIS,
  older Apache, Tomcat admin consoles — or the engagement reporting
  benchmark requires a Nikto sweep. Modern app servers (nginx, caddy,
  Flask / Node) see almost no signal from Nikto.
tools_available: [nikto]
mitre_attack: [T1190]
cwe: []
owasp: [A06:2021]
confidence: medium
version: 1
---

## When to use
When the server fingerprint names Apache 2.2 / IIS / Tomcat / Nginx with
a dated banner. A Node / Flask / Rails target is usually not worth the
scan time.

## Workflow (advisory)
1. `nikto` with the governed args (`-ask no -nointeractive -maxtime 180`).
   The 3-minute self-cap exists because Nikto on IIS can otherwise run
   until the subprocess timeout.
2. Treat exit code 1 as success (findings reported); the ok_exit_codes
   tuple already permits it.

## Verification
A Nikto hit is `candidate` — many entries are decade-old defaults
(expect-ct, x-powered-by exposure) that modern teams tolerate. Confirm
only the specific findings the engagement classifies as actionable.

## Known pitfalls
- Nikto DOES send some payload-y probes. It is P1 in the catalog (not
  P0) for this reason. Keep it in scan, not recon.
