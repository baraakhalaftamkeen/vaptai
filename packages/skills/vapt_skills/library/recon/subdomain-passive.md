---
id: recon-subdomain-passive
title: Passive subdomain enumeration
phase: recon
target_kinds: [network]
when_to_use: >-
  The engagement scope is a domain (not a single IP), and the attack
  surface likely spans subdomains. Passive sources (certificate
  transparency, Internet-wide scans, OSINT caches) find assets the
  engagement forgot to list — a common finding on its own.
tools_available: [subfinder, amass_passive, assetfinder, sublist3r]
mitre_attack: [T1590.001, T1596]
cwe: []
owasp: []
confidence: high
version: 1
---

## When to use
First step of any domain-scoped engagement. Four sources run cheaply in
parallel; de-duplication happens downstream.

## Workflow (advisory)
1. `subfinder` is the strongest single source today (CT logs + API
   providers). Set API keys via the per-provider env vars if available;
   the governed builder does not pass them in argv.
2. `amass_passive` and `assetfinder` broaden coverage with different
   source weights.
3. `sublist3r` is older but still catches search-engine indexed names
   the ProjectDiscovery stack misses.

## Verification
A discovered subdomain is NOT in scope until the engagement scope says
so. Every passive hit must be scope-checked before any active probe.

## Known pitfalls
- Passive sources return STALE data (hosts decommissioned months ago).
  Resolve each hit (`dns_resolve`) before escalating to active probing;
  a dangling CNAME is a separate finding (`scan-backup-takeover`).
