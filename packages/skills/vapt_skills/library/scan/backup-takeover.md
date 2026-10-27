---
id: scan-backup-takeover
title: Backup files and subdomain takeover
phase: scan
target_kinds: [web]
when_to_use: >-
  The target is a production web app, or the engagement scope covers
  subdomains. Backup files (`.bak`, `.swp`, `.tar.gz`) expose source;
  dangling CNAMEs to deprovisioned cloud resources enable takeover.
tools_available: [wapiti, feroxbuster]
mitre_attack: [T1584.001]
cwe: [CWE-530]
owasp: [A05:2021]
confidence: medium
version: 1
---

## When to use
Run alongside content discovery. Backup discovery is cheap (extension
suffixing on known routes) and takeover detection is a single DNS
query + fingerprint check.

## Workflow (advisory)
1. `wapiti` with the `backup` and `takeover` modules (already in the
   governed set).
2. `feroxbuster` with a backup-oriented wordlist (operator supplies via
   `VAPT_WORDLIST`) complements wapiti's targeted suffixing.

## Verification
A 200 response on `.env`, `.git/config`, or a `.bak` of a known route is
proof-confirmed exposure. Subdomain takeover requires an active claim at
the cloud provider — Tier-2 attack-phase, not scanned here.

## Known pitfalls
- `.git` exposure is often the WHOLE repo if `.git/HEAD` + the pack files
  are reachable. Flag the first `.git/` 200 immediately and halt the
  automated enumeration — further requests just inflate the finding count
  without changing the severity.
