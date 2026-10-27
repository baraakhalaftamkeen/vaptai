---
id: recon-url-history
title: Historical URL discovery
phase: recon
target_kinds: [web, network]
when_to_use: >-
  The target is a long-lived domain and the current site likely retired
  routes that still receive traffic. Wayback and gau return URLs the
  live crawl cannot see (deleted admin pages, old API paths, parameter
  patterns from past form versions).
tools_available: [waybackurls, gau]
mitre_attack: [T1596.002]
cwe: []
owasp: []
confidence: medium
version: 1
---

## When to use
Alongside katana crawling. Historical URLs often expose parameter names
that still work on current routes (unchanged backend handlers).

## Workflow (advisory)
1. `waybackurls` queries the Internet Archive's URL index. Fast; returns
   many URLs for popular domains.
2. `gau` broadens to AlienVault / Common Crawl / URLScan. Pair the two
   for coverage, de-duplicate downstream.

## Verification
Hits are candidate routes, not confirmed endpoints — many 404 today.
Feed them to `recon-param-discovery` to validate which still respond.

## Known pitfalls
- A query-string parameter pattern seen in Wayback may hint at an
  internal handler the current form hides. Keep the parameter names
  even when the specific URL 404s.
