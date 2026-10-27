---
id: recon-dns-enumeration
title: Active DNS enumeration
phase: recon
target_kinds: [network]
when_to_use: >-
  The target domain is in scope and NS / MX / TXT records drive mail /
  CDN / cloud-provider decisions. Also valuable for finding zone-transfer
  misconfigurations that leak the full host list.
tools_available: [dnsrecon, dns_resolve]
mitre_attack: [T1590.002]
cwe: [CWE-200]
owasp: []
confidence: high
version: 1
---

## When to use
After passive subdomain enumeration, to confirm what resolves and to
inspect the broader DNS posture.

## Workflow (advisory)
1. `dns_resolve` (P0, built-in) first — one-shot A/AAAA for the base
   domain. Confirms the engagement target exists.
2. `dnsrecon` runs a bounded probe set (NS, MX, SPF, DMARC, zone
   transfer attempts). A successful AXFR is a direct exposure finding.

## Verification
AXFR success is proof-confirmed. Missing SPF / DMARC / DKIM records are
candidate — the finding depends on whether the domain actually sends
mail, which the engagement brief determines.

## Known pitfalls
- `dnsrecon` picks up GEO-DNS variations by querying multiple
  resolvers. The hits for different resolvers may differ — record which
  one answered.
