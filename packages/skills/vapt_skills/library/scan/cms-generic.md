---
id: scan-cms-generic
title: Non-WordPress CMS scanning
phase: scan
target_kinds: [web]
when_to_use: >-
  `recon-web-fingerprint` identified a CMS that isn't WordPress — Joomla,
  Drupal, Magento, Ghost, or when the fingerprint is "some CMS, not sure
  which". Generic DAST under-covers CMS admin paths; dedicated scanners
  know the right routes.
tools_available: [cmseek, joomscan, droopescan]
auth_sensitive: false
mitre_attack: [T1190]
cwe: []
owasp: [A06:2021]
confidence: medium
version: 1
---

## When to use
Pick ONE scanner based on the fingerprint. Running all three on an
unidentified CMS is wasteful (they probe the same routes with different
tool banners) and increases detection by a WAF.

## Workflow (advisory)
1. If CMS is unknown, `cmseek` first — it identifies before scanning
   (exit 1 is "no CMS detected", not failure).
2. Joomla → `joomscan`, Drupal → `droopescan scan drupal`.

## Verification
Version-matched CVEs stay `candidate` — hand off to
`validate-cve-matching` for a nuclei template re-check.

## Known pitfalls
- `cmseek` on an HTTPS target with a bad cert hangs on the TLS verify
  before the governed builder adds `--follow-redirect`. The governed
  spec sets the right flags; don't tweak them.
