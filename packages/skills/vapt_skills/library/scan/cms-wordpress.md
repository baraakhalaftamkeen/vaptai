---
id: scan-cms-wordpress
title: WordPress-specific scanning
phase: scan
target_kinds: [web]
when_to_use: >-
  `recon-web-fingerprint` identified WordPress (any confidence). WordPress
  has a dedicated scanner that outperforms generic DAST on this stack —
  plugin + theme CVEs, user enumeration, config exposure.
tools_available: [wpscan, nuclei_safe]
auth_sensitive: false
mitre_attack: [T1190]
cwe: []
owasp: [A06:2021]
confidence: high
version: 1
---

## When to use
As soon as a WordPress fingerprint is confirmed. The WPScan CLI runs
unauthenticated enumeration + plugin version matching.

## Workflow (advisory)
1. `wpscan` with `--format cli-no-color` (governed builder's default).
   Exits 4 / 5 on vulns found — treat those as success, not failure.
2. `nuclei_safe` templates add WordPress-specific CVEs the WPScan DB
   doesn't yet carry.

## Verification
A plugin version matched to a CVE is `candidate`, not `confirmed` —
version matching produces false positives on backports. Confirm with
`nuclei_cve` for a template-based re-check (see `validate-cve-matching`).

## Known pitfalls
- WPScan rate-limits itself when the vendored DB finds > 50 plugins. On
  a plugin-heavy install, let it finish — don't tune the throttle up to
  "speed it up"; the API that backs the DB will 429 and the scan degrades.
