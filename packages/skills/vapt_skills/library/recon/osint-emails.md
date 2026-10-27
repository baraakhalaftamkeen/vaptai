---
id: recon-osint-emails
title: OSINT — emails, employees, registration data
phase: recon
target_kinds: [network]
when_to_use: >-
  The engagement scope covers a domain and the operator wants an org-wide
  posture (phishing surface, exposed emails, admin contact leakage).
  Passive — no probes to the target itself.
tools_available: [theharvester, whois_lookup]
mitre_attack: [T1589.002, T1591]
cwe: []
owasp: []
confidence: medium
version: 1
---

## When to use
Early in the engagement, in parallel with subdomain discovery. Useful
for Red Team / phishing-adjacent engagements; marginal value on pure
black-box web pentests.

## Workflow (advisory)
1. `theharvester -d <domain> -b bing,crtsh,duckduckgo` — the governed
   source set is already set (keep the list short; adding more providers
   trades time for marginal signal).
2. `whois_lookup` gets the registrant and admin contact. Modern
   registrars redact these; a redacted response is still a data point.

## Verification
Email lists coming back from theHarvester are frequently stale. Do not
auto-generate a credential-brute wordlist from them without operator
review — brute force is attack-phase anyway.

## Known pitfalls
- Rate-limited sources (crtsh) sometimes return empty. Not a failure —
  record coverage gap and move on.
