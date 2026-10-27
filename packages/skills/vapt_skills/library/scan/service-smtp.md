---
id: scan-service-smtp
title: SMTP service posture
phase: scan
target_kinds: [network, host]
when_to_use: >-
  Service scan detected SMTP (25, 465, 587). Open-relay testing, user
  enumeration via VRFY / EXPN / RCPT, and version-matched CVEs cover
  the standard mail-server exposure surface.
tools_available: [nmap_service_scan, smtp_user_enum]
mitre_attack: [T1589.002]
cwe: [CWE-200]
owasp: []
confidence: medium
version: 1
---

## When to use
When SMTP is in-scope and the engagement cares about mail-server
posture. `smtp_user_enum` is P2 (brute-ish — tries each wordlist entry
against VRFY/EXPN/RCPT); keep behind the human gate.

## Workflow (advisory)
1. `nmap_service_scan` on the port — captures the SMTP banner and TLS
   posture.
2. `smtp_user_enum -M VRFY -U <wordlist> -t <target>` only when the
   engagement explicitly covers user enumeration. VRFY is deprecated;
   many servers return 252 regardless (noise). Try RCPT if VRFY floods.

## Verification
A VRFY 250 response for one username but 550 for a non-existent one is
proof-confirmed enumeration. Uniform 252 is NOT confirmation.

## Known pitfalls
- Aggressive VRFY probing lands in the mail server's security log and
  often alerts the SOC. On a surprise engagement, skip this step until
  the operator confirms.
