---
id: scan-jwt-weakness
title: JWT algorithm / signature weaknesses
phase: scan
target_kinds: [web]
when_to_use: >-
  Response contains a JWT (three base64url segments separated by dots) in
  Authorization headers, cookies, or JSON bodies. Common weaknesses:
  `alg: none`, HS256 with a weak secret, RS256↔HS256 confusion, `kid`
  path traversal, and absent-expiration tokens.
tools_available: [nuclei_dast, http_probe]
auth_sensitive: true
mitre_attack: [T1552.001]
cwe: [CWE-347]
owasp: [A02:2021]
confidence: medium
version: 1
---

## When to use
Whenever a JWT is observed in traffic. Also valuable when the login flow
returns a token that is then sent back for every subsequent request —
weak signing lets an attacker forge privilege escalation.

## Workflow (advisory)
1. `nuclei_dast` with JWT fuzzing templates checks `alg: none` acceptance,
   `None` casing bypasses, and empty-signature submission.
2. Record the token's claims (via `http_probe` or an evidence capture) so
   a Tier-2 confirmer can later brute-force a weak HS256 secret.

## Verification
Acceptance of a server-forged `alg: none` token on an authenticated
endpoint is proof-confirmed. Offline brute-force of a captured token is
NOT in scope for V2 — it's an attack-phase action requiring approval.

## Known pitfalls
- Observing a JWT in traffic without actually SENDING it with a modified
  signature produces no evidence. The nuclei DAST template actually sends
  the probe; a passive scan alone cannot find the issue.
