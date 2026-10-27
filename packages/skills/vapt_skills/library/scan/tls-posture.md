---
id: scan-tls-posture
title: TLS configuration audit
phase: scan
target_kinds: [web, host]
when_to_use: >-
  Any HTTPS service. TLS misconfigurations (TLS 1.0 / 1.1 still enabled,
  weak ciphers, missing OCSP stapling, expired-cert exposure) are
  standard report items for every web engagement.
tools_available: [tls_check, sslyze]
mitre_attack: [T1573]
cwe: [CWE-326, CWE-327]
owasp: [A02:2021]
confidence: high
version: 1
---

## When to use
Once per unique (host, port) pair that terminates TLS. Not useful on
plain-HTTP targets.

## Workflow (advisory)
1. `tls_check` (testssl.sh) is the broad audit — ciphers, protocols,
   known-vuln checks (Heartbleed, ROBOT, Logjam) in one bounded call.
2. `sslyze` complements with a machine-readable JSON output when the
   report pipeline wants structured per-cipher data.

## Verification
A TLS 1.0 / 1.1 or SSLv3 negotiation is proof-confirmed. Weak-cipher
findings carry a specific OpenSSL cipher name in the finding — don't
flatten them to "weak ciphers enabled" without the list.

## Known pitfalls
- testssl.sh output has ANSI color codes even with `--color 0` on older
  builds. The normalizer strips them; don't post-process yourself.
- A target behind a WAF/CDN usually shows the CDN's TLS posture, not the
  origin's. Record which host actually terminated the connection.
