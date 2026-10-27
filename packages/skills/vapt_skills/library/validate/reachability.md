---
id: validate-reachability
title: Honest reachability confirmation
phase: validate
target_kinds: [web, network, host]
when_to_use: >-
  A candidate finding exists and the validation step must decide whether to
  promote it to `confirmed`. Not all finding classes can be confirmed by
  reachability — most active-scanner vuln findings cannot.
tools_available: [http_probe, nmap_service_scan, tls_check]
mitre_attack: []
owasp: []
confidence: high
version: 1
---

## When to use
As the first step of validation on EVERY candidate. The call either
confirms the service / port finding, or declines to confirm (not refutes)
an active-scanner vulnerability finding.

## Workflow (advisory)
1. For a service / open-port / banner finding, a reachability re-probe
   (`http_probe` or `nmap_service_scan`) that reproduces the observation
   is sufficient to mark `confirmed`.
2. For an active-scanner vulnerability finding (SQLi, XSS, SSTI, LFI,
   SSRF, open-redirect, IDOR), a reachability re-probe is NOT a
   confirmation. Status stays `candidate` pending a Tier-2 confirmer.

## Verification rule
`phases.validate_candidate` + `_is_reachability_confirmable` enforce this.
Do not propose a path that uses `http_probe` as "proof" of a payload
finding — the function explicitly refuses that mapping.

## Known pitfalls
- A SQLi, XSS, or SSTI candidate that comes back on a reachability re-probe
  looks like a confirmation but isn't. V1 shipped findings this way and
  burned trust on false confirmations — V2 explicitly fixes it.
