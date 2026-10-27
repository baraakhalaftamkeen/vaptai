---
id: scan-service-ldap
title: LDAP service posture
phase: scan
target_kinds: [network, host]
when_to_use: >-
  Service scan detected LDAP (389) or LDAPS (636). Anonymous bind is
  still a common misconfiguration on legacy / internal directory
  services and leaks the organizational tree.
tools_available: [ldapsearch_base, nmap_service_scan]
mitre_attack: [T1087.002]
cwe: [CWE-284]
owasp: []
confidence: medium
version: 1
---

## When to use
When 389 / 636 is open and in-scope. The governed `ldapsearch_base`
builder issues a bounded `-s base -b ""` request — one DSE query, no
subtree walk.

## Workflow (advisory)
1. `nmap_service_scan` with LDAP ports; captures the server banner.
2. `ldapsearch_base -x -H ldap://<target> -s base -b ""` — succeeds
   anonymously on servers that permit it. The DSE return reveals
   schema details and base DN hints.

## Verification
A non-empty DSE response under anonymous bind is proof-confirmed
information disclosure. Walking the tree (subtree scope) is NOT in
scope here — it is attack-phase.

## Known pitfalls
- Many Active Directory servers return a reduced DSE anonymously but
  reject subtree queries. The RootDSE alone is still a finding (it
  names the forest, domain functional level, supported SASL mechanisms).
