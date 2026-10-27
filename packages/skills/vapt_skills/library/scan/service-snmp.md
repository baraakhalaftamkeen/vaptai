---
id: scan-service-snmp
title: SNMP service posture
phase: scan
target_kinds: [network, host]
when_to_use: >-
  Service scan detected SNMP (UDP/161). Default community strings
  ("public", "private") still surface routinely on network kit and
  managed printers; a readable SNMP tree exposes OS, patch level,
  running processes, and sometimes credentials.
tools_available: [onesixtyone, nmap_service_scan]
mitre_attack: [T1046]
cwe: [CWE-521]
owasp: []
confidence: medium
version: 1
---

## When to use
When UDP/161 is reported open. `onesixtyone` is P2 — human-gated at
execution — because a community-string brute at scale lands in logs.

## Workflow (advisory)
1. `nmap_service_scan` with UDP probe is the lightweight first touch
   (banner, SNMP version).
2. `onesixtyone` tries a short bounded community-string list on the
   discovered target. Finding "public" or "private" readable is a
   direct exposure.

## Verification
A readable OID (e.g. `1.3.6.1.2.1.1.1.0` system description) with a
default community string is proof-confirmed. Record the OID that
returned data, not just "SNMP open".

## Known pitfalls
- SNMPv3 does not accept community strings. A `v3-only` target returns
  nothing to onesixtyone — not a bug, not a finding, just a coverage
  gap. Record it.
