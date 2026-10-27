---
id: scan-masscan-sweep
title: High-rate port sweep (gated)
phase: scan
target_kinds: [network]
when_to_use: >-
  The engagement scope is a /16 or larger, the operator has explicitly
  authorized a high-rate sweep, AND the target network is prepared for
  the traffic. masscan is intrusive by construction — it will trigger
  IDS and may saturate smaller links.
tools_available: [masscan]
mitre_attack: [T1046]
cwe: []
owasp: []
confidence: medium
version: 1
---

## When to use
Rare. Prefer `scan-port-sweep-fast` (naabu, P1) unless the scope is
genuinely too large for naabu's rate budget. masscan is P2 — always
human-gated at execution.

## Workflow (advisory)
1. `masscan` with the governed rate `--rate 1000` on `-p1-1000`. The
   catalog spec locks these; a scan step must not propose a higher rate.
2. Pair with `nmap_service_scan` on the resulting open-port set for
   version info — masscan does not do service detection.

## Verification
Open-port lists are directly observable. False-positive closes are rare
at the governed rate, but false-positive OPENS from retries happen —
verify any suspicious port with a confirmation probe.

## Known pitfalls
- A masscan run against a target behind a stateful firewall with
  connection limits can WEDGE the firewall briefly. The policy engine
  requires explicit approval precisely to prevent this from happening
  without an operator in the loop.
