---
id: scan-port-sweep-fast
title: Fast port sweep (bounded)
phase: scan
target_kinds: [network, host]
when_to_use: >-
  A large IP space is in scope and the engagement needs a quick ports
  survey before deciding where to focus. Naabu is faster than nmap's
  default service scan at the cost of less reliable version info.
tools_available: [naabu]
mitre_attack: [T1046]
cwe: []
owasp: []
confidence: high
version: 1
---

## When to use
On a /24 or larger scope, or when the operator wants fast triage. For a
single host, `recon-service-scan` (nmap_service_scan) is the better call
— it returns version info naabu does not.

## Workflow (advisory)
1. `naabu -host <target>` with the governed `-silent` flag. The
   discovered open ports feed `nmap_service_scan` for version detection.
2. For hosts with suspicious top-ports, run `host_scripts` on the open
   SMB/RDP/NetBIOS set.

## Verification
Open-port lists are directly observable in the output; "closed" ports
need a corroborating nmap SYN/CONNECT to confirm (naabu's negative
results have higher false-closed rates).

## Known pitfalls
- naabu's rate is tuned for Internet scanning. On an internal network
  with aggressive IDS, it will trigger alerts. Keep this to black-box
  external engagements.
