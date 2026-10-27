---
id: recon-service-scan
title: Bounded service / port discovery
phase: recon
target_kinds: [network, host]
when_to_use: >-
  The target is a host or network block, and the planner needs the service
  surface before any protocol-specific scanner is useful. Also the right
  first step when the user supplied an IP (not a URL) and web vs non-web is
  unknown.
tools_available: [nmap_service_scan, host_scripts]
mitre_attack: [T1046]
owasp: []
confidence: high
version: 1
---

## When to use
Always before protocol scanners (SMB, RDP, LDAP, TLS checks). The service
version strings also feed `validate-cve-matching` for a service→CVE lookup.

## Workflow (advisory)
1. `nmap_service_scan` with the engagement's authorized `ports` scope. Use
   `-sT -sV -Pn -T3` (non-privileged TCP connect, version detection, fixed
   timing). The planner must pin `ports` from scope — never a built-in
   default — or the scan silently narrows.
2. On confirmed Windows services (SMB 445, RDP 3389, NetBIOS 139), follow
   with `host_scripts` (safe NSE discovery category only).

## Known pitfalls
- Don't request `-A` or `--script "default or vuln"` here. Those drag in
  intrusive scripts that would need the P2 risk ceiling.
- `-sV` only probes ports it already found open, so the cost scales with the
  number of services — not the port range. Leaving the ports spec wide is
  cheaper than people expect.
