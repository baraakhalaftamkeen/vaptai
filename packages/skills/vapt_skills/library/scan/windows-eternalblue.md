---
id: scan-windows-eternalblue
title: Windows EternalBlue (safe detection)
phase: scan
target_kinds: [network, host]
when_to_use: >-
  Service scan detected SMB (445) on a Windows host and MS17-010 /
  EternalBlue coverage is required. The governed detection NEVER
  attempts exploitation — it fingerprints the vulnerability only.
tools_available: [win_vuln_scan]
mitre_attack: [T1210]
cwe: [CWE-20]
owasp: []
confidence: high
version: 1
---

## When to use
On every exposed SMB service in-scope. The underlying NSE script
(`smb-vuln-ms17-010`) is a safe fingerprint — it does NOT exploit, does
NOT risk crashing the host.

## Workflow (advisory)
1. `win_vuln_scan` on the SMB port set — bounded, safe category only.
2. If the host IS vulnerable, the finding stays `candidate` until an
   approved playbook (not configured today) confirms by exploit, which
   is attack-phase. The detection alone is proof enough for reporting
   purposes.

## Verification
NSE script output "LIKELY VULNERABLE" / "VULNERABLE" is proof-confirmed
by itself — the script's logic is deterministic.

## Known pitfalls
- `win_vuln_aggressive` (ms08-067, rdp-vuln-ms12-020) is intentionally a
  SEPARATE P2-intrusive tool — those scripts CAN crash the host. A
  skill cannot blur the line; the agent manifests enforce it.
