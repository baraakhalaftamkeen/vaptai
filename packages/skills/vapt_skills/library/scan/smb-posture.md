---
id: scan-smb-posture
title: SMB / NetBIOS posture audit
phase: scan
target_kinds: [network, host]
when_to_use: >-
  Service scan showed SMB (445/139), the target is a Windows / Samba
  host, and the engagement covers internal exposure. SMB enumeration
  exposes shares, users, OS version, and (if present) null-session
  readability — all common pivot points.
tools_available: [smbmap, enum4linux_ng, smbclient_list, host_scripts]
mitre_attack: [T1135, T1087]
cwe: [CWE-200]
owasp: []
confidence: high
version: 1
---

## When to use
When nmap reported 445 (or 139) open and in-scope. For a lab target the
null-session path is common; for production, the operator usually
supplies domain creds — the catalog tools accept them where applicable.

## Workflow (advisory)
1. `host_scripts` first — the governed NSE set (smb2-security-mode,
   smb-os-discovery, nbstat) is safe and often enough to grade the
   posture.
2. `smbclient_list -L -N` to list shares via null session. Exit 1 is
   not failure (no shares visible is a valid output).
3. `enum4linux_ng -A` or `smbmap -H <target>` for deeper enumeration.

## Verification
A listed share with read-anonymous access is proof-confirmed exposure.
smb-vuln-ms17-010 (EternalBlue) detection is a separate `win_vuln_scan`
tool — safe category only, never exploit.

## Known pitfalls
- enum4linux legacy and enum4linux-ng take the SAME `-A` flag but differ
  in output format. The governed builder tries both binary names.
