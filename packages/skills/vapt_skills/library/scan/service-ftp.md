---
id: scan-service-ftp
title: FTP service posture
phase: scan
target_kinds: [network, host]
when_to_use: >-
  Service scan detected FTP (21) or FTPS (990). Beyond anonymous login
  (still common on legacy / internal file shares), FTP servers often
  carry outdated vsftpd / proftpd / wu-ftpd versions with known CVEs.
tools_available: [nmap_service_scan, nmap_vuln]
mitre_attack: [T1595.002]
cwe: []
owasp: []
confidence: high
version: 1
---

## When to use
Whenever FTP shows open. On a modern production host, FTP presence is
itself a finding (SFTP/SCP is the right protocol); keep the exposure
observation in the report even without additional CVEs.

## Workflow (advisory)
1. `nmap_service_scan` for version detection on the FTP port.
2. `nmap_vuln` (vulners script) for version→CVE matching. Anonymous
   login detection is included in the broader NSE set.

## Verification
Anonymous read of the root directory is proof-confirmed exposure.
CVE matches stay `candidate` until a nuclei template or Tier-2 check
confirms exploitability.

## Known pitfalls
- Explicit FTPS (AUTH TLS) and implicit FTPS use different ports; the
  version banner differs after the TLS upgrade. Record which mode the
  server actually negotiated.
