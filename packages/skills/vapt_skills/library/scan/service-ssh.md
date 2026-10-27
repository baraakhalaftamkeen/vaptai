---
id: scan-service-ssh
title: SSH service posture
phase: scan
target_kinds: [network, host]
when_to_use: >-
  Service scan detected SSH on 22 (or any port). Version-matched CVEs,
  weak-cipher support, and host-key fingerprinting are the standard
  deliverables for an SSH-exposed host.
tools_available: [nmap_service_scan, nuclei_cve, searchsploit]
mitre_attack: [T1595.002]
cwe: [CWE-326]
owasp: []
confidence: high
version: 1
---

## When to use
After `recon-service-scan` has reported an SSH banner. Brute-force of
SSH credentials is NOT in scope here — that's attack-phase.

## Workflow (advisory)
1. `nmap_service_scan -sV` on the SSH port returns the OpenSSH /
   Dropbear version string.
2. `nuclei_cve` with any CVE id the version matched (hand-off from
   `validate-cve-matching`).
3. `searchsploit --cve <id>` to record public-PoC availability for the
   report — offline DB, no host contact.

## Verification
A nuclei template hit on a pinned CVE is proof-confirmed. A version
match alone is `candidate` — vendor backports mask the fix.

## Known pitfalls
- Many hosts proxy SSH through a bastion; the banner is the bastion's,
  not the real host's. Record the hop count if observable (TTL cue).
