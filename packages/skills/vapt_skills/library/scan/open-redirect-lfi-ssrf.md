---
id: scan-open-redirect-lfi-ssrf
title: Open-redirect / LFI / SSRF-local / sensitive-content / XXE
phase: scan
target_kinds: [web]
when_to_use: >-
  A parameter accepts a URL, a path, or an XML body — common on
  `/redirect?url=`, `/file?name=`, `/fetch?target=`, `/api/xml`. The
  deterministic probe fires one bounded payload per class and parses
  in-band proof.
tools_available: [web_param_probe]
auth_sensitive: true
mitre_attack: [T1190]
cwe: [CWE-601, CWE-22, CWE-918, CWE-611, CWE-200]
owasp: [A01:2021, A03:2021, A10:2021]
confidence: high
version: 1
---

## When to use
Instead of (not alongside) a full generic fuzzer for these specific classes.
`web_param_probe` is non-destructive by construction: one targeted GET per
class, one targeted POST where the class needs it.

## Workflow (advisory)
1. Invoke `web_param_probe` with the full URL and optional pinned
   `param` + `classes` subset (default = all).
2. For POST-only sinks (register/feedback/comment), set `method=post` and
   `content_type` to `application/x-www-form-urlencoded` or
   `application/json`.
3. The normalizer promotes any class marked `proof` in the probe's JSON
   output straight to a proof-confirmed finding via `_PROOF_SOURCE_TOOLS`.

## Verification
The probe emits a signature per class — the normalizer only accepts findings
with a signature match, not merely a payload echo. False positives from
generic fuzzers are the main reason this probe exists.

## Known pitfalls
- The probe runs under a 90s subprocess timeout. Point it at specific
  URLs; do not expect it to crawl.
