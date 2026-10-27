---
id: scan-web-dast
title: DAST on discovered parameters
phase: scan
target_kinds: [web]
when_to_use: >-
  Parameter-bearing URLs exist from `recon-param-discovery`, and the planner
  is ready to send payloads. Fuzzing a param URL is dramatically higher-signal
  than fuzzing a bare site root.
tools_available: [wapiti, nuclei_dast]
auth_sensitive: true
mitre_attack: [T1190]
cwe: [CWE-89, CWE-79]
owasp: [A03:2021]
confidence: high
version: 1
---

## When to use
After `recon-param-discovery` has produced seed URLs. P2 intrusive — these
tools send payloads; every invocation stays human-gated per policy.

## Workflow (advisory)
1. `wapiti` with `--start` per discovered endpoint. The governed builder
   also pins `--max-scan-time 240` + `--max-attack-time 60` (per-module) so
   one stuck module can't eat the subprocess budget — a real failure mode
   observed on DineHub port 5000 with 34 authenticated endpoints.
2. `nuclei_dast` for the same seeds, severity `low,medium,high,critical`.
   Uses `-dast` (not the deprecated `-fuzz`, and not the invalid
   `-fuzzing-templates` which exits 2 and emits nothing).
3. Seed refresh happens at EXECUTE time, not plan time — otherwise
   auth-discovered routes are invisible to the fuzzers.

## Verification
A finding from either tool is `candidate`, not `confirmed`. Reachability
re-probes do NOT confirm active-scanner vuln findings — see
`validate-reachability`.

## Known pitfalls
- Default wapiti module set is narrow (`exec/file/sql/xss/ssrf/upload/
  redirect/ssl/permanentxss`) and silently skips csrf, xxe, crlf, timesql,
  backup, takeover. The governed builder forces the expanded set.
