---
id: scan-sqli-detection
title: SQL injection detection on discovered parameters
phase: scan
target_kinds: [web]
when_to_use: >-
  Discovered query/form parameters exist on an HTTP(S) target, and SQLi is
  a plausible class for the stack (any DB-backed app). SQLi detection in V2
  is a DAST step; exploitation / data extraction is NOT in scope here.
tools_available: [wapiti, nuclei_dast, sqli_detect]
auth_sensitive: true
mitre_attack: [T1190]
cwe: [CWE-89]
owasp: [A03:2021]
confidence: medium
version: 1
---

## When to use
After `recon-param-discovery` has produced seed URLs. SQLi is one of the
module classes `wapiti` ships (`sql`, `timesql`) and `nuclei_dast` covers
with its DAST template set.

## Workflow (advisory)
1. `wapiti` with modules including `sql,timesql` (the governed builder
   already forces the expanded set).
2. `nuclei_dast` on the same seed URLs — complementary coverage for
   error-based + boolean payloads the wapiti patterns miss.

## Verification
- Wapiti's SQLi detection is **nondeterministic run-to-run** on the same
  endpoint. A single hit is not confirmation; two consecutive hits across
  independent probes raise confidence but do NOT change the finding status
  from `candidate` to `confirmed`.
- Reliable confirmation requires a bounded Tier-2 confirmer (planned
  `sqli_detect` wrapper over sqlmap, with no `--os-shell`, no `--dump`, no
  `--eval`). Until that lands, SQLi stays `candidate`.

## Known pitfalls
- `sqlmap` is NOT a scan-phase tool. It is catalogued as ATTACK-only and
  requires a human-approved playbook. A skill cannot bypass that; the
  planner has no path to schedule it.
