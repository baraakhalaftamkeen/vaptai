---
id: scan-nuclei-template-sweep
title: General Nuclei template sweep
phase: scan
target_kinds: [web, network]
when_to_use: >-
  Target is reachable and the planner wants broad known-vuln coverage
  without a specific CVE in mind. Two risk tiers exist: `nuclei_safe`
  (info/low/medium, P1) and `nuclei_intrusive` (high/critical, P2 —
  human-gated at execution).
tools_available: [nuclei_safe, nuclei_intrusive]
mitre_attack: [T1595.002]
cwe: []
owasp: []
confidence: high
version: 1
---

## When to use
Early in scan phase for `nuclei_safe`; later (post-approval) for
`nuclei_intrusive`. The DAST-fuzzing variant (`nuclei_dast`) is a
different tool — see `scan-web-dast`.

## Workflow (advisory)
1. `nuclei_safe` with severity default (`info,low,medium`). Returns
   fingerprints, exposure patterns, config leaks.
2. `nuclei_intrusive` with `high,critical` only runs on human approval.
   The policy engine enforces this — a planner proposal does not
   change the classification.

## Verification
A nuclei template that fires carries its own matcher result — most are
deterministic signature matches, directly reportable as proof. A few
timing / blind templates stay `candidate` until re-checked.

## Known pitfalls
- The nuclei template store updates frequently; a run that catches
  nothing may be worth re-running after a template update.
- `-fuzz` is deprecated and `-fuzzing-templates` is NOT a valid flag
  (exit 2 with no output). The governed `nuclei_dast` uses `-dast`
  alone; do not propose the legacy flags.
