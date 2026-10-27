---
id: scan-waf-detect
title: WAF detection and probe behavior
phase: scan
target_kinds: [web]
when_to_use: >-
  Payload-sending scanners show inconsistent results, OR the engagement
  pre-brief mentions a WAF (Cloudflare, AWS WAF, F5, Imperva). Detect it
  before fuzzing so downstream findings can be interpreted — a WAF-blocked
  payload isn't the same as a vuln-free app.
tools_available: [wafw00f]
mitre_attack: [T1595]
cwe: []
owasp: []
confidence: medium
version: 1
---

## When to use
Once per target, early in the scan. Running wafw00f on every endpoint
is wasteful — it keys off the base response.

## Workflow (advisory)
1. `wafw00f` returns a WAF name + confidence. Null output means no WAF
   was detected OR the detection payload was blocked silently (both are
   relevant signals; record both).

## Verification
WAF detection isn't a finding — it's context for other findings. A
"no SQLi" report against a target behind Cloudflare WAF with aggressive
rules carries a different meaning than one against a bare origin.

## Known pitfalls
- `wafw00f` sends test payloads. If the operator wants a truly passive
  WAF-check path, the planner should NOT propose this skill.
