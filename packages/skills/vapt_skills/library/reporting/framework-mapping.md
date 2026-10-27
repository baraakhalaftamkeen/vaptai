---
id: report-framework-mapping
title: Framework-tag enrichment at report time
phase: reporting
target_kinds: [web, network, host, local]
when_to_use: >-
  A confirmed finding is being written into the report, and the renderer
  needs its MITRE ATT&CK / CWE / OWASP IDs. Skills in this library already
  carry the tags; the reporter looks up the matching skill by finding type.
tools_available: [http_probe]
mitre_attack: []
owasp: []
confidence: medium
version: 1
---

## When to use
On every confirmed finding during report rendering. Tag inheritance is
one-way (skill → finding), never the other way around — a finding cannot
pick a skill id and have the skill's workflow run.

## Workflow (advisory)
1. For a confirmed finding of class X, retrieve skills whose
   `mitre_attack` / `cwe` / `owasp` fields match X.
2. Attach the mapping to the finding record under `framework_refs`.
3. The report template renders the tags inline per finding.

## Verification
The skill library is the SOURCE of these mappings. If a finding's class is
not covered by any skill's tags, record the gap in `coverage_gaps` — do
not invent a mapping at render time.

## Known pitfalls
- `tools_available` on a reporting skill is listed only because the loader
  requires at least one. `http_probe` is a safe placeholder here (P1) — a
  future variant could drop that requirement.
