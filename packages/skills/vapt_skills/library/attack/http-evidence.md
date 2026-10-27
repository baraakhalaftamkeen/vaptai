---
id: attack-http-evidence
title: Bounded HTTP evidence capture
phase: attack
target_kinds: [web]
when_to_use: >-
  A confirmed finding exists, the engagement has `allow_exploitation=True`
  AND an operator approves this specific action. One request, read-only.
tools_available: [burp_request, poc_screenshot]
mitre_attack: []
cwe: []
owasp: []
confidence: high
version: 1
---

## When to use
Only when `playbooks.get_playbook("http_evidence")` is the selected
`poc_playbook` on the engagement. The ATTACK agent cannot propose anything
else; the attack manifest's `allowed_tool_ids` is intentionally narrow
(`burp_request`, `poc_screenshot`, plus catalog ATTACK ids).

## Workflow (advisory)
1. `burp_request`: issues one approved request via the Burp MCP proxy and
   captures the response as evidence. Read / request only — no
   modification.
2. `poc_screenshot`: captures a screenshot of the confirmed issue as
   visual PoC evidence (V1 `poc_screenshot`). Bounded, single-shot.

## Verification
Every PoC action is forced through human approval by the ATTACK manifest's
`always_escalate` condition, regardless of its policy class. Approval
records the operator identity.

## Known pitfalls
- Do NOT propose anything else from the ATTACK catalog in this skill. A
  skill does not widen what the ATTACK agent may run; the playbook
  registry decides what is even allowed to be proposed.
