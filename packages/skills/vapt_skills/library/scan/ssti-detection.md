---
id: scan-ssti-detection
title: Server-side template injection detection
phase: scan
target_kinds: [web]
when_to_use: >-
  A reflected-XSS candidate was raised on a param that looks server-rendered
  (admin pages, announcement banners, feedback echo), OR the stack
  fingerprint names a template engine (Jinja2/Flask, ERB/Rails, Twig/Symfony,
  Freemarker/Spring). SSTI often masquerades as XSS to the first scanner.
tools_available: [ssti_detect]
auth_sensitive: true
mitre_attack: [T1221]
cwe: [CWE-1336]
owasp: [A03:2021]
confidence: high
version: 1
---

## When to use
As a confirmation step for a wapiti reflected-XSS candidate on an admin or
templated route, or when `recon-web-fingerprint` identified a template engine
and the current endpoint accepts user text.

## Workflow (advisory)
1. `ssti_detect` with the full endpoint URL (and optional `data=` for a
   POST sink). Detection only — the governed builder NEVER exposes
   `--os-cmd`, `--os-shell`, `--eval`, or `--upload`.
2. Pass an engine hint when `phases.infer_template_engine` returned one
   from httpx tech-detect (Werkzeug / Flask → Jinja2). Hint cuts runtime
   from 25+ plugin probes to one.

## Verification
sstimap confirms by executing a math-expression payload and matching the
rendered result (`{{7*7}}` → `49`). A match is proof-confirmed and promotes
the finding from `candidate` to `confirmed`.

## Known pitfalls
- Scope: `ssti_detect` is P2 intrusive and SCAN/VALIDATE-only. The upstream
  catalog `sstimap` entry stays ATTACK-only (that invariant is tested).
