---
id: scan-graphql-introspection
title: GraphQL introspection / mutation audit
phase: scan
target_kinds: [web]
when_to_use: >-
  The target exposes a `/graphql`, `/api/graphql`, or `/query` endpoint,
  or the response fingerprint names Apollo / Hasura / Relay. GraphQL
  endpoints often leak the full schema (via introspection) and permit
  query batching that bypasses rate limiting.
tools_available: [graphql_cop, nuclei_safe]
auth_sensitive: true
mitre_attack: [T1190]
cwe: [CWE-200]
owasp: [A05:2021]
confidence: high
version: 1
---

## When to use
Immediately when a GraphQL endpoint is detected. The introspection check
is cheap (one query) and the schema it returns feeds every subsequent
mutation / query probe.

## Workflow (advisory)
1. `graphql_cop` runs a bounded set of GraphQL-specific checks:
   introspection, mutation availability, aliasing abuse, depth limits.
2. `nuclei_safe` templates add known-CVE / known-misconfig coverage.

## Verification
A `__schema` response is proof-confirmed introspection. Confirming
further issues (unauthenticated mutations, aliasing DoS) is Tier-2 work
and needs a specialized probe.

## Known pitfalls
- Introspection being open is sometimes intentional (public API, docs
  generation). Don't auto-raise severity without checking the engagement's
  policy context first.
