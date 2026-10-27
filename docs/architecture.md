# VAPT-AI V2 architecture (as built — Week 1 foundation)

A modular monolith with separate processes for **API**, **orchestration**, and
**tools/workers**. See `docs/v2-plan/VAPT-AI-V2-Project-Plan.md` for the full blueprint.

```
Browser ── Next.js (apps/web) ──▶ /api/* proxy ──▶ FastAPI (services/api)
                                                     │  auth (Argon2id + sessions, RBAC)
                                                     │  engagements / scope / runs
                                                     ▼
                                           MariaDB (packages/persistence)
                                           + transactional outbox
                                                     │
                                           Redis / Celery (services/orchestrator)
                                                     ▼
                                    LangGraph StateGraph (shared bounded state)
                                      intake → plan → recon(1 safe P0 tool) → report
                                                     │
                              policy engine (packages/policy, deny-by-default)
                              tool registry + broker (packages/tools, argv-only)
                              LLM gateway (packages/llm_gateway, provider-independent)
```

## Packages
- `packages/domain` — enums + Pydantic contracts (no framework/DB coupling).
- `packages/persistence` — SQLAlchemy models (additive schema), engine/session.
- `packages/policy` — deterministic P0–P3 decisions. Never a model prompt.
- `packages/tools` — tool registry, safe argv builders, broker (shell disabled).
- `packages/llm_gateway` — one `invoke()` interface over Ollama / hosted providers.

## Services
- `services/api` (`vapt_api`) — FastAPI; owns authorization on every endpoint.
- `services/orchestrator` (`vapt_orch`) — Celery worker + LangGraph graph.

## Security invariants already enforced in code
1. **Deny-by-default**: out-of-scope and cloud-metadata targets are denied with no
   approval path; P3 actions are denied; P2 always needs approval (white-box included).
2. **No shell**: tools run as validated argv arrays; option-like targets are rejected.
3. **No self-signed tokens**: Argon2id passwords, opaque revocable sessions (hash-at-rest).
4. **Durable, idempotent runs**: outbox + stable idempotency keys so re-delivery resumes
   the same LangGraph thread instead of starting a second run.
5. **Candidate ≠ confirmed**: findings carry status; validation is a separate step.

## Week 1 exit gate — met
A scoped run persists a task, executes one safe tool (`dns_resolve`, P0) and completes
one model call path (gateway wired; model call is exercised when a profile is configured).
Verified by `tests/` (17 passing): policy matrix, argv safety, graph flow, full API slice.

## Not yet built (later milestones)
Agent harness + manifests, approval interrupts, scanner adapters (Nmap/Nuclei/ZAP/Nessus/
Burp), evidence viewer, source static analysis, reporting, migration, recovery, hardening.
Tracked in Linear project **VAPT-AI V2 (Internal Beta)**.
