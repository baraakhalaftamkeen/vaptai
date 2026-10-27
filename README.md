# VAPT-AI V2 (Internal Beta)

Authorized vulnerability-assessment & penetration-testing platform with evidence-linked
reporting. Rebuilt from the V1 prototype into a clean, modular monorepo. **Mobile is out
of scope for V2** (web, network, and white-box source only).

> ⚠️ Only run this against systems you are explicitly authorized to assess. Scope and a
> deny-by-default policy are enforced in code (`packages/policy`, `packages/tools`).

## Layout
```
apps/web/                Next.js frontend (login, dashboard, engagements, runs)
services/api/            FastAPI: auth (Argon2id + sessions, RBAC), engagements, runs
services/orchestrator/   Celery worker + LangGraph orchestrator
packages/domain/         enums + Pydantic contracts
packages/persistence/    SQLAlchemy models (additive schema) + session
packages/policy/         deterministic P0–P3 policy engine
packages/tools/          tool registry + argv-only broker
packages/llm_gateway/    provider-independent LLM gateway
migrations/              Alembic (initial schema generated)
infra/                   docker-compose + Dockerfiles
tests/                   17 tests (policy, tools, graph, full API slice)
docs/                    architecture, V1 triage, and the full V2 plan
```

## Quick start (local, SQLite + no external services)
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements/dev.txt
make test            # 17 passing
make api             # http://localhost:8000  (seeds a bootstrap admin on first run)
```
Frontend:
```bash
cd apps/web && npm install && npm run dev   # http://localhost:3000
```
Log in with the bootstrap admin from your `.env` (see `.env.example`). **Rotate that
password immediately.**

## Full stack (MariaDB + Redis + MinIO + API + worker + web)
```bash
cp .env.example .env     # fill in secrets
cd infra && docker compose up --build
```
Run migrations against MariaDB instead of the dev auto-create:
```bash
make migrate             # VAPT_DATABASE_URL must point at MariaDB
```

## Status
Week 1 foundation complete (BAR-5, BAR-6, BAR-7, BAR-8, BAR-9, BAR-10, BAR-11, BAR-12,
BAR-13, BAR-14). Progress tracked in Linear: **VAPT-AI V2 (Internal Beta)**.
See `docs/architecture.md` for what is and isn't built yet.
