# V1 → V2 triage (BAR-14)

The V1 prototype in `/home/pt-team/Desktop/VAPT-AI` has useful domain logic but no
clean application boundary: many historical variants sit beside live code
(`vapt_web.py / web2 / web3 / web4`, `tenable_client.py / 22 / 333 / 444`,
`burp_mcp.py / 22 / 33`, `vapt_ai*.py`). V2 lives in a **new `vapt-ai-v2/` directory**
and the legacy app/DB are **not edited** during development.

## Canonical V1 file per concern

| Concern | Canonical V1 file (by size/mtime) | V2 home |
|---|---|---|
| Web assessment driver | `vapt_web.py` (36 KB, newest) | `services/orchestrator` + `packages/agents` (Wk3) |
| Agent entry | `vapt_ai.py` (newest of the `vapt_ai*` set) | `services/orchestrator` |
| DB layer | `db.py` | `packages/persistence` (rewritten, versioned) |
| Auth | `auth.py` | `services/api/vapt_api/security.py` + `deps.py` |
| LLM calls | `llm.py` | `packages/llm_gateway` |
| Scheduler | `scheduler.py` | `packages/*` + Celery Beat (Wk4/5) |
| Report/export | `report_gen.py` (newest), `export.py` | `packages/agents` reporting (Wk4) |
| Tenable/Nessus | `tenable_client.py` (35 KB, newest), `nessus_import.py` | `packages/tools` adapter (Wk3) |
| Burp | `burp_mcp.py` (newest), `mcp-burp-server/` | `packages/tools` adapter (Wk3) |
| Recon | `subdomain_recon.py`, `tools_network.py` | `packages/tools` adapters (Wk3) |
| CVE / intel | `cve_engine.py`, `intelx_client.py` | `packages/tools` (Wk3, IntelX = stretch) |
| PoC capture | `poc_screenshot.py` | `packages/agents` attack/PoC (Wk4) |
| UI | `web_ui.html` (+ v2/v3) | `apps/web` (Next.js) — **no raw untrusted HTML** |

The `*22`, `*33`, `*333`, `*444`, `(1)` duplicates are **reference only** — not ported.

## Dropped from V2 (mobile excluded per decision 2026-10-08)
`tools_mobile.py`, Android/APK static analysis, emulator/adb evidence, and any iOS
item. The plan's Week-4 "mobile" scope is replaced by **white-box source** only.

## Baseline defects explicitly not carried forward
- `db.py`: hard-coded DB creds (`metatron/123`) and no pooling → config + SQLAlchemy pool.
- `auth.py`: SHA-256 password hashing + self-signed base64 tokens → **Argon2id** + opaque,
  server-side **revocable sessions** (only the token hash is stored).
- `vapt_web.py`: unauthenticated scan WebSocket, unsafe HTML interpolation, arbitrary
  command endpoints → authenticated SSE, no raw HTML, **argv-only tool broker** (no shell).
- Disabled Tenable TLS verification → restored in the adapter (Wk3).
- `setup.sh`: wrong server filename / incomplete deps → replaced by Docker Compose + locked deps.
- Passive JSON schedule records with no executor → Celery-backed durable run jobs.

## Reused concepts (reworked, not copied)
Nessus parsing shape, report layout ideas, CVE/NVD lookup flow, Burp handshake knowledge.
All are rebuilt behind typed adapters with provenance, retries, and redaction.
