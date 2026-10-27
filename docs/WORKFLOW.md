# VAPT-AI V2 — How the Workflow Works

*Authorized VAPT platform. Architecture & engagement workflow as of 2026-10-14.*

This document describes how an engagement runs end to end: the agents, how they're wired,
the governed execution model, the CVE pipeline, external intel (Tenable.sc / Nessus), and
the live observability that was added so a run is never a black box.

---

## 1. The big picture

VAPT-AI V2 is a **governed, multi-agent** assessment engine. A human defines an engagement
(scope + what classes of action are allowed); the platform plans and runs a bounded set of
tools against the in-scope assets, matches findings to CVEs, corroborates them against
authenticated-scanner data, and produces a grounded report. **Nothing intrusive runs
without a deterministic policy decision, and every proof-of-concept is human-gated.**

```
  Web UI (Next.js)
       │  create engagement, start run, approve/reject, read ledger & report
       ▼
  API (FastAPI)  ──writes run + Outbox row in one txn──►  Outbox
       │                                                     │
       │                                       relay (beat) publishes
       ▼                                                     ▼
  MariaDB/MySQL  ◄────────────────  Celery worker  ◄──── Redis queue
       ▲                                  │
       │                    runs the LangGraph engagement graph
       │                                  │
       └───────────────  Governed Harness ─┴─ Tool Broker ─► scanners / shims
```

Core principle — **separation of powers**: a model (LLM) only *proposes* a `tool_id` + typed
args. It can never widen a decision. The **policy engine** decides; the **harness** enforces
scope; a **human** approves anything intrusive. Defense in depth: scope is checked in the
harness *and* (later) in the worker network path.

---

## 2. Services

| Service | Role |
|---|---|
| **vapt_api** (FastAPI) | Engagements, runs, approvals, findings, report, CVE search endpoints. Writes a run change **and** an Outbox row in one DB transaction. |
| **vapt_orch** (Celery worker) | Consumes the queue, runs the LangGraph engagement graph per run. |
| **Celery beat** | Drives the **transactional outbox relay** (hands queued runs to the worker) and scheduled tasks. |
| **Redis** | Celery broker. |
| **MariaDB / MySQL** | System of record (runs, findings, ledger, approvals, checkpoints). SQLite is only a dev fallback. |

> A run stuck at `queued` with a single `run.created` ledger entry means the **relay/worker/beat
> isn't consuming** — not a platform bug. All three (Redis, worker, beat) must be up.

---

## 3. The agents and how they're connected

The engagement is a **LangGraph** state machine. Each node is an agent/phase; a self-looping
scan node processes one action per visit so an `interrupt()` for approval never drifts the
resume value. Committed findings survive an interrupt (the DB, not graph state, is the source
of truth for what a phase produced).

```
 START → intake → plan → recon → scan ⭯ ─(plan exhausted)→ probe_services → validate → attack → remediate → report → END
                                   │                                             │
                              (one tool per visit;                        (PoC: human-gated,
                               approval → interrupt)                       opt-in only)
```

| Node | What it does |
|---|---|
| **intake** | Load the run's scope (domains/CIDRs, allowed action classes, allowed ports). |
| **plan** | Ask the LLM planner for a bounded scan plan; falls back to a safe default set (`nmap_service_scan`, `http_probe`, `nuclei_safe`) when the model is offline (`plan.proposed … source=fallback`). |
| **recon** | Establish reachability. For a bare IP, DNS resolution is skipped (not applicable). |
| **scan** | Self-looping: runs one planned tool per visit through the harness. `nmap -sT -sV -Pn -T3` discovers services **with versions**. `tls_check` is skipped when no TLS service was found. |
| **probe_services** | (a) **External intel ingest** (Tenable.sc + `.nessus`) — runs first, independent of the active scan; (b) httpx follow-up on non-standard web ports; (c) NSE host scripts; (d) Windows vuln checks; (e) service→CVE (vulners); (f) NVD CPE fallback; (g) OS-CPE leads. |
| **validate** | Independently re-checks each candidate. CVE candidates go through the 3-tier confirmation (below); others get a port-anchored re-probe. **Only this phase marks CONFIRMED.** |
| **attack** | **Opt-in and always human-gated.** Runs a PoC playbook (e.g. Burp evidence capture) against a confirmed HTTP finding only after a reviewer approves in the dock. Off by default. |
| **remediate** | Drafts remediation (grounded on confirmed findings; deterministic fallback when the model is offline). |
| **report** | Generates the HTML/PDF report (grounded; deterministic fallback when offline). |

---

## 4. Governed execution (the safety core)

Every tool call goes through **one** mandatory path: `GovernedHarness.run_action`.

1. **Capability check** — may this agent use this tool at all? (`ToolSpec.allowed_agents`).
2. **Proposal recorded** in the ledger (idempotent on an action digest/key).
3. **Deterministic policy decision** by `PolicyEngine` using the tool's **policy class**:
   - `P0_PASSIVE` — always allowed (read-only intel, passive checks).
   - `P1_LOW_IMPACT` — auto-allowed under a **signed profile** (lab engagements); otherwise needs approval.
   - `P2_INTRUSIVE` — **always** needs human approval.
   - `P3_EXCLUDED` — never runs.
4. **Scope enforcement** — the target must fall inside the engagement's domains/CIDRs
   (`network` tools); `local` tools act on the uploaded bundle instead.
5. **Act**: ALLOW → broker executes; REQUIRE_APPROVAL → create approval + `interrupt()`;
   DENY → record a **coverage gap** (so the report never claims coverage it didn't achieve).

The **Tool Broker** runs every tool **argv-only (`shell=False`)**, with `stdin=DEVNULL`, and
marks the outcome `ok` only when the exit code is in the tool's `ok_exit_codes`.

---

## 5. The CVE pipeline

Findings become CVEs through several independent matchers, then a 3-tier confirmation:

**Matching (candidates)**
- **`nmap_vuln` (vulners)** — service→CVE from `-sV --script vulners`.
- **NVD CPE fallback (`nvd_cpe`)** — detected product+version → NVD CVEs (works when vulners.com is unreachable; version required).
- **OS-CPE leads (`nvd_os_cpe`)** — the detected Windows version (from `rdp-ntlm-info` build / `smb-os-discovery`) → top-critical CVEs for that OS. **Precision-gated**: only CVEs where the OS CPE is the *vulnerable* component are kept (drops third-party-app-on-Windows noise). Labeled "OS version lead, patch unverified".
- **Windows vuln NSE** — `smb-vuln-ms17-010` (safe, P1, auto); `smb-vuln-ms08-067` + `rdp-vuln-ms12-020` (crash-risky, P2, human-gated).

**Confirmation (`validate_cve_candidate`) — tiers**
1. **CONFIRMED** — a safe on-target NSE check reported VULNERABLE, **or** the CVE's nuclei template fired on the host. (nuclei is **skipped** for OS-CPE leads — no templates exist for OS-level CVEs.)
2. **EXPLOIT_AVAILABLE** — not confirmed on-target, but public exploitation intel exists: **CISA KEV** (actively exploited) or an NVD exploit-tagged reference. Via public API — no local Exploit-DB.
3. **INCONCLUSIVE** — version/OS match only, no template hit, no known exploit.

CVE details are enriched from **NVD** (CVSS, description, references), cached 24h. `VAPT_NVD_API_KEY`
(free) raises the rate limit 5→50 req/30s.

**Finding statuses:** `candidate` → `confirmed` | `exploit_available` (stays candidate, strong lead) | `inconclusive`. Severity bands follow NVD CVSS thresholds.

---

## 6. External authenticated-scanner intel (Tenable.sc + Nessus)

A **read-only (P0 passive)** evidence stream that corroborates the active scan. Runs first in
`probe_services`, independent of the active scan or signed profile.

- **`tenable_scan`** → `workers/bin/vapt-tenable`: queries an existing **Tenable.sc** deployment's
  cumulative vuln data over the REST API, per in-scope host. Creds from env
  (`VAPT_TENABLE_URL` / `_ACCESS_KEY` / `_SECRET_KEY`) **or** V1's `~/.vapt_ai/tenable.json`.
  It does **not** scan — it serves what Tenable already has.
- **`nessus_import`** → `workers/bin/vapt-nessus-import`: parses an exported `.nessus` file
  offline (`VAPT_NESSUS_FILE` / `scope.nessus_path`). No network.

Both emit a shared JSONL shape → `_intel` normalizer → `ingest_external_intel`:
- A CVE that the active scan already found is **promoted to CONFIRMED** (Tenable corroboration), not duplicated.
- A CVE only Tenable knows becomes a **new confirmed** finding (authenticated scanner = real on-target evidence).
- `exploit=true` is treated like **CISA KEV**.
- Info/low items with no CVE (e.g. SMB-enumeration) are skipped so the report isn't flooded.

> Tenable requires its data to already exist for the host; it won't scan on demand. If a host
> isn't in Tenable's repositories (or the API account can't see it), you simply get 0 intel findings.

---

## 7. Approvals (human-in-the-loop)

When policy returns REQUIRE_APPROVAL, the graph **pauses** (`interrupt()`) and creates an
Approval. A global **floating approval dock** in the UI polls pending approvals and lets a
reviewer **approve/reject inline** (showing the tool, target, reason, and enriched detail) —
no need to open the run page. On approval, the worker resumes the graph on the same thread
via `Command(resume=…)`; a stale/duplicate resume is a safe no-op (guarded by the checkpoint's
pending state).

Intrusive actions that are gated: the P2 Windows vuln checks (ms08-067 / ms12-020) and every
attack-agent PoC.

---

## 8. Live observability (so a run is never a black box)

- **Streaming ledger** — the graph is driven with per-super-step commits, so the Execution
  Ledger fills in **phase by phase as each node finishes**, instead of all at once at the end.
- **Per-tool progress** — each tool publishes `action.executing` (tool, target, `started_at`)
  the moment it starts, and `action.executed` with `elapsed_seconds` when it finishes. The run
  page shows a live **"running Ns"** counter on an in-flight tool and **"took Ns"** when done.
- **No kill switch** — a legitimately long scan runs to completion; only its progress is published.
- **Coverage gaps** are recorded honestly: a denied, unavailable, or non-ok tool is noted so the
  report never claims coverage it didn't achieve.

Ledger event vocabulary (per run): `run.created/started/paused/completed/cancelled`,
`phase.{intake,recon,scan,probe,validate,attack,report}`, `plan.proposed`, `action.{proposed,
executing,executed,denied,blocked}`, `approval.{requested,decided}`, `finding.{candidate,
confirmed,inconclusive,exploit_available}`, `intel.ingested`.

---

## 9. Running an engagement (operator quickstart)

1. Bring up **Redis**, the **worker**, and **beat** (venv activated):
   ```bash
   bash scripts/dev.sh api      # if not already running
   bash scripts/dev.sh worker
   bash scripts/dev.sh beat
   ```
2. Create an engagement (scope = authorized domains/CIDRs), set **Allowed ports** and the
   **allowed action classes** (include P2 Intrusive only if you want the crash-risky Windows
   checks, which still require approval).
3. (Optional) Configure intel: `VAPT_TENABLE_*` or `~/.vapt_ai/tenable.json` for live Tenable.sc;
   `VAPT_NESSUS_FILE` for an offline `.nessus`.
4. (Optional) Set `VAPT_NVD_API_KEY` to speed up CVE enrichment.
5. Start the run. Watch the ledger fill in live; approve any gated action in the dock.
6. Read the report (exec summary, remediation, findings by severity, coverage gaps). Export PDF.

**Key env vars:** `VAPT_DATABASE_URL` (MySQL), `VAPT_NVD_API_KEY`, `VAPT_TENABLE_URL/_ACCESS_KEY/_SECRET_KEY`,
`VAPT_TENABLE_CREDS`, `VAPT_NESSUS_FILE`, and the shim bins `VAPT_*_BIN` (httpx, dnsx, testssl,
burp, tenable, nessus). See `.env.example`.

---

## 10. Security invariants (always true)

- Mobile/APK is **excluded** from V2.
- Model proposes, never authorizes; deny-by-default; argv-only (`shell=False`).
- Every PoC/attack is human-gated; crash-risky NSE scripts are P2 + approval.
- Secrets (LLM keys, Tenable keys) are referenced by env/file, **never stored in the ledger**.
- Intel and tool output are untrusted data — parsed into structured findings, never allowed to
  redefine scope or policy.
