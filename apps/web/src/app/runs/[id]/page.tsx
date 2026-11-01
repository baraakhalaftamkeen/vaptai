"use client";

import type React from "react";
import { use, useCallback, useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import {
  api,
  type DiscoveryData,
  type Finding,
  type FindingEnrichment,
  type Observation,
  type Report,
  type RetestComparison,
  type Run,
  type RunEvent,
} from "@/lib/api";
import {
  Button,
  Empty,
  Panel,
  SeverityTag,
  ShortId,
  StatusTag,
} from "@/components/ui";

/* -------------------------------------------------------------------------- */
/*  Constants                                                                  */
/* -------------------------------------------------------------------------- */

const PHASE_EVENTS = new Set([
  "run.started", "run.completed", "run.paused", "run.cancelling",
  "phase.intake", "plan.proposed", "phase.recon", "phase.scan",
  "phase.validate", "phase.attack", "phase.analyze",
  "remediation.drafted", "report.generated", "phase.report",
]);

const TERMINAL = new Set(["completed", "cancelled", "failed"]);
const PAUSABLE = new Set(["queued", "running"]);

const SEVERITY_RANK: Record<string, number> = {
  critical: 5, high: 4, medium: 3, low: 2, info: 1,
};
const STATUS_RANK: Record<string, number> = {
  confirmed: 3, candidate: 2, inconclusive: 1,
};

function compareFindings(a: Finding, b: Finding): number {
  const sr = (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0);
  if (sr) return sr;
  const tr = (STATUS_RANK[b.status] ?? 0) - (STATUS_RANK[a.status] ?? 0);
  if (tr) return tr;
  return a.title.localeCompare(b.title);
}

const PHASE_LABEL: Record<string, string> = {
  intake: "Accepting the engagement",
  planning: "Planning the scan",
  recon: "Reconnaissance",
  scan: "Scanning for services",
  probe: "Probing discovered services",
  validate: "Validating findings",
  attack: "Proof-of-concept (awaiting approval)",
  remediate: "Drafting remediation",
  report: "Generating the report",
};

const GRAPH_PHASES = [
  "intake", "planning", "recon", "scan", "probe",
  "validate", "webvuln", "attack", "remediate", "report",
];

const PHASE_ICONS: Record<string, string> = {
  intake: "IN", planning: "PL", recon: "RC", scan: "SC", probe: "PB",
  validate: "VL", webvuln: "WV", attack: "AT", remediate: "RM", report: "RP",
};

const RESOLUTION_OPTIONS = [
  { value: "open", label: "Open" },
  { value: "resolved", label: "Resolved" },
  { value: "accepted_risk", label: "Accepted risk" },
  { value: "false_positive", label: "False positive" },
];

type Tab = "overview" | "ledger" | "graph" | "discovery";

/* -------------------------------------------------------------------------- */
/*  Helpers                                                                    */
/* -------------------------------------------------------------------------- */

function fmtElapsed(seconds: number): string {
  const s = Math.max(0, Math.floor(seconds));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  const r = s % 60;
  return r ? `${m}m ${r}s` : `${m}m`;
}

function Spinner({ className = "" }: { className?: string }) {
  return (
    <span
      className={`inline-block rounded-full border-2 border-line-strong border-t-accent animate-spin ${className}`}
      aria-hidden
    />
  );
}

function ProgressBanner({ status, phase }: { status: string; phase?: string | null }) {
  const queued = status === "queued";
  const label = (phase && PHASE_LABEL[phase]) || (queued ? "Waiting for a worker" : "Working");
  return (
    <div className="mb-4 flex items-center gap-3 border border-line bg-surface rounded px-4 py-3">
      <Spinner className="w-4 h-4" />
      <div className="min-w-0">
        <div className="text-sm font-medium">
          {queued ? "Queued" : "Run in progress"} — {label}
        </div>
        <div className="text-xs text-ink-3">
          {queued
            ? "The relay hands this to a worker within a few seconds; this page updates live."
            : "Results appear below as each phase completes — no need to refresh."}
        </div>
      </div>
      <div className="ml-auto h-1 w-24 overflow-hidden rounded bg-surface-2 shrink-0">
        <div className="h-full w-1/3 bg-primary/70 animate-[indeterminate_1.4s_ease-in-out_infinite]" />
      </div>
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/*  Tab bar                                                                    */
/* -------------------------------------------------------------------------- */

function TabBar({ active, onChange, counts }: {
  active: Tab;
  onChange: (t: Tab) => void;
  counts: { findings: number; events: number };
}) {
  const tabs: { id: Tab; label: string; badge?: number }[] = [
    { id: "overview", label: "Overview", badge: counts.findings },
    { id: "ledger", label: "Ledger", badge: counts.events },
    { id: "graph", label: "Agent graph" },
    { id: "discovery", label: "Discovery" },
  ];
  return (
    <div className="flex gap-0.5 border-b border-line mb-4">
      {tabs.map((t) => (
        <button
          key={t.id}
          onClick={() => onChange(t.id)}
          className={`px-4 py-2 text-sm border-b-2 transition-colors ${
            active === t.id
              ? "border-primary text-ink font-medium"
              : "border-transparent text-ink-3 hover:text-ink hover:border-line-strong"
          }`}
        >
          {t.label}
          {t.badge != null && t.badge > 0 && (
            <span className="ml-1.5 text-2xs tnum text-ink-3">({t.badge})</span>
          )}
        </button>
      ))}
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/*  Finding card with enrichment                                               */
/* -------------------------------------------------------------------------- */

const FINDING_DETAIL_KEYS: Array<{ key: string; label: string; mono?: boolean }> = [
  { key: "url", label: "URL", mono: true },
  { key: "method", label: "Method" },
  { key: "param", label: "Parameter", mono: true },
  { key: "parameter", label: "Parameter", mono: true },
  { key: "path", label: "Path", mono: true },
  { key: "class", label: "Class" },
  { key: "category", label: "Category" },
  { key: "kind", label: "Kind" },
  { key: "engine", label: "Engine" },
  { key: "payload", label: "Payload", mono: true },
  { key: "cwe", label: "CWE" },
  { key: "evidence", label: "Evidence" },
  { key: "info", label: "Info" },
  { key: "host", label: "Host", mono: true },
  { key: "reason", label: "Reason" },
  { key: "note", label: "Note" },
  { key: "excerpt", label: "Excerpt", mono: true },
  { key: "trace", label: "Probe trace" },
];
const FINDING_HIDE_KEYS = new Set(["confirmed", "http_request", "level"]);

function FindingCard({ finding }: { finding: Finding }) {
  const [open, setOpen] = useState(false);
  const [enrichment, setEnrichment] = useState<FindingEnrichment | null>(finding.enrichment);
  const [enrichLoading, setEnrichLoading] = useState(false);
  const [resolution, setResolution] = useState(finding.resolution_status || "open");
  const [notes, setNotes] = useState(finding.notes || "");
  const [saving, setSaving] = useState(false);
  const [showEvidence, setShowEvidence] = useState(false);

  const hasObs = finding.observations.length > 0;
  const displayTitle = enrichment?.human_title || finding.title;

  async function loadEnrichment() {
    if (enrichment || enrichLoading) return;
    setEnrichLoading(true);
    try {
      const res = await api.enrichFinding(finding.id);
      setEnrichment(res.enrichment);
    } catch (err) {
      console.warn("Enrichment failed for", finding.id, err);
    } finally {
      setEnrichLoading(false);
    }
  }

  function handleOpen() {
    const next = !open;
    setOpen(next);
    if (next && !enrichment) loadEnrichment();
  }

  async function saveChanges() {
    setSaving(true);
    try {
      await api.updateFinding(finding.id, { resolution_status: resolution, notes });
    } catch {
      // silent
    } finally {
      setSaving(false);
    }
  }

  const selectCls =
    "h-7 rounded bg-surface-2 border border-line text-xs text-ink px-2 pr-6 appearance-none " +
    "bg-[url('data:image/svg+xml;charset=utf-8,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%20width%3D%2210%22%20height%3D%226%22%3E%3Cpath%20d%3D%22M0%200l5%206%205-6z%22%20fill%3D%22%236b7c8f%22%2F%3E%3C%2Fsvg%3E')] " +
    "bg-[length:10px_6px] bg-[right_6px_center] bg-no-repeat focus:outline-none focus:border-primary";

  return (
    <div className="px-4 py-3 border-b border-line last:border-0">
      <button
        type="button"
        onClick={handleOpen}
        className="w-full text-left focus:outline-none focus:ring-1 focus:ring-blue-500/60 rounded-sm"
        aria-expanded={open}
      >
        <div className="flex items-center gap-2.5 mb-1 flex-wrap">
          <SeverityTag severity={finding.severity} />
          <StatusTag status={finding.status} />
          <ResolutionBadge status={resolution} />
          {finding.target_url && (
            <span className="mono text-2xs text-ink-3 truncate max-w-[200px]">{finding.target_url}</span>
          )}
          {hasObs && (
            <span className="text-2xs text-ink-3 mono">
              {finding.observations.length} evidence{finding.observations.length === 1 ? "" : "s"}
            </span>
          )}
          <span className="ml-auto text-2xs text-ink-3 shrink-0">
            {open ? "▴ hide" : "▾ details"}
          </span>
        </div>
        <div className="text-sm mb-1 break-words font-medium">{displayTitle}</div>
        {!open && hasObs && (
          <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-ink-3">
            <span>Sources</span>
            {Array.from(new Set(finding.observations.map((o) => o.source_tool))).map((s) => (
              <span
                key={s}
                className="mono text-2xs px-1.5 py-0.5 rounded-sm bg-surface-2 border border-line text-ink-2"
              >
                {s}
              </span>
            ))}
          </div>
        )}
      </button>

      {open && (
        <div className="mt-3 space-y-3 animate-[fadeIn_0.15s_ease-out]">
          {/* Enrichment section */}
          {enrichLoading && (
            <div className="flex items-center gap-2 text-xs text-ink-3 px-3 py-2 bg-surface-2 border border-line rounded-sm">
              <Spinner className="w-3 h-3" /> Generating analysis…
            </div>
          )}
          {enrichment && (
            <div className="space-y-2.5">
              <EnrichmentSection label="Description" content={enrichment.description} />
              <EnrichmentSection label="Impact" content={enrichment.impact} />
              <EnrichmentSection label="Steps to reproduce" content={enrichment.steps_to_reproduce} />
              <EnrichmentSection label="Recommendations" content={enrichment.recommendations} />
              <EnrichmentSection label="Evidence summary" content={enrichment.evidence_summary} />
              <button
                type="button"
                onClick={() => {
                  setEnrichment(null);
                  setEnrichLoading(true);
                  api.enrichFinding(finding.id, true)
                    .then((res) => setEnrichment(res.enrichment))
                    .catch(() => {})
                    .finally(() => setEnrichLoading(false));
                }}
                disabled={enrichLoading}
                className="text-2xs text-ink-3 hover:text-primary transition-colors"
              >
                Re-generate with LLM
              </button>
            </div>
          )}

          {/* Status & notes */}
          <div className="flex flex-wrap items-end gap-3 bg-surface-2 border border-line rounded-sm px-3 py-2.5">
            <div>
              <label className="text-2xs text-ink-3 block mb-1">Resolution</label>
              <select
                value={resolution}
                onChange={(e) => setResolution(e.target.value)}
                className={selectCls}
              >
                {RESOLUTION_OPTIONS.map((o) => (
                  <option key={o.value} value={o.value}>{o.label}</option>
                ))}
              </select>
            </div>
            <div className="flex-1 min-w-[200px]">
              <label className="text-2xs text-ink-3 block mb-1">Notes</label>
              <input
                type="text"
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
                placeholder="Add notes…"
                className="h-7 w-full rounded bg-surface border border-line text-xs text-ink px-2 placeholder:text-ink-3 focus:outline-none focus:border-primary"
              />
            </div>
            <Button onClick={saveChanges} disabled={saving}>
              {saving ? "Saving…" : "Save"}
            </Button>
          </div>

          {/* Evidence toggle */}
          {hasObs && (
            <div>
              <button
                type="button"
                onClick={() => setShowEvidence((v) => !v)}
                className="text-xs text-ink-3 hover:text-ink flex items-center gap-1"
              >
                {showEvidence ? "▴ Hide" : "▾ Show"} raw evidence ({finding.observations.length})
              </button>
              {showEvidence && (
                <div className="mt-2 space-y-2">
                  {finding.observations.map((o) => (
                    <ObservationBlock key={o.id} obs={o} />
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function ResolutionBadge({ status }: { status: string }) {
  const styles: Record<string, string> = {
    open: "text-primary bg-primary/10 border-primary/30",
    resolved: "text-ok bg-ok/10 border-ok/30",
    accepted_risk: "text-sev-medium bg-sev-medium/10 border-sev-medium/30",
    false_positive: "text-ink-3 bg-surface-2 border-line",
  };
  return (
    <span className={`text-2xs px-1.5 py-0.5 rounded-sm border ${styles[status] || styles.open}`}>
      {status.replace(/_/g, " ")}
    </span>
  );
}

function EnrichmentSection({ label, content }: { label: string; content: string }) {
  if (!content) return null;
  return (
    <div className="bg-surface-2 border border-line rounded-sm px-3 py-2">
      <div className="text-2xs text-ink-3 mb-1 uppercase tracking-wider">{label}</div>
      <div className="text-sm text-ink whitespace-pre-wrap">{content}</div>
    </div>
  );
}

function ObservationBlock({ obs }: { obs: Observation }) {
  const d = (obs.detail || {}) as Record<string, unknown>;
  const rendered = new Set<string>();
  const rows: Array<{ label: string; value: unknown; mono?: boolean }> = [];
  for (const { key, label, mono } of FINDING_DETAIL_KEYS) {
    if (key in d && d[key] !== null && d[key] !== undefined && d[key] !== "") {
      rendered.add(key);
      rows.push({ label, value: d[key], mono });
    }
  }
  const extraKeys = Object.keys(d).filter(
    (k) => !rendered.has(k) && !FINDING_HIDE_KEYS.has(k)
      && d[k] !== null && d[k] !== undefined && d[k] !== "",
  );
  return (
    <div className="border border-line rounded-sm bg-surface-2">
      <div className="px-3 py-1.5 border-b border-line flex items-center gap-2 text-xs">
        <span className="mono px-1.5 py-0.5 rounded-sm bg-surface-1 border border-line text-ink-2">
          {obs.source_tool}
        </span>
        <span className="text-ink-3">
          {new Date(obs.created_at).toLocaleTimeString()}
        </span>
      </div>
      <dl className="px-3 py-2 text-xs grid grid-cols-[auto_1fr] gap-x-3 gap-y-1.5">
        {rows.map((r) => (
          <ObservationRow key={r.label} label={r.label} value={r.value} mono={r.mono} />
        ))}
        {extraKeys.length > 0 && (
          <>
            <dt className="text-ink-3 pt-1">Other</dt>
            <dd className="pt-1">
              <pre className="mono text-2xs whitespace-pre-wrap break-all bg-surface-1 border border-line rounded-sm px-2 py-1 text-ink-2">
                {JSON.stringify(
                  Object.fromEntries(extraKeys.map((k) => [k, d[k]])),
                  null, 2,
                )}
              </pre>
            </dd>
          </>
        )}
      </dl>
    </div>
  );
}

function ObservationRow(
  { label, value, mono = false }: { label: string; value: unknown; mono?: boolean },
) {
  let body: React.ReactNode;
  if (Array.isArray(value)) {
    body = (
      <ul className="space-y-0.5 max-h-48 overflow-auto">
        {value.slice(0, 50).map((v, i) => (
          <li key={i} className={mono ? "mono text-2xs break-all text-ink-2" : "text-ink-2"}>
            {typeof v === "object" ? JSON.stringify(v) : String(v)}
          </li>
        ))}
        {value.length > 50 && (
          <li className="text-2xs text-ink-3">… and {value.length - 50} more</li>
        )}
      </ul>
    );
  } else if (typeof value === "object" && value !== null) {
    body = (
      <pre className="mono text-2xs whitespace-pre-wrap break-all bg-surface-1 border border-line rounded-sm px-2 py-1 text-ink-2">
        {JSON.stringify(value, null, 2)}
      </pre>
    );
  } else {
    const text = String(value);
    body = (
      <span className={mono ? "mono text-2xs break-all text-ink-2" : "text-ink-2 break-words"}>
        {text}
      </span>
    );
  }
  return (
    <>
      <dt className="text-ink-3">{label}</dt>
      <dd className="min-w-0">{body}</dd>
    </>
  );
}

/* -------------------------------------------------------------------------- */
/*  Ledger tab                                                                 */
/* -------------------------------------------------------------------------- */

function LedgerTab({ events, now }: { events: RunEvent[]; now: number }) {
  const [filter, setFilter] = useState("");

  const filtered = useMemo(() => {
    if (!filter) return events;
    const q = filter.toLowerCase();
    return events.filter((e) =>
      e.kind.toLowerCase().includes(q) ||
      JSON.stringify(e.payload).toLowerCase().includes(q),
    );
  }, [events, filter]);

  const finished = useMemo(() => {
    const s = new Set<string>();
    for (const e of events) {
      if (e.kind === "action.executed" && e.payload?.digest) s.add(String(e.payload.digest));
    }
    return s;
  }, [events]);

  if (events.length === 0) {
    return <Empty>No ledger entries yet.</Empty>;
  }

  return (
    <div>
      <div className="mb-3">
        <input
          type="text"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="Filter events…"
          className="h-8 w-full max-w-sm rounded bg-surface-2 border border-line text-xs text-ink px-3 placeholder:text-ink-3 focus:outline-none focus:border-primary"
        />
      </div>
      <Panel title="Execution ledger" meta={`${filtered.length} of ${events.length}`}>
        <ol className="px-4 py-3">
          {filtered.map((e) => {
            const isPhase = PHASE_EVENTS.has(e.kind);
            const p = (e.payload ?? {}) as Record<string, unknown>;
            const digest = p.digest ? String(p.digest) : "";
            const tool = p.tool ? String(p.tool) : "";
            const running = e.kind === "action.executing" && !!digest && !finished.has(digest);
            const elapsed =
              running && p.started_at
                ? fmtElapsed((now - Date.parse(String(p.started_at))) / 1000)
                : e.kind === "action.executed" && p.elapsed_seconds != null
                  ? fmtElapsed(Number(p.elapsed_seconds))
                  : "";

            const kindLabel = isPhase
              ? e.kind.replace("phase.", "Phase: ").replace("run.", "Run ").replace(".", " ")
              : e.kind;

            return (
              <li key={e.seq} className="flex gap-3 pb-3 last:pb-0">
                <div className="flex flex-col items-center shrink-0 pt-1">
                  {running ? (
                    <Spinner className="w-2.5 h-2.5" />
                  ) : (
                    <span
                      aria-hidden
                      className={`rounded-full ${isPhase ? "w-2 h-2 bg-primary" : "w-1.5 h-1.5 bg-line-strong"}`}
                    />
                  )}
                  <span aria-hidden className="w-px flex-1 bg-line mt-1" />
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex items-baseline gap-2 flex-wrap">
                    <span className={`text-sm ${running ? "text-ink font-medium" : isPhase ? "text-ink font-medium" : "text-ink-2"}`}>
                      {running && tool ? `Running ${tool}` : kindLabel}
                    </span>
                    {elapsed && (
                      <span className={`text-2xs tnum px-1.5 py-px rounded ${running ? "bg-primary/10 text-primary" : "text-ink-3"}`}>
                        {running ? `running ${elapsed}` : elapsed}
                      </span>
                    )}
                    <span className="text-2xs text-ink-3 tnum">
                      {new Date(e.created_at).toLocaleTimeString()}
                    </span>
                  </div>
                  {Object.keys(p).length > 0 && (
                    <div className="mono text-2xs text-ink-3 mt-0.5 break-all">
                      {Object.entries(p)
                        .filter(([k]) => k !== "digest" && k !== "tool")
                        .slice(0, 8)
                        .map(([k, v]) => `${k}=${typeof v === "object" ? JSON.stringify(v) : v}`)
                        .join("  ")}
                    </div>
                  )}
                </div>
              </li>
            );
          })}
        </ol>
      </Panel>
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/*  Agent graph tab                                                            */
/* -------------------------------------------------------------------------- */

function GraphTab({ events, currentPhase, status }: {
  events: RunEvent[];
  currentPhase: string | null;
  status: string;
}) {
  const completedPhases = useMemo(() => {
    const seen = new Set<string>();
    for (const e of events) {
      if (e.kind.startsWith("phase.")) {
        seen.add(e.kind.slice("phase.".length));
      }
    }
    return seen;
  }, [events]);

  const isTerminal = TERMINAL.has(status);
  const phaseIndex = currentPhase ? GRAPH_PHASES.indexOf(currentPhase) : -1;

  const activeAgents = useMemo(() => {
    const agents: Record<string, { tool: string; started: string }> = {};
    const done = new Set<string>();
    for (const e of events) {
      if (e.kind === "action.executing" && e.payload?.digest) {
        agents[String(e.payload.digest)] = {
          tool: String(e.payload.tool || "unknown"),
          started: String(e.payload.started_at || e.created_at),
        };
      }
      if (e.kind === "action.executed" && e.payload?.digest) {
        done.add(String(e.payload.digest));
      }
    }
    return Object.entries(agents)
      .filter(([d]) => !done.has(d))
      .map(([, v]) => v);
  }, [events]);

  return (
    <div className="space-y-6">
      {/* Phase pipeline visualization */}
      <Panel title="Phase pipeline">
        <div className="px-4 py-5">
          <div className="flex items-center gap-1 overflow-x-auto pb-2">
            {GRAPH_PHASES.map((phase, i) => {
              const completed = completedPhases.has(phase);
              const active = phase === currentPhase && !isTerminal;
              const upcoming = !completed && !active;

              return (
                <div key={phase} className="flex items-center gap-1 shrink-0">
                  <div
                    className={`flex flex-col items-center gap-1.5 px-3 py-2.5 rounded border transition-all ${
                      active
                        ? "border-primary bg-primary/10 shadow-[0_0_12px_rgba(193,2,48,0.1)]"
                        : completed
                          ? "border-ok/40 bg-ok/5"
                          : "border-line bg-surface-2"
                    }`}
                  >
                    <div
                      className={`w-8 h-8 rounded-full flex items-center justify-center text-xs font-medium ${
                        active
                          ? "bg-primary text-white"
                          : completed
                            ? "bg-ok/20 text-ok"
                            : "bg-surface text-ink-3"
                      }`}
                    >
                      {completed && !active ? "✓" : PHASE_ICONS[phase]}
                    </div>
                    <span className={`text-2xs ${active ? "text-ink font-medium" : completed ? "text-ok" : "text-ink-3"}`}>
                      {phase}
                    </span>
                    {active && (
                      <span className="w-1.5 h-1.5 rounded-full bg-primary animate-[signal-pulse_2.4s_ease-in-out_infinite]" />
                    )}
                  </div>
                  {i < GRAPH_PHASES.length - 1 && (
                    <div
                      className={`w-6 h-0.5 shrink-0 ${
                        completed && (i < phaseIndex || isTerminal)
                          ? "bg-ok/40"
                          : "bg-line"
                      }`}
                    />
                  )}
                </div>
              );
            })}
          </div>
        </div>
      </Panel>

      {/* Active agents */}
      <Panel title="Active agents" meta={activeAgents.length > 0 ? `${activeAgents.length} running` : undefined}>
        {activeAgents.length === 0 ? (
          <Empty>{isTerminal ? "Run completed — no active agents." : "No agents running right now."}</Empty>
        ) : (
          <div className="px-4 py-3 space-y-2">
            {activeAgents.map((a, i) => (
              <div key={i} className="flex items-center gap-3 bg-surface-2 border border-line rounded px-3 py-2">
                <Spinner className="w-3 h-3" />
                <span className="mono text-xs text-ink">{a.tool}</span>
                <span className="text-2xs text-ink-3">
                  started {new Date(a.started).toLocaleTimeString()}
                </span>
              </div>
            ))}
          </div>
        )}
      </Panel>

      {/* Phase event timeline */}
      <Panel title="Phase transitions" meta={`${events.filter((e) => PHASE_EVENTS.has(e.kind)).length}`}>
        <div className="px-4 py-3 space-y-1.5">
          {events
            .filter((e) => PHASE_EVENTS.has(e.kind))
            .map((e) => (
              <div key={e.seq} className="flex items-center gap-3 text-xs">
                <span className="w-2 h-2 rounded-full bg-accent shrink-0" />
                <span className="text-ink font-medium">
                  {e.kind.replace("phase.", "").replace("run.", "").replace(".", " ")}
                </span>
                <span className="text-ink-3 tnum">{new Date(e.created_at).toLocaleTimeString()}</span>
              </div>
            ))}
          {events.filter((e) => PHASE_EVENTS.has(e.kind)).length === 0 && (
            <Empty>No phase events yet.</Empty>
          )}
        </div>
      </Panel>
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/*  Discovery tab                                                              */
/* -------------------------------------------------------------------------- */

function DiscoveryTab({ runId }: { runId: string }) {
  const [data, setData] = useState<DiscoveryData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.runDiscovery(runId)
      .then((d) => { setData(d); setLoading(false); })
      .catch((e) => { setError(String(e)); setLoading(false); });
  }, [runId]);

  if (loading) {
    return (
      <div className="flex items-center gap-2 text-sm text-ink-2 py-6">
        <Spinner className="w-4 h-4" /> Loading discovery data…
      </div>
    );
  }
  if (error) return <Empty>{error}</Empty>;
  if (!data) return <Empty>No discovery data.</Empty>;

  const hasAny = data.subdomains.length > 0 || data.live_targets.length > 0
    || data.urls.length > 0 || data.parameters.length > 0
    || data.forms.length > 0 || data.technologies.length > 0;

  if (!hasAny) {
    return <Empty>No discovery data recorded for this run yet. Data appears as the scan progresses.</Empty>;
  }

  return (
    <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
      {data.subdomains.length > 0 && (
        <DiscoveryPanel title="Subdomains" count={data.subdomains.length}>
          {data.subdomains.map((s) => (
            <div key={s} className="mono text-xs text-ink-2 py-1 border-b border-line last:border-0 px-3">{s}</div>
          ))}
        </DiscoveryPanel>
      )}

      {data.live_targets.length > 0 && (
        <DiscoveryPanel title="Live targets" count={data.live_targets.length}>
          {data.live_targets.map((t) => (
            <div key={t} className="mono text-xs text-ink-2 py-1 border-b border-line last:border-0 px-3">{t}</div>
          ))}
        </DiscoveryPanel>
      )}

      {data.urls.length > 0 && (
        <DiscoveryPanel title="URLs & endpoints" count={data.urls.length}>
          <div className="max-h-96 overflow-auto">
            {data.urls.map((u) => (
              <div key={u} className="mono text-2xs text-ink-2 py-1 border-b border-line last:border-0 px-3 break-all">{u}</div>
            ))}
          </div>
        </DiscoveryPanel>
      )}

      {data.parameters.length > 0 && (
        <DiscoveryPanel title="Parameters" count={data.parameters.length}>
          <div className="max-h-96 overflow-auto">
            <div className="grid grid-cols-[1fr_auto] text-2xs text-ink-3 uppercase tracking-wider px-3 py-1 border-b border-line">
              <span>URL</span><span>Parameter</span>
            </div>
            {data.parameters.map((p, i) => (
              <div key={i} className="grid grid-cols-[1fr_auto] text-xs py-1 border-b border-line last:border-0 px-3">
                <span className="mono text-2xs text-ink-3 truncate">{p.url}</span>
                <span className="mono text-xs text-ink-2">{p.param}</span>
              </div>
            ))}
          </div>
        </DiscoveryPanel>
      )}

      {data.technologies.length > 0 && (
        <DiscoveryPanel title="Technologies" count={data.technologies.length}>
          <div className="flex flex-wrap gap-1.5 px-3 py-2">
            {data.technologies.map((t) => (
              <span key={t} className="text-xs px-2 py-0.5 rounded bg-surface-2 border border-line text-ink-2">{t}</span>
            ))}
          </div>
        </DiscoveryPanel>
      )}

      {data.forms.length > 0 && (
        <DiscoveryPanel title="Forms" count={data.forms.length}>
          <div className="max-h-96 overflow-auto">
            {data.forms.map((f, i) => (
              <div key={i} className="py-2 px-3 border-b border-line last:border-0">
                <div className="mono text-2xs text-ink-2 break-all">
                  {String((f as Record<string, unknown>).action || (f as Record<string, unknown>).url || "unknown")}
                </div>
                <div className="text-2xs text-ink-3 mt-0.5">
                  {JSON.stringify(f).slice(0, 150)}
                </div>
              </div>
            ))}
          </div>
        </DiscoveryPanel>
      )}
    </div>
  );
}

function DiscoveryPanel({ title, count, children }: {
  title: string; count: number; children: React.ReactNode;
}) {
  return (
    <Panel title={title} meta={`${count}`}>
      {children}
    </Panel>
  );
}

/* -------------------------------------------------------------------------- */
/*  Report panel                                                               */
/* -------------------------------------------------------------------------- */

function ReportPanel({ runId, active = false }: { runId: string; active?: boolean }) {
  const [report, setReport] = useState<Report | null>(null);
  const [absent, setAbsent] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    api
      .getReport(runId)
      .then((r) => { setReport(r); setAbsent(false); })
      .catch((e) => { if (String(e).includes("404")) setAbsent(true); else setError(String(e)); });
  }, [runId]);
  useEffect(() => {
    load();
    if (!active) return;
    const t = setInterval(load, 4000);
    return () => clearInterval(t);
  }, [load, active]);

  async function act(kind: "regenerate" | "signoff") {
    setBusy(kind);
    setError(null);
    try {
      const r = kind === "regenerate" ? await api.regenerateReport(runId) : await api.signoffReport(runId);
      setReport(r);
    } catch (e) {
      const msg = String(e);
      setError(msg.includes("403") ? "You need the lead or reviewer role to sign off." : msg);
    } finally {
      setBusy(null);
    }
  }

  return (
    <Panel
      title="Report"
      meta={report ? report.status : undefined}
      action={
        report ? (
          <a
            href={api.reportDownloadUrl(runId, "html")}
            target="_blank"
            rel="noreferrer"
            className="text-xs text-primary hover:underline"
          >
            Open full report
          </a>
        ) : undefined
      }
    >
      {absent && !report ? (
        active ? (
          <div className="px-4 py-4 flex items-center gap-2.5 text-sm text-ink-2">
            <Spinner className="w-3.5 h-3.5" />
            The report is generated automatically when the run reaches reporting.
          </div>
        ) : (
          <Empty>No report yet. One is generated automatically when the run reaches reporting.</Empty>
        )
      ) : !report ? (
        <Empty>Loading…</Empty>
      ) : (
        <div className="px-4 py-4 space-y-3">
          {error && <p className="text-xs text-sev-high">{error}</p>}
          <div>
            <div className="text-xs text-ink-3 mb-1">Executive summary</div>
            <p className="text-sm">
              {report.summary || <span className="text-ink-3">No summary (model offline).</span>}
            </p>
          </div>
          <div>
            <div className="text-xs text-ink-3 mb-1">Remediation</div>
            <p className="text-sm">
              {report.remediation || <span className="text-ink-3">No remediation guidance (model offline).</span>}
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2 pt-1">
            <StatusTag status={report.status} />
            <Button onClick={() => act("regenerate")} disabled={busy !== null}>
              {busy === "regenerate" ? "Regenerating…" : "Regenerate"}
            </Button>
            {report.status !== "final" && (
              <Button variant="primary" onClick={() => act("signoff")} disabled={busy !== null}>
                {busy === "signoff" ? "Signing off…" : "Sign off"}
              </Button>
            )}
            <a
              href={api.reportDownloadUrl(runId, "pdf")}
              target="_blank"
              rel="noreferrer"
              className="text-xs text-ink-2 hover:text-primary"
            >
              PDF
            </a>
          </div>
        </div>
      )}
    </Panel>
  );
}

/* -------------------------------------------------------------------------- */
/*  Retest panel                                                               */
/* -------------------------------------------------------------------------- */

function RetestPanel({ runId }: { runId: string }) {
  const [cmp, setCmp] = useState<RetestComparison | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.getRetest(runId).then(setCmp).catch((e) => setError(String(e)));
  }, [runId]);

  const groups: [string, { title: string; severity: string }[]][] = cmp
    ? [["Fixed", cmp.fixed], ["Still open", cmp.still_open], ["New", cmp.new]]
    : [];

  return (
    <Panel
      title="Retest"
      meta={cmp ? `${cmp.counts.fixed} fixed · ${cmp.counts.still_open} open · ${cmp.counts.new} new` : undefined}
    >
      {error ? (
        <Empty>{error}</Empty>
      ) : !cmp ? (
        <Empty>Loading…</Empty>
      ) : (
        <div className="px-4 py-3 grid grid-cols-1 sm:grid-cols-3 gap-4">
          {groups.map(([label, items]) => (
            <div key={label}>
              <div className="text-xs text-ink-2 mb-1.5">
                {label} <span className="text-ink-3 tnum">({items.length})</span>
              </div>
              {items.length === 0 ? (
                <div className="text-2xs text-ink-3">—</div>
              ) : (
                <ul className="space-y-1">
                  {items.map((f, i) => (
                    <li key={i} className="flex items-center gap-2 text-xs">
                      <SeverityTag severity={f.severity} />
                      <span className="truncate">{f.title}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          ))}
        </div>
      )}
    </Panel>
  );
}

/* -------------------------------------------------------------------------- */
/*  Main page                                                                  */
/* -------------------------------------------------------------------------- */

export default function RunPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const router = useRouter();
  const [run, setRun] = useState<Run | null>(null);
  const [events, setEvents] = useState<RunEvent[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [now, setNow] = useState(() => Date.now());
  const [tab, setTab] = useState<Tab>("overview");

  const poll = useCallback(async () => {
    try {
      const [r, ev, f] = await Promise.all([
        api.getRun(id),
        api.runEvents(id, 0),
        api.runFindings(id),
      ]);
      setRun(r);
      setEvents(ev);
      setFindings(f);
      setError(null);
    } catch (e) {
      setError(String(e));
    }
  }, [id]);

  useEffect(() => {
    poll();
    const t = setInterval(poll, 4000);
    return () => clearInterval(t);
  }, [poll]);

  const latestPhase = (() => {
    for (let i = events.length - 1; i >= 0; i--) {
      const k = events[i].kind;
      if (k.startsWith("phase.")) return k.slice("phase.".length);
    }
    return run?.phase ?? null;
  })();

  const runActive = !!run && !TERMINAL.has(run.status ?? "");
  useEffect(() => {
    if (!runActive) return;
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, [runActive]);

  async function control(action: "pause" | "cancel") {
    setBusy(true);
    setError(null);
    try {
      await (action === "pause" ? api.pauseRun(id) : api.cancelRun(id));
      await poll();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function retest() {
    setBusy(true);
    setError(null);
    try {
      const nr = await api.retestRun(id);
      router.push(`/runs/${nr.id}`);
    } catch (e) {
      setError(String(e));
      setBusy(false);
    }
  }

  const confirmed = findings.filter((f) => f.status === "confirmed").length;
  const status = run?.status ?? "";
  const canPause = PAUSABLE.has(status);
  const canCancel = status !== "" && !TERMINAL.has(status);
  const canRetest = TERMINAL.has(status);
  const active = status !== "" && !TERMINAL.has(status);
  const hasReport = !active; // don't show progress banner once run is terminal

  return (
    <div className="max-w-[1180px]">
      <header className="mb-5 flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <div className="flex items-center gap-2.5">
            <h1 className="text-2xl font-semibold leading-tight">Run</h1>
            <span className="mono text-sm text-ink-3">{id.slice(0, 8)}</span>
            {run && <StatusTag status={run.status} />}
            {run?.auto_approve && (
              <span
                className="mono text-2xs px-2 py-0.5 rounded-sm bg-amber-500/15 text-amber-500 border border-amber-500/40"
                title="This run auto-approves every tool action — scope and policy still enforced, but no human gate"
              >
                AUTO-APPROVE
              </span>
            )}
          </div>
          <p className="text-sm text-ink-2 mt-0.5">
            {run?.engagement_name && <span>{run.engagement_name} · </span>}
            {latestPhase ? `phase ${latestPhase} · ` : ""}
            {findings.length} {findings.length === 1 ? "finding" : "findings"}
            {findings.length > 0 && ` · ${confirmed} confirmed`} ·{" "}
            {events.length} ledger {events.length === 1 ? "entry" : "entries"}
          </p>
        </div>
        <div className="flex gap-2 shrink-0">
          <Button onClick={() => control("pause")} disabled={busy || !canPause}>
            Pause
          </Button>
          <Button variant="danger" onClick={() => control("cancel")} disabled={busy || !canCancel}>
            Cancel
          </Button>
          <Button onClick={retest} disabled={busy || !canRetest}>
            Retest
          </Button>
        </div>
      </header>

      {error && (
        <p className="text-sm text-ink-2 border border-line bg-surface rounded px-4 py-3 mb-4">
          {error}
        </p>
      )}

      {active && <ProgressBanner status={status} phase={latestPhase} />}

      {run?.retest_of && (
        <div className="mb-4">
          <RetestPanel runId={id} />
        </div>
      )}

      <TabBar
        active={tab}
        onChange={setTab}
        counts={{ findings: findings.length, events: events.length }}
      />

      {tab === "overview" && (
        <div className="space-y-4">
          <ReportPanel runId={id} active={active} />

          <Panel title="Findings" meta={findings.length ? `${findings.length}` : undefined}>
            {findings.length === 0 ? (
              active ? (
                <div className="px-4 py-3 flex items-center gap-2.5 text-sm text-ink-2">
                  <Spinner className="w-3.5 h-3.5" />
                  Scanning… findings appear here as they're discovered and confirmed.
                </div>
              ) : (
                <Empty>
                  No findings recorded. Scan output becomes candidates, then validation confirms them.
                </Empty>
              )
            ) : (
              [...findings].sort(compareFindings).map((f) => (
                <FindingCard key={f.id} finding={f} />
              ))
            )}
          </Panel>
        </div>
      )}

      {tab === "ledger" && <LedgerTab events={events} now={now} />}

      {tab === "graph" && (
        <GraphTab events={events} currentPhase={latestPhase} status={status} />
      )}

      {tab === "discovery" && <DiscoveryTab runId={id} />}

      <p className="text-xs text-ink-3 mt-3">
        The ledger is append-only: every proposal, policy decision and execution is
        recorded with its action digest. <ShortId id={id} />
      </p>
    </div>
  );
}
