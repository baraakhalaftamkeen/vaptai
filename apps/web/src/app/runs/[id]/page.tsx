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

function groupKey(title: string): string {
  let key = title;
  key = key.replace(/\s+at\s+https?:\/\/.*$/i, "");
  key = key.replace(/\s+at\s+\/\S.*$/i, "");
  key = key.replace(/\s+on\s+parameter\s+'[^']*'/i, "");
  key = key.replace(/\s*\([^)]*\)\s*$/, "");
  return key.trim() || title;
}

function groupFindings(findings: Finding[]): { key: string; severity: string; items: Finding[] }[] {
  const sorted = [...findings].sort(compareFindings);
  const map = new Map<string, Finding[]>();
  const order: string[] = [];
  for (const f of sorted) {
    const k = groupKey(f.title);
    if (!map.has(k)) {
      map.set(k, []);
      order.push(k);
    }
    map.get(k)!.push(f);
  }
  return order.map((k) => {
    const items = map.get(k)!;
    const best = items.reduce((a, b) =>
      (SEVERITY_RANK[b.severity] ?? 0) > (SEVERITY_RANK[a.severity] ?? 0) ? b : a
    );
    return { key: k, severity: best.severity, items };
  });
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

const SEV_COLOR: Record<string, string> = {
  critical: "var(--sev-critical)",
  high: "var(--sev-high)",
  medium: "var(--sev-medium)",
  low: "var(--sev-low)",
  info: "var(--sev-info)",
};

function FindingGroup({ group }: { group: { key: string; severity: string; items: Finding[] } }) {
  const [open, setOpen] = useState(false);
  const count = group.items.length;

  if (count === 1) {
    return <FindingCard finding={group.items[0]} />;
  }

  const accentColor = SEV_COLOR[group.severity] ?? SEV_COLOR.info;
  const confirmedCount = group.items.filter((f) => f.status === "confirmed").length;
  const urls = new Set(group.items.map((f) => f.target_url).filter(Boolean));

  return (
    <div className="border-b border-line last:border-0">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="w-full text-left px-4 py-3.5 flex items-center gap-3 hover:bg-surface-hover/50 transition-colors focus:outline-none"
        style={{ borderLeft: `3px solid ${accentColor}` }}
      >
        <SeverityTag severity={group.severity} />
        <div className="min-w-0 flex-1">
          <div className="text-sm font-semibold truncate">{group.key}</div>
          <div className="flex items-center gap-2 mt-0.5 text-2xs text-ink-3">
            {confirmedCount > 0 && (
              <span>{confirmedCount} confirmed</span>
            )}
            {confirmedCount > 0 && confirmedCount < count && (
              <span className="text-ink-3/50">&middot;</span>
            )}
            {confirmedCount < count && (
              <span>{count - confirmedCount} candidate{count - confirmedCount === 1 ? "" : "s"}</span>
            )}
            {urls.size > 0 && (
              <>
                <span className="text-ink-3/50">&middot;</span>
                <span>{urls.size} endpoint{urls.size === 1 ? "" : "s"}</span>
              </>
            )}
          </div>
        </div>
        <span className="flex items-center gap-2.5 shrink-0">
          <span
            className="text-xs font-semibold px-2.5 py-1 rounded-md tnum"
            style={{ background: `color-mix(in srgb, ${accentColor} 12%, transparent)`, color: accentColor }}
          >
            {count}
          </span>
          <svg
            width="14"
            height="14"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2.5"
            strokeLinecap="round"
            strokeLinejoin="round"
            className={`text-ink-3 transition-transform duration-200 ${open ? "rotate-180" : ""}`}
          >
            <polyline points="6 9 12 15 18 9" />
          </svg>
        </span>
      </button>
      {open && (
        <div
          className="ml-4 border-l-2 bg-surface-2/30"
          style={{ borderColor: `color-mix(in srgb, ${accentColor} 30%, transparent)` }}
        >
          {group.items.map((f) => (
            <FindingCard key={f.id} finding={f} />
          ))}
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

interface PhaseBlock {
  phase: string;
  startedAt: string;
  endedAt: string | null;
  tools: { tool: string; elapsed: number | null; status: "done" | "running" }[];
}

function buildPhaseBlocks(events: RunEvent[]): PhaseBlock[] {
  const blocks: PhaseBlock[] = [];
  let cur: PhaseBlock | null = null;

  const executingTools = new Map<string, { tool: string; started: number }>();
  const doneDigests = new Set<string>();

  for (const e of events) {
    if (e.kind.startsWith("phase.") || e.kind === "plan.proposed"
        || e.kind === "remediation.drafted" || e.kind === "report.generated") {
      let phaseName: string;
      if (e.kind.startsWith("phase.")) phaseName = e.kind.slice("phase.".length);
      else if (e.kind === "plan.proposed") phaseName = "planning";
      else if (e.kind === "remediation.drafted") phaseName = "remediate";
      else phaseName = "report";

      if (cur && cur.phase !== phaseName) {
        cur.endedAt = e.created_at;
      }
      if (!cur || cur.phase !== phaseName) {
        cur = { phase: phaseName, startedAt: e.created_at, endedAt: null, tools: [] };
        blocks.push(cur);
      }
    }

    if (e.kind === "action.executing" && e.payload?.digest && cur) {
      const digest = String(e.payload.digest);
      const tool = String(e.payload.tool || "unknown");
      executingTools.set(digest, { tool, started: Date.parse(e.created_at) });
    }
    if (e.kind === "action.executed" && e.payload?.digest && cur) {
      const digest = String(e.payload.digest);
      doneDigests.add(digest);
      const started = executingTools.get(digest);
      const elapsed = e.payload.elapsed_seconds != null
        ? Number(e.payload.elapsed_seconds)
        : started ? (Date.parse(e.created_at) - started.started) / 1000 : null;
      const tool = started?.tool || String(e.payload.tool || "unknown");
      cur.tools.push({ tool, elapsed, status: "done" });
      executingTools.delete(digest);
    }

    if (e.kind.startsWith("run.")) {
      if (cur && (e.kind === "run.completed" || e.kind === "run.paused" || e.kind === "run.cancelling")) {
        cur.endedAt = e.created_at;
      }
    }
  }

  for (const [, v] of executingTools) {
    if (cur) cur.tools.push({ tool: v.tool, elapsed: null, status: "running" });
  }

  return blocks;
}

function PhaseRow({ block, isActive, isTerminal }: {
  block: PhaseBlock; isActive: boolean; isTerminal: boolean;
}) {
  const [open, setOpen] = useState(false);
  const phaseDone = !!block.endedAt;
  const duration = block.endedAt
    ? Math.round((Date.parse(block.endedAt) - Date.parse(block.startedAt)) / 1000)
    : null;
  const toolCount = block.tools.length;
  const runningCount = block.tools.filter((t) => t.status === "running").length;

  return (
    <div className="border-b border-line last:border-0">
      <button
        type="button"
        onClick={() => toolCount > 0 && setOpen((v) => !v)}
        className={`w-full text-left px-4 py-2 flex items-center gap-3 transition-colors ${toolCount > 0 ? "hover:bg-surface-hover/50 cursor-pointer" : "cursor-default"}`}
      >
        <div className={`w-5 h-5 rounded-full flex items-center justify-center text-2xs font-semibold shrink-0 ${
          isActive ? "bg-primary text-white" : phaseDone ? "bg-ok/20 text-ok" : "bg-surface-2 text-ink-3"
        }`}>
          {phaseDone && !isActive ? "✓" : PHASE_ICONS[block.phase]?.[0] || "?"}
        </div>
        <span className="text-xs font-semibold capitalize w-20 shrink-0">{block.phase}</span>
        {isActive && <span className="text-2xs px-1.5 py-0.5 rounded bg-primary/10 text-primary font-medium shrink-0">Active</span>}
        <span className="text-2xs tnum text-ink-3 w-20 shrink-0">{new Date(block.startedAt).toLocaleTimeString()}</span>
        {duration !== null && (
          <span className="text-2xs tnum text-ink-2 w-14 shrink-0">{fmtElapsed(duration)}</span>
        )}
        {isActive && runningCount > 0 && (
          <span className="flex items-center gap-1 text-2xs text-primary shrink-0">
            <Spinner className="w-2.5 h-2.5" /> {runningCount} running
          </span>
        )}
        <span className="flex-1" />
        {toolCount > 0 && (
          <span className="text-2xs tnum text-ink-3 shrink-0">{toolCount} tool{toolCount === 1 ? "" : "s"}</span>
        )}
        {toolCount > 0 && (
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"
            className={`text-ink-3 transition-transform duration-150 shrink-0 ${open ? "rotate-180" : ""}`}
          ><polyline points="6 9 12 15 18 9" /></svg>
        )}
      </button>
      {open && toolCount > 0 && (
        <div className="px-4 pb-2 pl-12">
          <div className="flex flex-wrap gap-1.5">
            {block.tools.map((t, ti) => (
              <span
                key={ti}
                className={`inline-flex items-center gap-1.5 mono text-2xs px-2 py-1 rounded border ${
                  t.status === "running"
                    ? "bg-primary/5 border-primary/30 text-primary"
                    : "bg-surface-2 border-line text-ink-2"
                }`}
              >
                {t.status === "running" ? <Spinner className="w-2.5 h-2.5" /> : <span className="w-1.5 h-1.5 rounded-full bg-ok shrink-0" />}
                {t.tool}
                {t.elapsed !== null && <span className="tnum text-ink-3">{fmtElapsed(t.elapsed)}</span>}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function GraphTab({ events, currentPhase, status }: {
  events: RunEvent[];
  currentPhase: string | null;
  status: string;
}) {
  const isTerminal = TERMINAL.has(status);
  const blocks = useMemo(() => buildPhaseBlocks(events), [events]);

  const completedPhases = useMemo(() => {
    const seen = new Set<string>();
    for (const b of blocks) if (b.endedAt) seen.add(b.phase);
    return seen;
  }, [blocks]);

  const phaseIndex = currentPhase ? GRAPH_PHASES.indexOf(currentPhase) : -1;

  const totalTools = blocks.reduce((s, b) => s + b.tools.length, 0);
  const runningTools = blocks.reduce((s, b) => s + b.tools.filter((t) => t.status === "running").length, 0);
  const totalDuration = blocks.reduce((s, b) => {
    if (!b.endedAt) return s;
    return s + (Date.parse(b.endedAt) - Date.parse(b.startedAt)) / 1000;
  }, 0);

  return (
    <div className="space-y-4">
      {/* Phase pipeline */}
      <Panel title="Phase pipeline">
        <div className="px-4 py-4">
          <div className="flex items-center gap-1 overflow-x-auto pb-1">
            {GRAPH_PHASES.map((phase, i) => {
              const completed = completedPhases.has(phase);
              const active = phase === currentPhase && !isTerminal;
              return (
                <div key={phase} className="flex items-center gap-1 shrink-0">
                  <div
                    className={`flex flex-col items-center gap-1 px-2.5 py-2 rounded border transition-all ${
                      active
                        ? "border-primary bg-primary/10 shadow-[0_0_12px_rgba(193,2,48,0.1)]"
                        : completed ? "border-ok/40 bg-ok/5" : "border-line bg-surface-2"
                    }`}
                  >
                    <div className={`w-7 h-7 rounded-full flex items-center justify-center text-2xs font-medium ${
                      active ? "bg-primary text-white" : completed ? "bg-ok/20 text-ok" : "bg-surface text-ink-3"
                    }`}>
                      {completed && !active ? "✓" : PHASE_ICONS[phase]}
                    </div>
                    <span className={`text-2xs ${active ? "text-ink font-medium" : completed ? "text-ok" : "text-ink-3"}`}>{phase}</span>
                    {active && <span className="w-1.5 h-1.5 rounded-full bg-primary animate-[signal-pulse_2.4s_ease-in-out_infinite]" />}
                  </div>
                  {i < GRAPH_PHASES.length - 1 && (
                    <div className={`w-5 h-0.5 shrink-0 ${completed && (i < phaseIndex || isTerminal) ? "bg-ok/40" : "bg-line"}`} />
                  )}
                </div>
              );
            })}
          </div>
        </div>
      </Panel>

      {/* Compact phase breakdown */}
      <Panel
        title="Execution timeline"
        meta={`${totalTools} tool${totalTools === 1 ? "" : "s"}${runningTools > 0 ? ` · ${runningTools} running` : ""} · ${fmtElapsed(totalDuration)}`}
      >
        {blocks.length === 0 ? (
          <Empty>No phase events yet.</Empty>
        ) : (
          blocks.map((block, bi) => (
            <PhaseRow key={bi} block={block} isActive={block.phase === currentPhase && !isTerminal} isTerminal={isTerminal} />
          ))
        )}
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
        <DiscoveryPanel title="Subdomains" count={data.subdomains.length} slug="subdomains" data={data.subdomains}>
          {data.subdomains.map((s) => (
            <div key={s} className="mono text-xs text-ink-2 py-1 border-b border-line last:border-0 px-3">{s}</div>
          ))}
        </DiscoveryPanel>
      )}

      {data.live_targets.length > 0 && (
        <DiscoveryPanel title="Live targets" count={data.live_targets.length} slug="live-targets" data={data.live_targets}>
          {data.live_targets.map((t) => (
            <div key={t} className="mono text-xs text-ink-2 py-1 border-b border-line last:border-0 px-3">{t}</div>
          ))}
        </DiscoveryPanel>
      )}

      {data.urls.length > 0 && (
        <DiscoveryPanel title="URLs & endpoints" count={data.urls.length} slug="urls" data={data.urls}>
          <div className="max-h-96 overflow-auto">
            {data.urls.map((u) => (
              <div key={u} className="mono text-2xs text-ink-2 py-1 border-b border-line last:border-0 px-3 break-all">{u}</div>
            ))}
          </div>
        </DiscoveryPanel>
      )}

      {data.parameters.length > 0 && (
        <DiscoveryPanel title="Parameters" count={data.parameters.length} slug="parameters" data={data.parameters}>
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
        <DiscoveryPanel title="Technologies" count={data.technologies.length} slug="technologies" data={data.technologies}>
          <div className="flex flex-wrap gap-1.5 px-3 py-2">
            {data.technologies.map((t) => (
              <span key={t} className="text-xs px-2 py-0.5 rounded bg-surface-2 border border-line text-ink-2">{t}</span>
            ))}
          </div>
        </DiscoveryPanel>
      )}

      {data.forms.length > 0 && (
        <DiscoveryPanel title="Forms" count={data.forms.length} slug="forms" data={data.forms}>
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

function downloadFile(filename: string, content: string, mime: string) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function toCSV(data: unknown[]): string {
  if (data.length === 0) return "";
  if (typeof data[0] === "string") return data.join("\n");
  const keys = Object.keys(data[0] as Record<string, unknown>);
  const header = keys.join(",");
  const rows = data.map((row) => {
    const r = row as Record<string, unknown>;
    return keys.map((k) => {
      const v = String(r[k] ?? "");
      return v.includes(",") || v.includes('"') || v.includes("\n")
        ? `"${v.replace(/"/g, '""')}"`
        : v;
    }).join(",");
  });
  return [header, ...rows].join("\n");
}

function ExportButtons({ slug, data }: { slug: string; data: unknown[] }) {
  return (
    <span className="flex gap-1 shrink-0">
      <button
        type="button"
        onClick={() => downloadFile(`${slug}.json`, JSON.stringify(data, null, 2), "application/json")}
        className="text-2xs px-1.5 py-0.5 rounded bg-surface-2 border border-line text-ink-3 hover:text-ink hover:border-primary/40 transition-colors"
      >
        JSON
      </button>
      <button
        type="button"
        onClick={() => downloadFile(`${slug}.csv`, toCSV(data), "text/csv")}
        className="text-2xs px-1.5 py-0.5 rounded bg-surface-2 border border-line text-ink-3 hover:text-ink hover:border-primary/40 transition-colors"
      >
        CSV
      </button>
    </span>
  );
}

function DiscoveryPanel({ title, count, slug, data, children }: {
  title: string; count: number; slug: string; data: unknown[]; children: React.ReactNode;
}) {
  return (
    <Panel
      title={title}
      meta={`${count}`}
      action={<ExportButtons slug={slug} data={data} />}
    >
      {children}
    </Panel>
  );
}

/* -------------------------------------------------------------------------- */
/*  Report panel                                                               */
/* -------------------------------------------------------------------------- */

function ReportPanel({ runId, active = false, runStatus = "", findingCount = 0 }: {
  runId: string; active?: boolean; runStatus?: string; findingCount?: number;
}) {
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
        ) : !active && findingCount > 0 && (runStatus === "cancelled" || runStatus === "failed") ? (
          <div className="px-4 py-3">
            <p className="text-xs text-ink-2 mb-2">
              Run {runStatus} before reaching the report phase. {findingCount} finding{findingCount === 1 ? "" : "s"} collected.
            </p>
            <Button
              onClick={() => act("regenerate")}
              disabled={busy !== null}
              variant="primary"
            >
              {busy === "regenerate" ? "Generating…" : "Generate Report from Findings"}
            </Button>
          </div>
        ) : (
          <Empty>No report yet. One is generated automatically when the run reaches reporting.</Empty>
        )
      ) : !report ? (
        <Empty>Loading…</Empty>
      ) : (
        <div className="px-4 py-3">
          {error && <p className="text-xs text-sev-high mb-2">{error}</p>}
          <div className="flex flex-wrap items-center gap-2">
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
    if (run?.phase) return run.phase;
    for (let i = events.length - 1; i >= 0; i--) {
      const k = events[i].kind;
      if (k.startsWith("phase.")) return k.slice("phase.".length);
    }
    return null;
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
          <ReportPanel runId={id} active={active} runStatus={status} findingCount={findings.length} />

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
              groupFindings(findings).map((g) => (
                <FindingGroup key={g.key} group={g} />
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
