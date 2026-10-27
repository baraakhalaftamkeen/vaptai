"use client";

import type React from "react";
import { use, useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { api, type Finding, type Observation, type Report, type RetestComparison, type Run, type RunEvent } from "@/lib/api";
import {
  Button,
  Empty,
  Panel,
  SeverityTag,
  ShortId,
  StatusTag,
} from "@/components/ui";

/* Phase/lifecycle events anchor the timeline; action events are the detail between
 * them. Kept in sync with the engagement graph's node phases. */
const PHASE_EVENTS = new Set([
  "run.started",
  "run.completed",
  "run.paused",
  "run.cancelling",
  "phase.intake",
  "plan.proposed",
  "phase.recon",
  "phase.scan",
  "phase.validate",
  "phase.attack",
  "phase.analyze",
  "remediation.drafted",
  "report.generated",
  "phase.report",
]);

// A run in a terminal state can't be paused or cancelled.
const TERMINAL = new Set(["completed", "cancelled", "failed"]);
const PAUSABLE = new Set(["queued", "running"]);

// Severity rank (high = urgent) and status rank (confirmed outranks candidate) govern
// the Findings list order so operators see the real work at the top. Previously the list
// was DB insertion order, which buried CRITICAL confirmed findings under the dozens of
// INFO probe traces that fire late in the run.
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

// Human-readable phase labels for the progress banner.
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

// "2m 14s" / "9s" from a seconds value — compact elapsed for the ledger.
// Keys we understand how to render inline in the finding detail. Everything else is
// shown via the "Raw detail" expander. Order here = render order in the UI.
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
  { key: "language", label: "Language" },
  { key: "payload", label: "Payload", mono: true },
  { key: "cwe", label: "CWE" },
  { key: "evidence", label: "Evidence" },
  { key: "info", label: "Info" },
  { key: "host", label: "Host", mono: true },
  { key: "cookie_src", label: "Session source" },
  { key: "budget_used", label: "Budget used" },
  { key: "reason", label: "Reason" },
  { key: "note", label: "Note" },
  { key: "stderr_tail", label: "Stderr tail", mono: true },
  { key: "stdout_tail", label: "Stdout tail", mono: true },
  { key: "excerpt", label: "Excerpt", mono: true },
  { key: "sample", label: "Sample paths" },
  { key: "trace", label: "Probe trace" },
];
const FINDING_HIDE_KEYS = new Set(["confirmed", "http_request", "level"]);

function FindingCard({ finding }: { finding: Finding }) {
  const [open, setOpen] = useState(false);
  const hasObs = finding.observations.length > 0;
  const hasDesc = finding.description && finding.description.trim().length > 0;
  return (
    <div className="px-4 py-3 border-b border-line last:border-0">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="w-full text-left focus:outline-none focus:ring-1 focus:ring-blue-500/60 rounded-sm"
        aria-expanded={open}
      >
        <div className="flex items-center gap-3 mb-1">
          <SeverityTag severity={finding.severity} />
          <StatusTag status={finding.status} />
          {hasObs && (
            <span className="text-2xs text-ink-3 mono">
              {finding.observations.length} evidence
              {finding.observations.length === 1 ? "" : "s"}
            </span>
          )}
          <span className="ml-auto text-2xs text-ink-3">{open ? "▴ hide" : "▾ details"}</span>
        </div>
        <div className="text-sm mb-1 break-words">{finding.title}</div>
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
        <div className="mt-3 space-y-3">
          {hasDesc && (
            <div className="text-xs text-ink-2 whitespace-pre-wrap bg-surface-2 border border-line rounded-sm px-3 py-2">
              {finding.description}
            </div>
          )}
          {hasObs ? (
            finding.observations.map((o) => (
              <ObservationBlock key={o.id} obs={o} />
            ))
          ) : (
            <div className="text-xs text-ink-3">No evidence recorded.</div>
          )}
        </div>
      )}
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
  // Everything else that's non-empty, not hidden, and not already rendered.
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
                  null,
                  2,
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
  // Lists (trace/sample) render as a compact ul; everything else as text.
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
        <div className="h-full w-1/3 bg-accent/70 animate-[indeterminate_1.4s_ease-in-out_infinite]" />
      </div>
    </div>
  );
}

export default function RunPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const router = useRouter();
  const [run, setRun] = useState<Run | null>(null);
  const [events, setEvents] = useState<RunEvent[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [now, setNow] = useState(() => Date.now());

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

  // Derive the current phase from the ledger instead of the Run row.
  // Run.phase is only updated at terminal/pause moments by the orchestrator (completed,
  // awaiting_approval, cancelled). Mid-run — when phase.scan has fired and the probe
  // phase is active — Run.phase is still "intake" in the DB. The ledger is the source
  // of truth: pick the latest `phase.*` kind. Falls back to Run.phase if no phase event
  // has fired yet.
  const latestPhase = (() => {
    for (let i = events.length - 1; i >= 0; i--) {
      const k = events[i].kind;
      if (k.startsWith("phase.")) return k.slice("phase.".length);
    }
    return run?.phase ?? null;
  })();

  // Tick a 1s clock while the run is active so a long-running tool's elapsed time counts
  // up live ("running 2m 14s") — the signal that it's working, not stuck.
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
  // A run stuck in "cancelling" can still be cancelled — the cancel now finalizes it.
  const canCancel = status !== "" && !TERMINAL.has(status);
  const canRetest = TERMINAL.has(status);
  const active = status !== "" && !TERMINAL.has(status); // queued / running / cancelling

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
                ⚠ AUTO-APPROVE
              </span>
            )}
          </div>
          <p className="text-sm text-ink-2 mt-0.5">
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

      <div className="mb-4">
        <ReportPanel runId={id} active={active} />
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
        <Panel title="Findings" meta={findings.length ? `${findings.length}` : undefined}>
          {findings.length === 0 ? (
            active ? (
              <div className="px-4 py-3 flex items-center gap-2.5 text-sm text-ink-2">
                <Spinner className="w-3.5 h-3.5" />
                Scanning… findings appear here as they’re discovered and confirmed.
              </div>
            ) : (
              <Empty>
                No findings recorded. Scan output becomes candidates, then validation
                confirms them.
              </Empty>
            )
          ) : (
            [...findings].sort(compareFindings).map((f) => (
              <FindingCard key={f.id} finding={f} />
            ))
          )}
        </Panel>

        <Panel title="Execution ledger" meta={events.length ? `${events.length}` : undefined}>
          {events.length === 0 ? (
            active ? (
              <div className="px-4 py-3 flex items-center gap-2.5 text-sm text-ink-2">
                <Spinner className="w-3.5 h-3.5" /> Waiting for the worker to start this run…
              </div>
            ) : (
              <Empty>No entries yet.</Empty>
            )
          ) : (
            <ol className="px-4 py-3">
              {(() => {
                // An executing step whose digest has no later action.executed is still
                // in flight — show it with a live elapsed counter so a long tool reads as
                // "working", not "stuck". (Digests appear in action.executed payloads.)
                const finished = new Set<string>();
                for (const e of events)
                  if (e.kind === "action.executed" && e.payload?.digest)
                    finished.add(String(e.payload.digest));
                return events.map((e) => {
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
                  return (
                    <li key={e.seq} className="flex gap-3 pb-3 last:pb-0">
                      <div className="flex flex-col items-center shrink-0 pt-1">
                        {running ? (
                          <Spinner className="w-2.5 h-2.5" />
                        ) : (
                          <span
                            aria-hidden
                            className={`rounded-full ${
                              isPhase ? "w-2 h-2 bg-accent" : "w-1.5 h-1.5 bg-line-strong"
                            }`}
                          />
                        )}
                        <span aria-hidden className="w-px flex-1 bg-line mt-1" />
                      </div>
                      <div className="min-w-0 flex-1">
                        <div className="flex items-baseline gap-2 flex-wrap">
                          <span
                            className={`text-sm ${
                              running ? "text-ink font-medium" : isPhase ? "text-ink font-medium" : "text-ink-2"
                            }`}
                          >
                            {running && tool ? `Running ${tool}` : e.kind}
                          </span>
                          {elapsed && (
                            <span
                              className={`text-2xs tnum px-1.5 py-px rounded ${
                                running ? "bg-accent/10 text-accent" : "text-ink-3"
                              }`}
                            >
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
                              .map(([k, v]) => `${k}=${typeof v === "object" ? JSON.stringify(v) : v}`)
                              .join("  ")}
                          </div>
                        )}
                      </div>
                    </li>
                  );
                });
              })()}
            </ol>
          )}
        </Panel>
      </div>

      <p className="text-xs text-ink-3 mt-3">
        The ledger is append-only: every proposal, policy decision and execution is
        recorded with its action digest. <ShortId id={id} />
      </p>
    </div>
  );
}

/* Retest comparison: what a fix cycle changed versus the prior run. */
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

/* The run's generated, evidence-linked report: executive summary, remediation, and a
 * link to the full HTML/PDF. A reviewer signs off a draft to mark it final. */
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
    // While the run is still going, poll so the report appears the moment it's generated.
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
            className="text-xs text-accent hover:underline"
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
              className="text-xs text-ink-2 hover:text-accent"
            >
              PDF
            </a>
          </div>
        </div>
      )}
    </Panel>
  );
}
