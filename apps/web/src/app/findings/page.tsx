"use client";

import { useEffect, useMemo, useState } from "react";
import { api, type Engagement, type Finding, type FindingEnrichment } from "@/lib/api";
import { Button, Empty, Panel, SeverityTag, ShortId, StatusTag } from "@/components/ui";

const ENG_PAGE_SIZE = 10;
const FINDING_PAGE_SIZE = 20;

const SEVERITY_OPTIONS = ["critical", "high", "medium", "low", "info"] as const;

const RESOLUTION_OPTIONS = [
  { value: "open", label: "Open" },
  { value: "resolved", label: "Resolved" },
  { value: "accepted_risk", label: "Accepted risk" },
  { value: "false_positive", label: "False positive" },
] as const;

const STATUS_OPTIONS = [
  { value: "confirmed", label: "Confirmed" },
  { value: "candidate", label: "Candidate" },
  { value: "inconclusive", label: "Inconclusive" },
  { value: "false_positive", label: "False positive" },
] as const;

const SEVERITY_RANK: Record<string, number> = {
  critical: 5, high: 4, medium: 3, low: 2, info: 1,
};
const STATUS_RANK: Record<string, number> = {
  confirmed: 3, candidate: 2, inconclusive: 1, false_positive: 0,
};
const RESOLUTION_RANK: Record<string, number> = {
  open: 3, accepted_risk: 2, false_positive: 1, resolved: 0,
};

interface UniqueFinding {
  key: string;
  representative: Finding;
  run_ids: string[];
  run_count: number;
  latest_created: string;
}

function deduplicateFindings(findings: Finding[]): UniqueFinding[] {
  const map = new Map<string, UniqueFinding>();
  for (const f of findings) {
    const key = `${(f.engagement_id || "").toLowerCase()}::${f.title.toLowerCase().trim()}`;
    const existing = map.get(key);
    if (!existing) {
      map.set(key, {
        key,
        representative: f,
        run_ids: [f.run_id],
        run_count: 1,
        latest_created: f.created_at,
      });
    } else {
      existing.run_count += 1;
      if (!existing.run_ids.includes(f.run_id)) existing.run_ids.push(f.run_id);
      if (f.created_at > existing.latest_created) existing.latest_created = f.created_at;
      const cur = existing.representative;
      const pickNew =
        (SEVERITY_RANK[f.severity] ?? 0) > (SEVERITY_RANK[cur.severity] ?? 0) ||
        ((SEVERITY_RANK[f.severity] ?? 0) === (SEVERITY_RANK[cur.severity] ?? 0) &&
          (STATUS_RANK[f.status] ?? 0) > (STATUS_RANK[cur.status] ?? 0)) ||
        ((SEVERITY_RANK[f.severity] ?? 0) === (SEVERITY_RANK[cur.severity] ?? 0) &&
          (STATUS_RANK[f.status] ?? 0) === (STATUS_RANK[cur.status] ?? 0) &&
          (RESOLUTION_RANK[f.resolution_status] ?? 0) > (RESOLUTION_RANK[cur.resolution_status] ?? 0));
      if (pickNew) existing.representative = f;
    }
  }
  return Array.from(map.values());
}

export default function FindingsPage() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [engagements, setEngagements] = useState<Engagement[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("");
  const [resolutionFilter, setResolutionFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [engagementFilter, setEngagementFilter] = useState("");
  const [page, setPage] = useState(1);

  useEffect(() => {
    Promise.all([
      api.listFindings(),
      api.listEngagements(),
    ])
      .then(([f, e]) => {
        setFindings(f);
        setEngagements(e);
        setLoading(false);
      })
      .catch((e) => {
        setError(String(e));
        setLoading(false);
      });
  }, []);

  const unique = useMemo(() => deduplicateFindings(findings), [findings]);

  const filtered = useMemo(() => {
    const q = search.toLowerCase().trim();
    let list = [...unique].sort((a, b) => {
      const ar = a.representative, br = b.representative;
      const sr = (SEVERITY_RANK[br.severity] ?? 0) - (SEVERITY_RANK[ar.severity] ?? 0);
      if (sr) return sr;
      return b.latest_created.localeCompare(a.latest_created);
    });
    if (q) {
      list = list.filter(({ representative: f }) =>
        f.title.toLowerCase().includes(q) ||
        (f.description || "").toLowerCase().includes(q) ||
        (f.target_url || "").toLowerCase().includes(q) ||
        f.id.toLowerCase().includes(q) ||
        (f.engagement_name || "").toLowerCase().includes(q),
      );
    }
    if (severityFilter) list = list.filter(({ representative: f }) => f.severity === severityFilter);
    if (resolutionFilter) list = list.filter(({ representative: f }) => f.resolution_status === resolutionFilter);
    if (statusFilter) list = list.filter(({ representative: f }) => f.status === statusFilter);
    if (engagementFilter) list = list.filter(({ representative: f }) => f.engagement_id === engagementFilter);
    return list;
  }, [unique, search, severityFilter, resolutionFilter, statusFilter, engagementFilter]);

  useEffect(() => {
    setPage(1);
  }, [search, severityFilter, resolutionFilter, statusFilter, engagementFilter]);

  const grouped = useMemo(() => {
    const map = new Map<string, UniqueFinding[]>();
    for (const uf of filtered) {
      const key = uf.representative.engagement_name || uf.representative.engagement_id || "Unknown";
      if (!map.has(key)) map.set(key, []);
      map.get(key)!.push(uf);
    }
    return Array.from(map.entries());
  }, [filtered]);

  const totalEngPages = Math.max(1, Math.ceil(grouped.length / ENG_PAGE_SIZE));
  const safePage = Math.min(page, totalEngPages);
  const pagedGroups = grouped.slice((safePage - 1) * ENG_PAGE_SIZE, safePage * ENG_PAGE_SIZE);

  const selectCls =
    "h-8 rounded bg-surface-2 border border-line text-xs text-ink px-2 pr-6 appearance-none " +
    "bg-[url('data:image/svg+xml;charset=utf-8,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%20width%3D%2210%22%20height%3D%226%22%3E%3Cpath%20d%3D%22M0%200l5%206%205-6z%22%20fill%3D%22%236b7c8f%22%2F%3E%3C%2Fsvg%3E')] " +
    "bg-[length:10px_6px] bg-[right_6px_center] bg-no-repeat focus:outline-none focus:border-primary";

  return (
    <div className="max-w-[1180px]">
      <header className="mb-5">
        <h1 className="text-2xl font-semibold leading-tight">Findings</h1>
        <p className="text-sm text-ink-2 mt-0.5">
          All findings across every engagement and run, with resolution tracking.
        </p>
      </header>

      {error && (
        <p className="text-sm text-ink-2 border border-line bg-surface rounded px-4 py-3 mb-4">
          {error}
        </p>
      )}

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-2.5 mb-4">
        <input
          type="text"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search by title, description, target, engagement…"
          className="h-8 flex-1 min-w-[200px] rounded bg-surface-2 border border-line text-xs text-ink px-3 placeholder:text-ink-3 focus:outline-none focus:border-primary"
        />
        <select value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)} className={selectCls}>
          <option value="">All severities</option>
          {SEVERITY_OPTIONS.map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
        <select value={resolutionFilter} onChange={(e) => setResolutionFilter(e.target.value)} className={selectCls}>
          <option value="">All resolutions</option>
          {RESOLUTION_OPTIONS.map((r) => (
            <option key={r.value} value={r.value}>{r.label}</option>
          ))}
        </select>
        <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)} className={selectCls}>
          <option value="">All statuses</option>
          {STATUS_OPTIONS.map((s) => (
            <option key={s.value} value={s.value}>{s.label}</option>
          ))}
        </select>
        <select value={engagementFilter} onChange={(e) => setEngagementFilter(e.target.value)} className={selectCls}>
          <option value="">All engagements</option>
          {engagements.map((e) => (
            <option key={e.id} value={e.id}>{e.name}</option>
          ))}
        </select>
      </div>

      {/* Summary */}
      <div className="flex flex-wrap gap-4 mb-4">
        <SummaryCard label="Unique" count={filtered.length} />
        <SummaryCard label="Open" count={filtered.filter((u) => u.representative.resolution_status === "open").length} color="var(--accent)" />
        <SummaryCard label="Resolved" count={filtered.filter((u) => u.representative.resolution_status === "resolved").length} color="var(--ok)" />
        <SummaryCard label="Critical" count={filtered.filter((u) => u.representative.severity === "critical").length} color="var(--sev-critical)" />
        <SummaryCard label="High" count={filtered.filter((u) => u.representative.severity === "high").length} color="var(--sev-high)" />
        {findings.length !== unique.length && (
          <SummaryCard label="Total (all runs)" count={findings.length} />
        )}
      </div>

      {loading ? (
        <div className="flex items-center gap-2 text-sm text-ink-2 py-6">
          <span className="inline-block rounded-full border-2 border-line-strong border-t-accent animate-spin w-4 h-4" />
          Loading findings…
        </div>
      ) : pagedGroups.length === 0 ? (
        <Panel title="Findings" meta="0">
          <Empty>
            {findings.length === 0
              ? "No findings yet. Findings appear as runs complete."
              : "No findings match the current filters."}
          </Empty>
        </Panel>
      ) : (
        <div className="space-y-3">
          {pagedGroups.map(([engName, group]) => (
            <EngagementGroup key={engName} name={engName} findings={group} />
          ))}
        </div>
      )}

      {/* Engagement pagination */}
      {totalEngPages > 1 && (
        <div className="flex items-center justify-between mt-3 px-1">
          <span className="text-xs text-ink-3 tnum">
            Page {safePage} of {totalEngPages} · {grouped.length} engagement{grouped.length === 1 ? "" : "s"} · {filtered.length} findings
          </span>
          <div className="flex items-center gap-1.5">
            <button
              disabled={safePage <= 1}
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              className="h-7 px-2.5 rounded text-xs bg-surface-2 border border-line text-ink hover:border-primary disabled:opacity-30 disabled:cursor-not-allowed"
            >
              Previous
            </button>
            {Array.from({ length: totalEngPages }, (_, i) => i + 1)
              .filter((p) => p === 1 || p === totalEngPages || Math.abs(p - safePage) <= 1)
              .reduce<(number | "…")[]>((acc, p) => {
                const last = acc[acc.length - 1];
                if (typeof last === "number" && p - last > 1) acc.push("…");
                acc.push(p);
                return acc;
              }, [])
              .map((item, i) =>
                item === "…" ? (
                  <span key={`e${i}`} className="text-xs text-ink-3 px-1">&hellip;</span>
                ) : (
                  <button
                    key={item}
                    onClick={() => setPage(item)}
                    className={`h-7 min-w-[28px] px-1.5 rounded text-xs border tnum ${
                      item === safePage
                        ? "bg-primary text-white border-primary font-medium"
                        : "bg-surface-2 border-line text-ink hover:border-primary"
                    }`}
                  >
                    {item}
                  </button>
                ),
              )}
            <button
              disabled={safePage >= totalEngPages}
              onClick={() => setPage((p) => Math.min(totalEngPages, p + 1))}
              className="h-7 px-2.5 rounded text-xs bg-surface-2 border border-line text-ink hover:border-primary disabled:opacity-30 disabled:cursor-not-allowed"
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/*  Engagement group — collapsible section                                     */
/* -------------------------------------------------------------------------- */

const SEV_COLOR: Record<string, string> = {
  critical: "var(--sev-critical)",
  high: "var(--sev-high)",
  medium: "var(--sev-medium)",
  low: "var(--sev-low)",
  info: "var(--sev-info)",
};

function EngagementGroup({ name, findings }: { name: string; findings: UniqueFinding[] }) {
  const [open, setOpen] = useState(false);
  const [fPage, setFPage] = useState(1);

  const sevCounts: Record<string, number> = {};
  for (const uf of findings) {
    const s = uf.representative.severity;
    sevCounts[s] = (sevCounts[s] ?? 0) + 1;
  }
  const confirmedCount = findings.filter((uf) => uf.representative.status === "confirmed").length;
  const highestSev = (["critical", "high", "medium", "low", "info"] as const).find((s) => sevCounts[s]) ?? "info";
  const accentColor = SEV_COLOR[highestSev] ?? SEV_COLOR.info;

  const totalFPages = Math.max(1, Math.ceil(findings.length / FINDING_PAGE_SIZE));
  const safeFPage = Math.min(fPage, totalFPages);
  const pagedFindings = findings.slice((safeFPage - 1) * FINDING_PAGE_SIZE, safeFPage * FINDING_PAGE_SIZE);

  return (
    <div className="bg-surface border border-line rounded-lg shadow-card overflow-hidden">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="w-full text-left px-4 py-3 flex items-center gap-3 hover:bg-surface-hover/50 transition-colors focus:outline-none"
        style={{ borderLeft: `3px solid ${accentColor}` }}
      >
        <div className="min-w-0 flex-1">
          <div className="text-sm font-semibold truncate">{name}</div>
          <div className="flex items-center gap-2 mt-0.5 text-2xs text-ink-3">
            <span>{findings.length} finding{findings.length === 1 ? "" : "s"}</span>
            {confirmedCount > 0 && (
              <>
                <span className="text-ink-3/50">&middot;</span>
                <span>{confirmedCount} confirmed</span>
              </>
            )}
          </div>
        </div>
        <div className="flex items-center gap-1.5 shrink-0">
          {(["critical", "high", "medium", "low", "info"] as const).map((s) => {
            const n = sevCounts[s];
            if (!n) return null;
            return (
              <span
                key={s}
                className="text-2xs font-medium tnum px-1.5 py-0.5 rounded"
                style={{
                  background: `color-mix(in srgb, ${SEV_COLOR[s]} 12%, transparent)`,
                  color: SEV_COLOR[s],
                }}
              >
                {n} {s}
              </span>
            );
          })}
        </div>
        <svg
          width="14"
          height="14"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2.5"
          strokeLinecap="round"
          strokeLinejoin="round"
          className={`text-ink-3 transition-transform duration-200 shrink-0 ${open ? "rotate-180" : ""}`}
        >
          <polyline points="6 9 12 15 18 9" />
        </svg>
      </button>
      {open && (
        <div className="border-t border-line">
          {pagedFindings.map((uf) => (
            <FindingRow key={uf.key} uf={uf} />
          ))}
          {totalFPages > 1 && (
            <div className="flex items-center justify-between px-4 py-2 border-t border-line bg-surface-2/30">
              <span className="text-2xs text-ink-3 tnum">
                {(safeFPage - 1) * FINDING_PAGE_SIZE + 1}–{Math.min(safeFPage * FINDING_PAGE_SIZE, findings.length)} of {findings.length}
              </span>
              <div className="flex items-center gap-1">
                <button
                  disabled={safeFPage <= 1}
                  onClick={(e) => { e.stopPropagation(); setFPage((p) => Math.max(1, p - 1)); }}
                  className="h-6 px-2 rounded text-2xs bg-surface border border-line text-ink hover:border-primary disabled:opacity-30 disabled:cursor-not-allowed"
                >
                  Prev
                </button>
                {Array.from({ length: totalFPages }, (_, i) => i + 1)
                  .filter((p) => p === 1 || p === totalFPages || Math.abs(p - safeFPage) <= 1)
                  .reduce<(number | "…")[]>((acc, p) => {
                    const last = acc[acc.length - 1];
                    if (typeof last === "number" && p - last > 1) acc.push("…");
                    acc.push(p);
                    return acc;
                  }, [])
                  .map((item, i) =>
                    item === "…" ? (
                      <span key={`e${i}`} className="text-2xs text-ink-3 px-0.5">&hellip;</span>
                    ) : (
                      <button
                        key={item}
                        onClick={(e) => { e.stopPropagation(); setFPage(item); }}
                        className={`h-6 min-w-[24px] px-1 rounded text-2xs border tnum ${
                          item === safeFPage
                            ? "bg-primary text-white border-primary font-medium"
                            : "bg-surface border-line text-ink hover:border-primary"
                        }`}
                      >
                        {item}
                      </button>
                    ),
                  )}
                <button
                  disabled={safeFPage >= totalFPages}
                  onClick={(e) => { e.stopPropagation(); setFPage((p) => Math.min(totalFPages, p + 1)); }}
                  className="h-6 px-2 rounded text-2xs bg-surface border border-line text-ink hover:border-primary disabled:opacity-30 disabled:cursor-not-allowed"
                >
                  Next
                </button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/*  Finding row — expandable with enrichment detail                            */
/* -------------------------------------------------------------------------- */

function FindingRow({ uf }: { uf: UniqueFinding }) {
  const f = uf.representative;
  const [open, setOpen] = useState(false);
  const [enrichment, setEnrichment] = useState<FindingEnrichment | null>(f.enrichment);
  const [enrichLoading, setEnrichLoading] = useState(false);
  const [resolution, setResolution] = useState(f.resolution_status || "open");
  const [notes, setNotes] = useState(f.notes || "");
  const [saving, setSaving] = useState(false);

  const displayTitle = enrichment?.human_title || f.title;

  async function loadEnrichment() {
    if (enrichment || enrichLoading) return;
    setEnrichLoading(true);
    try {
      const res = await api.enrichFinding(f.id);
      setEnrichment(res.enrichment);
    } catch {
      // enrichment is optional
    } finally {
      setEnrichLoading(false);
    }
  }

  function handleToggle() {
    const next = !open;
    setOpen(next);
    if (next && !enrichment) loadEnrichment();
  }

  async function saveChanges() {
    setSaving(true);
    try {
      await api.updateFinding(f.id, { resolution_status: resolution, notes });
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
    <div className="border-b border-line last:border-0">
      {/* Summary row — click to expand */}
      <button
        type="button"
        onClick={handleToggle}
        className="w-full text-left px-4 py-2.5 hover:bg-surface-2/50 transition-colors focus:outline-none focus:ring-1 focus:ring-blue-500/60"
        aria-expanded={open}
      >
        <div className="flex items-center gap-3">
          <span className="w-16 shrink-0">
            <SeverityTag severity={f.severity} />
          </span>
          <span className="flex-[2] min-w-0 text-xs text-ink truncate font-medium">
            {displayTitle}
          </span>
          <span className="w-24 shrink-0">
            <StatusTag status={f.status} />
          </span>
          <span className="w-24 shrink-0">
            <ResolutionBadge status={resolution} />
          </span>
          <span className="flex-1 min-w-0 mono text-2xs text-ink-3 truncate">
            {f.target_url || "—"}
          </span>
          <span className="w-16 shrink-0 text-right">
            {uf.run_count > 1 ? (
              <span
                className="text-2xs tnum px-1.5 py-0.5 rounded-sm bg-surface-2 border border-line text-ink-2"
                title={`Found in ${uf.run_count} runs: ${uf.run_ids.map((r) => r.slice(0, 8)).join(", ")}`}
              >
                {uf.run_count} runs
              </span>
            ) : (
              <ShortId id={f.run_id} />
            )}
          </span>
          <span className="text-2xs text-ink-3 shrink-0 w-12 text-right">
            {open ? "▴ hide" : "▾ details"}
          </span>
        </div>
      </button>

      {/* Expanded detail */}
      {open && (
        <div className="px-4 pb-4 pt-1 space-y-3 animate-[fadeIn_0.15s_ease-out]">
          {/* LLM enrichment loading */}
          {enrichLoading && (
            <div className="flex items-center gap-2 text-xs text-ink-3 px-3 py-2 bg-surface-2 border border-line rounded-sm">
              <span className="inline-block rounded-full border-2 border-line-strong border-t-accent animate-spin w-3 h-3" />
              Generating analysis…
            </div>
          )}

          {/* Enrichment sections */}
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
                  api.enrichFinding(f.id, true)
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

          {/* No enrichment, no LLM — show raw description */}
          {!enrichment && !enrichLoading && f.description && (
            <div className="bg-surface-2 border border-line rounded-sm px-3 py-2">
              <div className="text-2xs text-ink-3 mb-1 uppercase tracking-wider">Description</div>
              <div className="text-sm text-ink whitespace-pre-wrap">{f.description}</div>
            </div>
          )}

          {/* Run info */}
          {uf.run_count > 1 && (
            <div className="bg-surface-2 border border-line rounded-sm px-3 py-2">
              <div className="text-2xs text-ink-3 mb-1 uppercase tracking-wider">
                Found in {uf.run_count} runs
              </div>
              <div className="flex flex-wrap gap-1.5">
                {uf.run_ids.map((rid) => (
                  <a
                    key={rid}
                    href={`/runs/${rid}`}
                    className="mono text-2xs px-1.5 py-0.5 rounded-sm bg-surface border border-line text-primary hover:text-primary-hover hover:border-primary/40 transition-colors"
                  >
                    {rid.slice(0, 8)}
                  </a>
                ))}
              </div>
            </div>
          )}

          {/* Resolution & notes */}
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
        </div>
      )}
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/*  Small components                                                           */
/* -------------------------------------------------------------------------- */

function EnrichmentSection({ label, content }: { label: string; content: string }) {
  if (!content) return null;
  return (
    <div className="bg-surface-2 border border-line rounded-sm px-3 py-2">
      <div className="text-2xs text-ink-3 mb-1 uppercase tracking-wider">{label}</div>
      <div className="text-sm text-ink whitespace-pre-wrap">{content}</div>
    </div>
  );
}

function SummaryCard({ label, count, color }: { label: string; count: number; color?: string }) {
  return (
    <div className="bg-surface border border-line rounded px-4 py-2.5 min-w-[100px]">
      <div className="text-2xs text-ink-3 uppercase tracking-wider">{label}</div>
      <div className="text-xl font-semibold tnum mt-0.5" style={color ? { color } : undefined}>
        {count}
      </div>
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
