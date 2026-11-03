"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useCallback, useEffect, useState } from "react";
import { api, type CveFeedItem, type Dashboard } from "@/lib/api";
import {
  Button,
  Empty,
  Panel,
  PolicyTag,
  Row,
  SEVERITIES,
  SEV_VAR,
  SeverityTag,
  ShortId,
  StatusTag,
} from "@/components/ui";

const SEV_RANK: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };

export default function OverviewPage() {
  const router = useRouter();
  const [d, setD] = useState<Dashboard | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [deciding, setDeciding] = useState<string | null>(null);

  const load = useCallback(() => {
    api.dashboard().then(setD).catch((e) => setError(String(e)));
  }, []);

  useEffect(() => {
    load();
    const t = setInterval(load, 5000);
    return () => clearInterval(t);
  }, [load]);

  async function decide(id: string, decision: "approve" | "reject") {
    setDeciding(id);
    try {
      await api.decideApproval(id, decision);
      load();
    } catch (e) {
      setError(String(e));
    } finally {
      setDeciding(null);
    }
  }

  if (error) {
    return (
      <div className="max-w-md">
        <h1 className="text-xl font-semibold mb-2">Overview unavailable</h1>
        <p className="text-sm text-ink-2 mb-4">{error}</p>
        <Button onClick={() => router.push("/login")}>Sign in</Button>
      </div>
    );
  }

  const pending = d?.pending_approvals ?? [];
  const engagements = d?.totals?.engagements ?? 0;
  const totalRuns = d?.totals?.runs ?? 0;
  const activeRuns = d?.active_runs?.length ?? 0;
  const totalFindings = d?.totals?.findings ?? 0;
  const confirmed = d?.finding_status_counts?.confirmed ?? 0;
  const totalActions = d?.totals?.actions ?? 0;

  return (
    <div className="max-w-[1280px]">
      <header className="mb-6">
        <h1 className="text-2xl font-bold leading-tight">Overview</h1>
        <p className="text-sm text-ink-2 mt-0.5">
          Security assessment dashboard — real-time status across all engagements.
        </p>
      </header>

      {/* ── KPI cards ── */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        <StatCard
          icon={<BriefcaseIcon />}
          label="Engagements"
          value={engagements}
          href="/engagements"
          loading={!d}
          color="var(--primary)"
        />
        <StatCard
          icon={<RunIcon />}
          label="Total Runs"
          value={totalRuns}
          sub={activeRuns > 0 ? `${activeRuns} active` : undefined}
          href="/runs"
          loading={!d}
          color="var(--accent)"
        />
        <StatCard
          icon={<FindingIcon />}
          label="Findings"
          value={totalFindings}
          sub={confirmed > 0 ? `${confirmed} confirmed` : undefined}
          href="/findings"
          loading={!d}
          color="var(--sev-high)"
        />
        <StatCard
          icon={<ApprovalIcon />}
          label="Pending Approvals"
          value={pending.length}
          href="/approvals"
          loading={!d}
          color={pending.length > 0 ? "var(--primary)" : "var(--ok)"}
          pulse={pending.length > 0}
        />
      </div>

      {/* ── Charts row ── */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4 mb-6">
        <Panel title="Severity Distribution">
          {!d ? (
            <Empty>Loading...</Empty>
          ) : totalFindings === 0 ? (
            <Empty>No findings yet.</Empty>
          ) : (
            <SeverityDonut counts={d.severity_counts} total={totalFindings} />
          )}
        </Panel>

        <Panel title="Finding Status">
          {!d ? (
            <Empty>Loading...</Empty>
          ) : totalFindings === 0 ? (
            <Empty>No findings yet.</Empty>
          ) : (
            <StatusBreakdown counts={d.finding_status_counts} total={totalFindings} />
          )}
        </Panel>

        <Panel title="Run Status">
          {!d ? (
            <Empty>Loading...</Empty>
          ) : totalRuns === 0 ? (
            <Empty>No runs yet.</Empty>
          ) : (
            <RunStatusChart counts={d.run_counts} total={totalRuns} />
          )}
        </Panel>
      </div>

      {/* ── Main content ── */}
      <div className="grid grid-cols-1 xl:grid-cols-[1fr_380px] gap-4">
        <div className="space-y-4 min-w-0">
          {/* Policy class breakdown */}
          <Panel title="Governed Actions" meta={totalActions > 0 ? `${totalActions} total` : undefined}>
            {!d ? (
              <Empty>Loading...</Empty>
            ) : totalActions === 0 ? (
              <Empty>No actions recorded yet. Start a run to see policy-class distribution.</Empty>
            ) : (
              <PolicyBreakdown counts={d.action_class_counts} total={totalActions} />
            )}
          </Panel>

          <Panel
            title="Active Runs"
            meta={d && d.active_runs.length ? `${d.active_runs.length}` : undefined}
            action={<Link href="/runs" className="text-xs text-ink-2 hover:text-primary">All runs</Link>}
          >
            {!d ? (
              <Empty>Loading...</Empty>
            ) : d.active_runs.length === 0 ? (
              <Empty>
                Nothing running.{" "}
                <Link href="/engagements" className="text-primary hover:underline">Start a run</Link>{" "}
                from an engagement.
              </Empty>
            ) : (
              d.active_runs.map((r) => (
                <Row key={r.id} onClick={() => router.push(`/runs/${r.id}`)}>
                  <span
                    aria-hidden
                    className={`w-1.5 h-1.5 rounded-full shrink-0 ${
                      r.status === "awaiting_approval" || r.status === "paused"
                        ? "bg-primary signal-dot"
                        : "bg-ok"
                    }`}
                  />
                  <span className="flex-1 min-w-0 truncate">{r.engagement_name}</span>
                  <span className="hidden sm:block text-xs text-ink-2 w-20 shrink-0">{r.phase ?? "—"}</span>
                  <span className="w-28 shrink-0 text-right sm:text-left"><StatusTag status={r.status} /></span>
                  <span className="hidden sm:block"><ShortId id={r.id} /></span>
                </Row>
              ))
            )}
          </Panel>

          <Panel title="Latest Findings" meta={d && totalFindings ? `${totalFindings} total` : undefined}>
            {!d ? (
              <Empty>Loading...</Empty>
            ) : d.recent_findings.length === 0 ? (
              <Empty>No findings yet. A run records candidates, then validation confirms them.</Empty>
            ) : (
              [...d.recent_findings]
                .sort((a, b) => (SEV_RANK[b.severity] ?? 0) - (SEV_RANK[a.severity] ?? 0))
                .map((f) => (
                  <Row key={f.id} onClick={() => router.push(`/runs/${f.run_id}`)}>
                    <span className="w-20 shrink-0"><SeverityTag severity={f.severity} /></span>
                    <span className="flex-1 min-w-0 truncate">{f.title}</span>
                    <span className="w-24 shrink-0 text-right"><StatusTag status={f.status} /></span>
                  </Row>
                ))
            )}
          </Panel>
        </div>

        {/* ── Right rail ── */}
        <div className="space-y-4 min-w-0">
          <Panel title="Awaiting Decision" meta={pending.length ? `${pending.length}` : undefined}>
            {!d ? (
              <Empty>Loading...</Empty>
            ) : pending.length === 0 ? (
              <Empty>Nothing to decide. Intrusive actions pause here for approval.</Empty>
            ) : (
              pending.map((a) => (
                <div key={a.id} className="px-4 py-3 border-b border-line last:border-0">
                  <div className="flex items-center justify-between gap-2 mb-1.5">
                    <PolicyTag policyClass={a.policy_class} />
                    <ShortId id={a.action_digest} />
                  </div>
                  <div className="mono text-sm mb-0.5 truncate" title={a.tool_id ?? ""}>{a.tool_id ?? "action"}</div>
                  <div className="text-xs text-ink-2 mb-3 truncate">{a.target_ref ?? "—"}</div>
                  <div className="flex gap-2">
                    <Button variant="primary" disabled={deciding === a.id} onClick={() => decide(a.id, "approve")}>Approve</Button>
                    <Button variant="danger" disabled={deciding === a.id} onClick={() => decide(a.id, "reject")}>Reject</Button>
                  </div>
                </div>
              ))
            )}
          </Panel>

          <Panel title="Risk Overview" meta={d ? "by severity" : undefined}>
            {!d ? (
              <Empty>Loading...</Empty>
            ) : totalFindings === 0 ? (
              <Empty>No findings yet. Start a run to collect evidence.</Empty>
            ) : (
              <RiskSummary counts={d.severity_counts} total={totalFindings} />
            )}
          </Panel>

          <CveFeedPanel />
        </div>
      </div>
    </div>
  );
}

/* ── SVG Donut chart for severity ── */
function SeverityDonut({ counts, total }: { counts: Record<string, number>; total: number }) {
  const SEV_HEX: Record<string, string> = {
    critical: "#c10230",
    high: "#e05a2b",
    medium: "#e38c30",
    low: "#d4a031",
    info: "#7b8694",
  };
  const present = SEVERITIES.filter((s) => (counts[s] ?? 0) > 0);
  const r = 60, cx = 80, cy = 80, stroke = 20;
  const circumference = 2 * Math.PI * r;
  let offset = 0;

  return (
    <div className="flex items-center gap-6 px-4 py-5">
      <svg viewBox="0 0 160 160" className="w-[130px] h-[130px] shrink-0">
        {present.length === 0 ? (
          <circle cx={cx} cy={cy} r={r} fill="none" stroke="var(--line)" strokeWidth={stroke} />
        ) : (
          present.map((s) => {
            const pct = (counts[s] ?? 0) / total;
            const dash = pct * circumference;
            const gap = circumference - dash;
            const segment = (
              <circle
                key={s}
                cx={cx}
                cy={cy}
                r={r}
                fill="none"
                stroke={SEV_HEX[s]}
                strokeWidth={stroke}
                strokeDasharray={`${dash} ${gap}`}
                strokeDashoffset={-offset}
                transform={`rotate(-90 ${cx} ${cy})`}
              />
            );
            offset += dash;
            return segment;
          })
        )}
        <text x={cx} y={cy - 6} textAnchor="middle" className="text-2xl font-bold" fill="var(--ink)" fontSize="28">{total}</text>
        <text x={cx} y={cy + 14} textAnchor="middle" fill="var(--ink-3)" fontSize="11">findings</text>
      </svg>
      <div className="flex-1 space-y-2">
        {SEVERITIES.map((s) => {
          const n = counts[s] ?? 0;
          if (n === 0) return null;
          const pct = Math.round((n / total) * 100);
          return (
            <div key={s} className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-sm shrink-0" style={{ background: SEV_HEX[s] }} />
              <span className="text-xs text-ink capitalize flex-1">{s}</span>
              <span className="text-xs tnum font-medium text-ink">{n}</span>
              <span className="text-2xs tnum text-ink-3 w-8 text-right">{pct}%</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

/* ── Horizontal bar chart for finding status ── */
function StatusBreakdown({ counts, total }: { counts: Record<string, number>; total: number }) {
  const STATUS_COLORS: Record<string, string> = {
    confirmed: "#1b9e6a",
    candidate: "#5a6270",
    inconclusive: "#8b929e",
    false_positive: "#cdd2d9",
  };
  const STATUS_LABELS: Record<string, string> = {
    confirmed: "Confirmed",
    candidate: "Candidate",
    inconclusive: "Inconclusive",
    false_positive: "False Positive",
  };
  const entries = Object.entries(counts).sort((a, b) => b[1] - a[1]);
  const max = entries.length > 0 ? entries[0][1] : 1;

  return (
    <div className="px-4 py-4 space-y-3">
      {entries.map(([status, n]) => {
        const pct = Math.round((n / total) * 100);
        const barW = Math.max((n / max) * 100, 2);
        return (
          <div key={status}>
            <div className="flex items-center justify-between mb-1">
              <span className="text-xs text-ink">{STATUS_LABELS[status] ?? status.replace(/_/g, " ")}</span>
              <span className="text-xs tnum text-ink-2">{n} <span className="text-ink-3">({pct}%)</span></span>
            </div>
            <div className="h-2 bg-surface-2 rounded-full overflow-hidden">
              <div
                className="h-full rounded-full transition-all duration-500"
                style={{ width: `${barW}%`, background: STATUS_COLORS[status] ?? "#8b929e" }}
              />
            </div>
          </div>
        );
      })}
    </div>
  );
}

/* ── Run status mini chart ── */
function RunStatusChart({ counts, total }: { counts: Record<string, number>; total: number }) {
  const STATUS_COLORS: Record<string, string> = {
    completed: "#1b9e6a",
    running: "#C10230",
    queued: "#F6A119",
    paused: "#d98a0e",
    awaiting_approval: "#e38c30",
    failed: "#e05a2b",
    cancelled: "#cdd2d9",
    cancelling: "#8b929e",
  };
  const entries = Object.entries(counts).sort((a, b) => b[1] - a[1]);

  return (
    <div className="px-4 py-4">
      {/* Stacked bar */}
      <div className="flex gap-0.5 h-6 mb-4 rounded overflow-hidden">
        {entries.map(([status, n]) => (
          <div
            key={status}
            title={`${n} ${status.replace(/_/g, " ")}`}
            style={{ width: `${(n / total) * 100}%`, background: STATUS_COLORS[status] ?? "#8b929e" }}
          />
        ))}
      </div>
      <div className="grid grid-cols-2 gap-x-4 gap-y-2">
        {entries.map(([status, n]) => (
          <div key={status} className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-sm shrink-0" style={{ background: STATUS_COLORS[status] ?? "#8b929e" }} />
            <span className="text-xs text-ink capitalize flex-1 truncate">{status.replace(/_/g, " ")}</span>
            <span className="text-xs tnum font-medium text-ink">{n}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ── Policy class horizontal bars ── */
function PolicyBreakdown({ counts, total }: { counts: Record<string, number>; total: number }) {
  const POLICY_META: Record<string, { label: string; color: string }> = {
    p0_passive: { label: "Passive (P0)", color: "#1b9e6a" },
    p1_low_impact: { label: "Low Impact (P1)", color: "#F6A119" },
    p2_intrusive: { label: "Intrusive (P2)", color: "#e05a2b" },
    p3_excluded: { label: "Excluded (P3)", color: "#8b929e" },
  };
  const entries = Object.entries(counts).sort((a, b) => b[1] - a[1]);

  return (
    <div className="px-4 py-4">
      <div className="flex gap-0.5 h-3 mb-4 rounded-full overflow-hidden">
        {entries.map(([cls, n]) => (
          <div
            key={cls}
            title={`${n} ${POLICY_META[cls]?.label ?? cls}`}
            style={{ width: `${(n / total) * 100}%`, background: POLICY_META[cls]?.color ?? "#8b929e" }}
          />
        ))}
      </div>
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        {entries.map(([cls, n]) => {
          const meta = POLICY_META[cls] ?? { label: cls, color: "#8b929e" };
          const pct = Math.round((n / total) * 100);
          return (
            <div key={cls} className="bg-surface-2 rounded-lg px-3 py-2.5">
              <div className="flex items-center gap-2 mb-1">
                <span className="w-2 h-2 rounded-full shrink-0" style={{ background: meta.color }} />
                <span className="text-2xs text-ink-3 font-medium uppercase tracking-wide">{meta.label}</span>
              </div>
              <div className="flex items-baseline gap-1.5">
                <span className="text-lg font-bold tnum text-ink">{n}</span>
                <span className="text-2xs tnum text-ink-3">{pct}%</span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

/* ── Risk summary with progress bars ── */
function RiskSummary({ counts, total }: { counts: Record<string, number>; total: number }) {
  const SEV_HEX: Record<string, string> = {
    critical: "#c10230",
    high: "#e05a2b",
    medium: "#e38c30",
    low: "#d4a031",
    info: "#7b8694",
  };
  const critHigh = (counts.critical ?? 0) + (counts.high ?? 0);
  const riskPct = total > 0 ? Math.round((critHigh / total) * 100) : 0;

  return (
    <div className="px-4 py-4">
      <div className="flex items-center justify-between mb-3">
        <div>
          <div className="text-2xs text-ink-3 uppercase tracking-wide font-medium mb-0.5">Risk Score</div>
          <div className="flex items-baseline gap-1">
            <span className="text-3xl font-bold tnum leading-none" style={{ color: riskPct > 50 ? "#c10230" : riskPct > 25 ? "#e38c30" : "#1b9e6a" }}>
              {riskPct}%
            </span>
            <span className="text-xs text-ink-3">critical + high</span>
          </div>
        </div>
        <div className="text-right">
          <div className="text-2xs text-ink-3">Total</div>
          <div className="text-xl font-bold tnum">{total}</div>
        </div>
      </div>
      <div className="space-y-2.5">
        {SEVERITIES.map((s) => {
          const n = counts[s] ?? 0;
          const pct = total > 0 ? (n / total) * 100 : 0;
          return (
            <div key={s}>
              <div className="flex items-center justify-between mb-0.5">
                <div className="flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-sm" style={{ background: SEV_HEX[s] }} />
                  <span className="text-xs capitalize text-ink">{s}</span>
                </div>
                <span className="text-xs tnum text-ink-2">{n}</span>
              </div>
              <div className="h-1.5 bg-surface-2 rounded-full overflow-hidden">
                <div
                  className="h-full rounded-full"
                  style={{ width: `${Math.max(pct, n > 0 ? 2 : 0)}%`, background: SEV_HEX[s] }}
                />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

/* ── CVE Feed ── */
function CveFeedPanel() {
  const [items, setItems] = useState<CveFeedItem[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .cveFeed({ days: 7, minScore: 7.0, limit: 8 })
      .then(setItems)
      .catch((e) => setError(String(e)));
  }, []);

  return (
    <Panel
      title="Latest CVEs"
      meta={items && items.length ? `${items.length} · 7 days` : undefined}
    >
      {error ? (
        <Empty>Feed unavailable (needs internet access to NVD).</Empty>
      ) : !items ? (
        <Empty>Loading...</Empty>
      ) : items.length === 0 ? (
        <Empty>No high/critical CVEs published in the last 7 days.</Empty>
      ) : (
        <ul className="px-4 py-2">
          {items.map((c) => (
            <li key={c.id} className="py-2 border-b border-line last:border-0">
              <div className="flex items-center gap-2 mb-0.5">
                <SeverityTag severity={c.severity} />
                <a
                  href={`https://nvd.nist.gov/vuln/detail/${c.id}`}
                  target="_blank"
                  rel="noreferrer"
                  className="mono text-xs text-primary hover:underline"
                >
                  {c.id}
                </a>
                <span className="text-2xs text-ink-3 tnum ml-auto">
                  CVSS {c.score.toFixed(1)} · {c.published}
                </span>
              </div>
              <p className="text-xs text-ink-2 line-clamp-2">{c.description}</p>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

/* ── KPI stat card ── */
function StatCard({
  icon, label, value, sub, href, loading, color, pulse,
}: {
  icon: React.ReactNode;
  label: string;
  value: number;
  sub?: string;
  href: string;
  loading: boolean;
  color: string;
  pulse?: boolean;
}) {
  return (
    <Link
      href={href}
      className="block bg-surface border border-line rounded-lg shadow-card px-4 py-4 hover:shadow-card-hover transition-shadow group"
    >
      <div className="flex items-start justify-between mb-3">
        <div className="w-9 h-9 rounded-lg flex items-center justify-center" style={{ background: `${color}14` }}>
          <span style={{ color }}>{icon}</span>
        </div>
        {pulse && (
          <span className="relative flex h-2.5 w-2.5">
            <span className="absolute inline-flex h-full w-full rounded-full opacity-60 animate-ping" style={{ background: color }} />
            <span className="relative inline-flex h-2.5 w-2.5 rounded-full" style={{ background: color }} />
          </span>
        )}
      </div>
      <div className="text-2xs text-ink-3 uppercase tracking-wide font-medium">{label}</div>
      <div className="flex items-baseline gap-2 mt-0.5">
        <span className="text-2xl font-bold tnum text-ink">{loading ? "—" : value}</span>
        {sub && <span className="text-2xs text-ink-3 tnum">{sub}</span>}
      </div>
    </Link>
  );
}

/* ── Icons ── */
function BriefcaseIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="2" y="7" width="20" height="14" rx="2" /><path d="M16 7V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v2" />
    </svg>
  );
}
function RunIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10" /><polygon points="10 8 16 12 10 16 10 8" />
    </svg>
  );
}
function FindingIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" /><line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" />
    </svg>
  );
}
function ApprovalIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M9 11l3 3L22 4" /><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11" />
    </svg>
  );
}
