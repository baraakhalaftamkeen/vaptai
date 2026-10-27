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
  SeverityMeter,
  SeverityTag,
  ShortId,
  StatusTag,
} from "@/components/ui";

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
  const activeRuns = d?.active_runs?.length ?? 0;
  const confirmed = d?.finding_status_counts?.confirmed ?? 0;

  return (
    <div className="max-w-[1180px]">
      <header className="mb-4">
        <h1 className="text-2xl font-semibold leading-tight">Overview</h1>
        <p className="text-sm text-ink-2 mt-0.5">
          Your authorized assessments at a glance. Everything starts from an engagement.
        </p>
      </header>

      {/* ---------- KPI row ---------- */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 mb-4">
        <Stat label="Engagements" value={engagements} href="/engagements" loading={!d} />
        <Stat label="Active runs" value={activeRuns} href="/runs" loading={!d} />
        <Stat label="Confirmed findings" value={confirmed} href="/runs" loading={!d} tone="warn" />
        <Stat
          label="Awaiting approval"
          value={pending.length}
          href="/approvals"
          loading={!d}
          tone={pending.length ? "accent" : undefined}
        />
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-[1fr_340px] gap-4">
        <div className="space-y-4 min-w-0">
          <Panel
            title="Active runs"
            meta={d && d.active_runs.length ? `${d.active_runs.length}` : undefined}
            action={<Link href="/runs" className="text-xs text-ink-2 hover:text-accent">All runs</Link>}
          >
            {!d ? (
              <Empty>Loading…</Empty>
            ) : d.active_runs.length === 0 ? (
              <Empty>
                Nothing running.{" "}
                <Link href="/engagements" className="text-accent hover:underline">Start a run</Link>{" "}
                from an engagement.
              </Empty>
            ) : (
              d.active_runs.map((r) => (
                <Row key={r.id} onClick={() => router.push(`/runs/${r.id}`)}>
                  <span
                    aria-hidden
                    className={`w-1.5 h-1.5 rounded-full shrink-0 ${
                      r.status === "awaiting_approval" || r.status === "paused"
                        ? "bg-accent signal-dot"
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

          <Panel title="Latest findings" meta={d && d.totals.findings ? `${d.totals.findings} total` : undefined}>
            {!d ? (
              <Empty>Loading…</Empty>
            ) : d.recent_findings.length === 0 ? (
              <Empty>No findings yet. A run records candidates, then validation confirms them.</Empty>
            ) : (
              d.recent_findings.map((f) => (
                <Row key={f.id} onClick={() => router.push(`/runs/${f.run_id}`)}>
                  <span className="w-20 shrink-0"><SeverityTag severity={f.severity} /></span>
                  <span className="flex-1 min-w-0 truncate">{f.title}</span>
                  <span className="w-24 shrink-0 text-right"><StatusTag status={f.status} /></span>
                </Row>
              ))
            )}
          </Panel>
        </div>

        {/* ---------- Right rail ---------- */}
        <div className="space-y-4 min-w-0">
          <Panel title="Awaiting your decision" meta={pending.length ? `${pending.length}` : undefined}>
            {!d ? (
              <Empty>Loading…</Empty>
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

          <Panel title="Risk" meta={d ? "by severity" : undefined}>
            {!d ? <Empty>Loading…</Empty> : <SeverityMeter counts={d.severity_counts} />}
          </Panel>

          <CveFeedPanel />
        </div>
      </div>
    </div>
  );
}

/* Latest high/critical CVEs (NIST NVD threat-intel feed). Best-effort: if the API host
 * is offline it just shows an empty state. */
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
        <Empty>Loading…</Empty>
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
                  className="mono text-xs text-accent hover:underline"
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

/* A labelled KPI tile that links to its area. */
function Stat({
  label, value, href, loading, tone,
}: {
  label: string; value: number; href: string; loading: boolean;
  tone?: "accent" | "warn";
}) {
  const color = tone === "accent" ? "var(--accent-deep)" : "var(--line)";
  return (
    <Link
      href={href}
      className="block bg-surface border rounded px-4 py-3 hover:border-line-strong transition-colors"
      style={{ borderColor: color }}
    >
      <div className="text-2xs text-ink-3 uppercase tracking-wide">{label}</div>
      <div className={`text-2xl font-semibold tnum mt-0.5 ${tone === "warn" ? "text-sev-high" : "text-ink"}`}>
        {loading ? "—" : value}
      </div>
    </Link>
  );
}

