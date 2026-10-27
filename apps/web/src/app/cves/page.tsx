"use client";

import { useCallback, useEffect, useState } from "react";
import { api, type CveDetail, type CveFeedItem } from "@/lib/api";
import { Button, Empty, Panel, SeverityTag } from "@/components/ui";

const CVE_RE = /^CVE-\d{4}-\d{4,7}$/i;
const inputCls =
  "w-full bg-surface border border-line rounded px-3 py-2 text-sm outline-none focus:border-line-strong";

export default function CvesPage() {
  const [query, setQuery] = useState("");
  const [days, setDays] = useState(7);
  const [minScore, setMinScore] = useState(7.0);

  const [feed, setFeed] = useState<CveFeedItem[] | null>(null);
  const [detail, setDetail] = useState<CveDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const loadFeed = useCallback(
    async (keyword: string) => {
      setBusy(true);
      setError(null);
      setDetail(null);
      try {
        const items = await api.cveFeed({ days, minScore, keyword, limit: 40 });
        setFeed(items);
      } catch (e) {
        setError(errText(e));
        setFeed([]);
      } finally {
        setBusy(false);
      }
    },
    [days, minScore],
  );

  // Initial + filter-change load (unless the user is viewing a specific CVE).
  useEffect(() => {
    if (!CVE_RE.test(query.trim())) loadFeed(query.trim());
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [days, minScore]);
  useEffect(() => {
    loadFeed("");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function search() {
    const q = query.trim();
    if (CVE_RE.test(q)) {
      setBusy(true);
      setError(null);
      setFeed(null);
      try {
        setDetail(await api.cveLookup(q.toUpperCase()));
      } catch (e) {
        setError(errText(e));
        setDetail(null);
      } finally {
        setBusy(false);
      }
    } else {
      loadFeed(q);
    }
  }

  return (
    <div className="max-w-[900px]">
      <header className="mb-5">
        <h1 className="text-2xl font-semibold leading-tight">CVEs</h1>
        <p className="text-sm text-ink-2 mt-0.5">
          Search a CVE by ID for full NVD detail + exploitation status, or browse recent
          high/critical CVEs. Needs internet access to NVD / CISA KEV.
        </p>
      </header>

      <div className="flex flex-wrap items-center gap-2 mb-4">
        <input
          className={`${inputCls} flex-1 min-w-[220px]`}
          placeholder="CVE-2021-41773  or  a keyword (e.g. apache, exchange)"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && search()}
        />
        <select
          className="bg-surface border border-line rounded px-2 py-2 text-sm"
          value={minScore}
          onChange={(e) => setMinScore(Number(e.target.value))}
          title="Minimum severity (feed)"
        >
          <option value={7.0}>High+</option>
          <option value={9.0}>Critical only</option>
        </select>
        <select
          className="bg-surface border border-line rounded px-2 py-2 text-sm"
          value={days}
          onChange={(e) => setDays(Number(e.target.value))}
          title="Time window (feed)"
        >
          <option value={7}>7 days</option>
          <option value={14}>14 days</option>
          <option value={30}>30 days</option>
        </select>
        <Button variant="primary" onClick={search} disabled={busy}>
          {busy ? "Searching…" : "Search"}
        </Button>
      </div>

      {error && (
        <p className="text-sm text-ink-2 border border-line bg-surface rounded px-4 py-3 mb-4">
          {error}
        </p>
      )}

      {detail ? (
        <CveDetailCard detail={detail} />
      ) : (
        <Panel
          title={query.trim() ? `Results for “${query.trim()}”` : "Latest CVEs"}
          meta={feed && feed.length ? `${feed.length}` : undefined}
        >
          {!feed ? (
            <Empty>Loading…</Empty>
          ) : feed.length === 0 ? (
            <Empty>
              No matching high/critical CVEs. Try a broader window, a different keyword, or a
              full CVE ID.
            </Empty>
          ) : (
            <ul>
              {feed.map((c) => (
                <li key={c.id} className="px-4 py-3 border-b border-line last:border-0">
                  <div className="flex items-center gap-2.5 mb-1">
                    <SeverityTag severity={c.severity} />
                    <button
                      className="mono text-sm text-accent hover:underline"
                      onClick={() => {
                        setQuery(c.id);
                        setBusy(true);
                        setError(null);
                        setFeed(null);
                        api
                          .cveLookup(c.id)
                          .then(setDetail)
                          .catch((e) => setError(errText(e)))
                          .finally(() => setBusy(false));
                      }}
                    >
                      {c.id}
                    </button>
                    <span className="text-2xs text-ink-3 tnum ml-auto">
                      CVSS {c.score.toFixed(1)} · {c.published}
                    </span>
                  </div>
                  <p className="text-xs text-ink-2">{c.description}</p>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      )}
    </div>
  );
}

function CveDetailCard({ detail }: { detail: CveDetail }) {
  return (
    <Panel title={detail.cve_id} meta={detail.cvss != null ? `CVSS ${detail.cvss.toFixed(1)}` : undefined}>
      <div className="px-4 py-4 space-y-3">
        <div className="flex flex-wrap items-center gap-2">
          <SeverityTag severity={detail.severity} />
          {detail.exploited && (
            <span className="text-2xs px-2 py-0.5 rounded-sm bg-sev-high/15 text-sev-high border border-sev-high/30">
              ⚠ {detail.exploit_basis || "Exploited"}
            </span>
          )}
          <a
            href={`https://nvd.nist.gov/vuln/detail/${detail.cve_id}`}
            target="_blank"
            rel="noreferrer"
            className="text-xs text-accent hover:underline ml-auto"
          >
            View on NVD
          </a>
        </div>

        {detail.vector && (
          <div className="mono text-2xs text-ink-3 break-all">{detail.vector}</div>
        )}

        <p className="text-sm">
          {detail.description || <span className="text-ink-3">No description available.</span>}
        </p>

        {detail.references.length > 0 && (
          <div>
            <div className="text-xs text-ink-3 mb-1">References</div>
            <ul className="space-y-1">
              {detail.references.map((r) => (
                <li key={r}>
                  <a
                    href={r}
                    target="_blank"
                    rel="noreferrer"
                    className="text-xs text-accent hover:underline break-all"
                  >
                    {r}
                  </a>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </Panel>
  );
}

function errText(e: unknown): string {
  const s = String(e);
  if (s.includes("404")) return "CVE not found (or NVD is unreachable — needs internet access).";
  if (s.includes("400")) return "That doesn't look like a valid CVE ID.";
  return s;
}
