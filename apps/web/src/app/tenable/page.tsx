"use client";

import { useEffect, useRef, useState } from "react";
import { api, type TenableVuln, type TenablePage as TPage, type TenableStatus } from "@/lib/api";
import { Button, Empty, Panel, SeverityTag } from "@/components/ui";

const inputCls =
  "w-full bg-surface border border-line rounded px-3 py-2 text-sm outline-none focus:border-line-strong";

const SEV_OPTIONS = [
  { value: "", label: "All severities" },
  { value: "critical", label: "Critical" },
  { value: "high", label: "High" },
  { value: "critical,high", label: "Critical + High" },
  { value: "medium", label: "Medium" },
  { value: "low", label: "Low" },
  { value: "info", label: "Info" },
];

const PAGE_SIZE = 20;

export default function TenablePage() {
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("");
  const [ipFilter, setIpFilter] = useState("");

  const [data, setData] = useState<TPage | null>(null);
  const [tStatus, setTStatus] = useState<TenableStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const filtersRef = useRef({ severity: "", search: "", ipFilter: "" });
  filtersRef.current = { severity, search, ipFilter };

  const reqId = useRef(0);

  useEffect(() => {
    api.tenableStatus().then(setTStatus).catch(() => {});
    fetchPage(1);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function fetchPage(p: number) {
    const id = ++reqId.current;
    setBusy(true);
    setError(null);
    const f = filtersRef.current;
    try {
      const result = await api.tenableVulns({
        severity: f.severity || undefined,
        search: f.search.trim() || undefined,
        ip: f.ipFilter.trim() || undefined,
        page: p,
        pageSize: PAGE_SIZE,
      });
      if (id !== reqId.current) return;
      setData(result);
    } catch (e) {
      if (id !== reqId.current) return;
      setError(String(e));
    } finally {
      if (id === reqId.current) setBusy(false);
    }
  }

  function doSearch() {
    fetchPage(1);
  }

  function goPage(p: number) {
    fetchPage(p);
  }

  const vulns = data?.items ?? [];

  return (
    <div className="max-w-[1100px]">
      <header className="mb-5">
        <h1 className="text-2xl font-semibold leading-tight">Tenable Findings</h1>
        <p className="text-sm text-ink-2 mt-0.5">
          Vulnerability findings from your Tenable.sc instance.
          {tStatus?.configured && tStatus.url && (
            <span className="ml-1 text-ink-3">Connected to {tStatus.url}</span>
          )}
          {tStatus && !tStatus.configured && (
            <span className="ml-1 text-sev-high">
              Not configured &mdash; set VAPT_TENABLE_URL, VAPT_TENABLE_ACCESS_KEY, and VAPT_TENABLE_SECRET_KEY.
            </span>
          )}
        </p>
      </header>

      {/* Filters — single row */}
      <div className="flex items-center gap-2 mb-4">
        <input
          className="flex-1 min-w-0 bg-surface border border-line rounded px-3 py-2 text-sm outline-none focus:border-line-strong"
          placeholder="Search plugin, CVE, synopsis..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && doSearch()}
        />
        <input
          className="w-[130px] bg-surface border border-line rounded px-3 py-2 text-sm outline-none focus:border-line-strong"
          placeholder="Filter by IP"
          value={ipFilter}
          onChange={(e) => setIpFilter(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && doSearch()}
        />
        <select
          className="bg-surface border border-line rounded px-2 py-2 text-sm"
          value={severity}
          onChange={(e) => {
            setSeverity(e.target.value);
            filtersRef.current = { ...filtersRef.current, severity: e.target.value };
            fetchPage(1);
          }}
        >
          {SEV_OPTIONS.map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </select>
        <Button variant="primary" onClick={doSearch} disabled={busy}>
          {busy ? "Loading..." : "Refresh"}
        </Button>
      </div>

      {error && (
        <p className="text-sm text-ink-2 border border-line bg-surface rounded px-4 py-3 mb-4">
          {error}
        </p>
      )}

      <Panel
        title="Vulnerabilities"
        meta={data ? `${data.total}` : undefined}
      >
        {!data && !error ? (
          <Empty>Loading...</Empty>
        ) : vulns.length === 0 ? (
          <Empty>
            {tStatus && !tStatus.configured
              ? "Tenable.sc is not configured. Set the VAPT_TENABLE_* environment variables."
              : "No vulnerabilities found matching your filters."}
          </Empty>
        ) : (
          <>
            <div className="relative overflow-x-auto">
              {/* Loading overlay — shown on page transitions while keeping the table visible */}
              {busy && (
                <div className="absolute inset-0 z-10 bg-surface/70 flex items-center justify-center backdrop-blur-[1px]">
                  <div className="flex items-center gap-2 text-sm text-ink-2">
                    <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24" fill="none">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                    </svg>
                    Loading...
                  </div>
                </div>
              )}
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-2xs uppercase tracking-wider text-ink-3 border-b border-line">
                    <th className="px-4 py-2">Severity</th>
                    <th className="px-4 py-2">Plugin</th>
                    <th className="px-4 py-2">CVE</th>
                    <th className="px-4 py-2">Host</th>
                    <th className="px-4 py-2">CVSS</th>
                    <th className="px-4 py-2">Exploit</th>
                  </tr>
                </thead>
                <tbody>
                  {vulns.map((v, i) => (
                    <VulnRow key={`${v.ip}-${v.port}-${v.plugin}-${v.cve}-${i}`} vuln={v} />
                  ))}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            {data && data.pages > 1 && (
              <div className="flex items-center justify-between px-4 py-3 border-t border-line">
                <span className="text-xs text-ink-3">
                  Showing {(data.page - 1) * data.page_size + 1}
                  &ndash;
                  {Math.min(data.page * data.page_size, data.total)} of {data.total}
                </span>
                <div className="flex items-center gap-1">
                  <PaginationButton
                    disabled={data.page <= 1 || busy}
                    onClick={() => goPage(1)}
                    label="First"
                  />
                  <PaginationButton
                    disabled={data.page <= 1 || busy}
                    onClick={() => goPage(data.page - 1)}
                    label="Prev"
                  />
                  <PageNumbers
                    current={data.page}
                    total={data.pages}
                    onSelect={goPage}
                    disabled={busy}
                  />
                  <PaginationButton
                    disabled={data.page >= data.pages || busy}
                    onClick={() => goPage(data.page + 1)}
                    label="Next"
                  />
                  <PaginationButton
                    disabled={data.page >= data.pages || busy}
                    onClick={() => goPage(data.pages)}
                    label="Last"
                  />
                </div>
              </div>
            )}
          </>
        )}
      </Panel>
    </div>
  );
}

function PaginationButton({ disabled, onClick, label }: { disabled: boolean; onClick: () => void; label: string }) {
  return (
    <button
      disabled={disabled}
      onClick={onClick}
      className={`px-2.5 py-1 text-xs rounded border transition-colors ${
        disabled
          ? "border-line text-ink-3 cursor-not-allowed"
          : "border-line text-ink hover:bg-surface-hover hover:border-line-strong"
      }`}
    >
      {label}
    </button>
  );
}

function PageNumbers({ current, total, onSelect, disabled }: {
  current: number; total: number; onSelect: (p: number) => void; disabled: boolean;
}) {
  const pages: (number | "...")[] = [];
  if (total <= 7) {
    for (let i = 1; i <= total; i++) pages.push(i);
  } else {
    pages.push(1);
    if (current > 3) pages.push("...");
    for (let i = Math.max(2, current - 1); i <= Math.min(total - 1, current + 1); i++) {
      pages.push(i);
    }
    if (current < total - 2) pages.push("...");
    pages.push(total);
  }

  return (
    <>
      {pages.map((p, i) =>
        p === "..." ? (
          <span key={`ellipsis-${i}`} className="px-1 text-xs text-ink-3">...</span>
        ) : (
          <button
            key={p}
            disabled={disabled || p === current}
            onClick={() => onSelect(p)}
            className={`w-7 h-7 text-xs rounded border transition-colors ${
              p === current
                ? "bg-primary text-white border-primary font-medium"
                : disabled
                  ? "border-line text-ink-3 cursor-not-allowed"
                  : "border-line text-ink hover:bg-surface-hover hover:border-line-strong"
            }`}
          >
            {p}
          </button>
        ),
      )}
    </>
  );
}

function VulnRow({ vuln }: { vuln: TenableVuln }) {
  const [open, setOpen] = useState(false);

  return (
    <>
      <tr
        className="border-b border-line last:border-0 hover:bg-surface-hover cursor-pointer transition-colors"
        onClick={() => setOpen(!open)}
      >
        <td className="px-4 py-2.5">
          <SeverityTag severity={vuln.severity} />
        </td>
        <td className="px-4 py-2.5 max-w-[300px]">
          <div className="truncate font-medium">{vuln.plugin || "—"}</div>
        </td>
        <td className="px-4 py-2.5 mono text-xs">
          {vuln.cve || "—"}
        </td>
        <td className="px-4 py-2.5 mono text-xs">
          {vuln.ip}
          {vuln.port ? `:${vuln.port}` : ""}
          {vuln.protocol ? `/${vuln.protocol}` : ""}
        </td>
        <td className="px-4 py-2.5 tnum">
          {vuln.cvss != null ? vuln.cvss.toFixed(1) : "—"}
        </td>
        <td className="px-4 py-2.5">
          {vuln.exploit ? (
            <span className="text-2xs px-2 py-0.5 rounded-sm bg-sev-high/15 text-sev-high border border-sev-high/30">
              Yes
            </span>
          ) : (
            <span className="text-ink-3 text-xs">No</span>
          )}
        </td>
      </tr>
      {open && (
        <tr className="border-b border-line">
          <td colSpan={6} className="px-4 py-3 bg-surface">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
              <div>
                <div className="text-ink-3 mb-1 uppercase tracking-wider text-2xs">Synopsis</div>
                <p className="text-ink">{vuln.synopsis || "—"}</p>
              </div>
              <div>
                <div className="text-ink-3 mb-1 uppercase tracking-wider text-2xs">Solution</div>
                <p className="text-ink">{vuln.solution || "—"}</p>
              </div>
              {vuln.os && (
                <div>
                  <div className="text-ink-3 mb-1 uppercase tracking-wider text-2xs">OS</div>
                  <p className="text-ink">{vuln.os}</p>
                </div>
              )}
              {vuln.frameworks && (
                <div>
                  <div className="text-ink-3 mb-1 uppercase tracking-wider text-2xs">
                    Exploit Frameworks
                  </div>
                  <p className="text-ink">{vuln.frameworks}</p>
                </div>
              )}
              {(vuln.first_seen || vuln.last_seen) && (
                <div>
                  <div className="text-ink-3 mb-1 uppercase tracking-wider text-2xs">Timeline</div>
                  <p className="text-ink">
                    {vuln.first_seen && <>First seen: {vuln.first_seen}</>}
                    {vuln.first_seen && vuln.last_seen && <> · </>}
                    {vuln.last_seen && <>Last seen: {vuln.last_seen}</>}
                  </p>
                </div>
              )}
            </div>
          </td>
        </tr>
      )}
    </>
  );
}
