"use client";

import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { api, type Run } from "@/lib/api";
import { Empty, Panel, Row, ShortId, StatusTag } from "@/components/ui";

const PAGE_SIZE = 15;

const STATUS_OPTIONS = [
  "running",
  "queued",
  "paused",
  "awaiting_approval",
  "completed",
  "failed",
  "cancelled",
] as const;

const MODE_OPTIONS = [
  { value: "black_box", label: "Black box" },
  { value: "gray_box", label: "Gray box" },
] as const;

export default function RunsPage() {
  const router = useRouter();
  const [runs, setRuns] = useState<Run[]>([]);
  const [error, setError] = useState<string | null>(null);

  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [modeFilter, setModeFilter] = useState("");
  const [page, setPage] = useState(1);

  useEffect(() => {
    api.listRuns().then(setRuns).catch((e) => setError(String(e)));
  }, []);

  const filtered = useMemo(() => {
    const q = search.toLowerCase().trim();
    let list = [...runs].sort((a, b) =>
      b.created_at.localeCompare(a.created_at),
    );
    if (q) {
      list = list.filter(
        (r) =>
          r.id.toLowerCase().includes(q) ||
          r.engagement_name.toLowerCase().includes(q) ||
          (r.phase ?? "").toLowerCase().includes(q),
      );
    }
    if (statusFilter) {
      list = list.filter((r) => r.status === statusFilter);
    }
    if (modeFilter) {
      list = list.filter((r) => r.testing_mode === modeFilter);
    }
    return list;
  }, [runs, search, statusFilter, modeFilter]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const safePage = Math.min(page, totalPages);
  const paged = filtered.slice(
    (safePage - 1) * PAGE_SIZE,
    safePage * PAGE_SIZE,
  );

  useEffect(() => {
    setPage(1);
  }, [search, statusFilter, modeFilter]);

  const selectCls =
    "h-8 rounded bg-surface-2 border border-line text-xs text-ink px-2 pr-6 appearance-none " +
    "bg-[url('data:image/svg+xml;charset=utf-8,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%20width%3D%2210%22%20height%3D%226%22%3E%3Cpath%20d%3D%22M0%200l5%206%205-6z%22%20fill%3D%22%236b7c8f%22%2F%3E%3C%2Fsvg%3E')] " +
    "bg-[length:10px_6px] bg-[right_6px_center] bg-no-repeat focus:outline-none focus:border-primary";

  return (
    <div className="max-w-[1180px]">
      <header className="mb-5">
        <h1 className="text-2xl font-semibold leading-tight">Runs</h1>
        <p className="text-sm text-ink-2 mt-0.5">
          Every run keeps a full execution ledger. Open one to see its timeline
          and findings.
        </p>
      </header>

      {error && (
        <p className="text-sm text-ink-2 border border-line bg-surface rounded px-4 py-3 mb-4">
          {error}
        </p>
      )}

      {/* Search + filters */}
      <div className="flex flex-wrap items-center gap-2.5 mb-4">
        <input
          type="text"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search by ID, engagement, or phase…"
          className="h-8 flex-1 min-w-[200px] rounded bg-surface-2 border border-line text-xs text-ink px-3 placeholder:text-ink-3 focus:outline-none focus:border-primary"
        />
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className={selectCls}
        >
          <option value="">All statuses</option>
          {STATUS_OPTIONS.map((s) => (
            <option key={s} value={s}>
              {s.replace(/_/g, " ")}
            </option>
          ))}
        </select>
        <select
          value={modeFilter}
          onChange={(e) => setModeFilter(e.target.value)}
          className={selectCls}
        >
          <option value="">All modes</option>
          {MODE_OPTIONS.map((m) => (
            <option key={m.value} value={m.value}>
              {m.label}
            </option>
          ))}
        </select>
      </div>

      <Panel
        title="All runs"
        meta={
          filtered.length !== runs.length
            ? `${filtered.length} of ${runs.length}`
            : `${runs.length}`
        }
      >
        {/* Column headers */}
        {paged.length > 0 && (
          <div className="flex items-center gap-3 px-4 py-1.5 border-b border-line text-2xs text-ink-3 uppercase tracking-wider select-none">
            <span className="w-[68px] shrink-0">ID</span>
            <span className="flex-[2] min-w-0">Engagement</span>
            <span className="flex-1 min-w-0">Phase</span>
            <span className="w-20 shrink-0">Mode</span>
            <span className="w-28 shrink-0">Status</span>
            <span className="w-[150px] shrink-0 text-right">Created</span>
          </div>
        )}

        {paged.length === 0 ? (
          <Empty>
            {runs.length === 0
              ? "No runs yet. Start one from an engagement."
              : "No runs match the current filters."}
          </Empty>
        ) : (
          paged.map((r) => (
            <Row key={r.id} onClick={() => router.push(`/runs/${r.id}`)}>
              <ShortId id={r.id} />
              <span className="flex-[2] min-w-0 text-xs text-ink truncate">
                {r.engagement_name || "—"}
              </span>
              <span className="flex-1 min-w-0 text-xs text-ink-2 truncate">
                {r.phase ?? "—"}
              </span>
              <span className="w-20 shrink-0 text-xs text-ink-3">
                {r.testing_mode
                  ? r.testing_mode.replace(/_/g, " ")
                  : "—"}
              </span>
              <span className="w-28 shrink-0">
                <StatusTag status={r.status} />
              </span>
              <span className="text-xs text-ink-3 tnum w-[150px] shrink-0 text-right">
                {new Date(r.created_at).toLocaleString()}
              </span>
            </Row>
          ))
        )}
      </Panel>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between mt-3 px-1">
          <span className="text-xs text-ink-3 tnum">
            Page {safePage} of {totalPages}
          </span>
          <div className="flex items-center gap-1.5">
            <button
              disabled={safePage <= 1}
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              className="h-7 px-2.5 rounded text-xs bg-surface-2 border border-line text-ink hover:border-primary disabled:opacity-30 disabled:cursor-not-allowed"
            >
              Previous
            </button>
            {Array.from({ length: totalPages }, (_, i) => i + 1)
              .filter(
                (p) =>
                  p === 1 ||
                  p === totalPages ||
                  Math.abs(p - safePage) <= 1,
              )
              .reduce<(number | "…")[]>((acc, p) => {
                const last = acc[acc.length - 1];
                if (typeof last === "number" && p - last > 1) acc.push("…");
                acc.push(p);
                return acc;
              }, [])
              .map((item, i) =>
                item === "…" ? (
                  <span key={`e${i}`} className="text-xs text-ink-3 px-1">
                    &hellip;
                  </span>
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
              disabled={safePage >= totalPages}
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
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
