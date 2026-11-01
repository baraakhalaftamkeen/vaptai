"use client";

import { Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { api, type Engagement, type Schedule } from "@/lib/api";
import { Button, Empty, Panel, Row, ShortId } from "@/components/ui";

const PAGE_SIZE = 15;

const MODE_LABEL: Record<string, string> = {
  black_box: "black box",
  gray_box: "gray box",
  white_box: "white box",
};

const MODES = ["black_box", "gray_box", "white_box"] as const;
const TARGETS = ["web", "network", "source"] as const;

const selectCls =
  "h-8 rounded bg-surface-2 border border-line text-xs text-ink px-2 pr-6 appearance-none " +
  "bg-[url('data:image/svg+xml;charset=utf-8,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%20width%3D%2210%22%20height%3D%226%22%3E%3Cpath%20d%3D%22M0%200l5%206%205-6z%22%20fill%3D%22%236b7c8f%22%2F%3E%3C%2Fsvg%3E')] " +
  "bg-[length:10px_6px] bg-[right_6px_center] bg-no-repeat focus:outline-none focus:border-primary";

const SUCCESS_MESSAGES: Record<string, string> = {
  created: "Engagement created successfully.",
  updated: "Engagement updated successfully.",
  deleted: "Engagement deleted successfully.",
};

function SuccessBanner() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const success = searchParams.get("success");
  const message = success ? SUCCESS_MESSAGES[success] : null;

  useEffect(() => {
    if (!success) return;
    const t = setTimeout(() => {
      router.replace("/engagements", { scroll: false });
    }, 4000);
    return () => clearTimeout(t);
  }, [success, router]);

  if (!message) return null;

  return (
    <div className="flex items-center gap-2 text-sm border border-primary/30 bg-primary/5 text-ink rounded px-4 py-2.5 mb-4">
      <span className="text-primary font-medium">&#10003;</span>
      <span>{message}</span>
      <button
        className="ml-auto text-ink-3 hover:text-ink text-xs"
        onClick={() => router.replace("/engagements", { scroll: false })}
      >
        Dismiss
      </button>
    </div>
  );
}

export default function EngagementsPage() {
  const router = useRouter();
  const [items, setItems] = useState<Engagement[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  // --- filters ---
  const [search, setSearch] = useState("");
  const [modeFilter, setModeFilter] = useState("");
  const [targetFilter, setTargetFilter] = useState("");
  const [page, setPage] = useState(1);

  const reload = useCallback(() => {
    api.listEngagements().then(setItems).catch((e) => setError(String(e)));
  }, []);
  useEffect(reload, [reload]);

  // --- filtered + paginated ---
  const filtered = useMemo(() => {
    const q = search.toLowerCase().trim();
    let list = [...items].sort((a, b) =>
      b.created_at.localeCompare(a.created_at),
    );
    if (q) {
      list = list.filter(
        (e) =>
          e.name.toLowerCase().includes(q) ||
          e.id.toLowerCase().includes(q),
      );
    }
    if (modeFilter) {
      list = list.filter((e) => e.testing_mode === modeFilter);
    }
    if (targetFilter) {
      list = list.filter((e) => e.target_type === targetFilter);
    }
    return list;
  }, [items, search, modeFilter, targetFilter]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const safePage = Math.min(page, totalPages);
  const paged = filtered.slice(
    (safePage - 1) * PAGE_SIZE,
    safePage * PAGE_SIZE,
  );

  useEffect(() => {
    setPage(1);
  }, [search, modeFilter, targetFilter]);

  async function startRun(
    engagementId: string,
    autoApprove = false,
    webUsername?: string,
    webPassword?: string,
    webUsernameB?: string,
    webPasswordB?: string,
    webUsernameC?: string,
    webPasswordC?: string,
  ) {
    setBusy(engagementId);
    try {
      const run = await api.createRun(
        engagementId, autoApprove, webUsername, webPassword,
        webUsernameB, webPasswordB, webUsernameC, webPasswordC);
      router.push(`/runs/${run.id}`);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="max-w-[1320px]">
      <header className="flex items-end justify-between gap-4 mb-5">
        <div>
          <h1 className="text-2xl font-semibold leading-tight">Engagements</h1>
          <p className="text-sm text-ink-2 mt-0.5">
            An engagement fixes the authorized scope and testing mode. Runs can only act inside it.
          </p>
        </div>
        <Button
          variant="primary"
          onClick={() => router.push("/engagements/new")}
        >
          New engagement
        </Button>
      </header>

      <Suspense>
        <SuccessBanner />
      </Suspense>

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
          placeholder="Search by name or ID…"
          className="h-8 flex-1 min-w-[200px] rounded bg-surface-2 border border-line text-xs text-ink px-3 placeholder:text-ink-3 focus:outline-none focus:border-primary"
        />
        <select
          value={modeFilter}
          onChange={(e) => setModeFilter(e.target.value)}
          className={selectCls}
        >
          <option value="">All modes</option>
          {MODES.map((m) => (
            <option key={m} value={m}>
              {MODE_LABEL[m]}
            </option>
          ))}
        </select>
        <select
          value={targetFilter}
          onChange={(e) => setTargetFilter(e.target.value)}
          className={selectCls}
        >
          <option value="">All targets</option>
          {TARGETS.map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </select>
      </div>

      <Panel
        title="All engagements"
        meta={
          filtered.length !== items.length
            ? `${filtered.length} of ${items.length}`
            : `${items.length}`
        }
      >
        {/* Column headers */}
        {paged.length > 0 && (
          <div className="flex items-center gap-3 px-4 py-1.5 border-b border-line text-2xs text-ink-3 uppercase tracking-wider select-none">
            <span className="flex-1 min-w-0">Name</span>
            <span className="w-20 shrink-0">Mode</span>
            <span className="w-16 shrink-0">Type</span>
            <span className="w-20 shrink-0">Scope</span>
            <span className="w-[68px] shrink-0">ID</span>
            <span className="w-[400px] shrink-0 text-right">Actions</span>
          </div>
        )}

        {paged.length === 0 ? (
          <Empty>
            {items.length === 0
              ? "No engagements yet. Create one to define an authorized scope."
              : "No engagements match the current filters."}
          </Empty>
        ) : (
          paged.map((e) => (
            <Row key={e.id}>
              <span className="flex-1 min-w-0 truncate">{e.name}</span>
              <span className="text-xs text-ink-2 w-20 shrink-0">
                {MODE_LABEL[e.testing_mode] ?? e.testing_mode}
              </span>
              <span className="text-xs text-ink-2 w-16 shrink-0">{e.target_type}</span>
              <span className="text-xs text-ink-3 w-20 shrink-0 tnum">
                scope v{e.scope_version}
              </span>
              <ShortId id={e.id} />
              <span className="flex items-center gap-1.5 w-[400px] shrink-0 justify-end">
                {e.target_type === "source" && <SourceUpload engagementId={e.id} />}
                <ScheduleControl engagementId={e.id} />
                <Button
                  variant="quiet"
                  onClick={() => router.push(`/engagements/${e.id}/edit`)}
                  className="shrink-0"
                >
                  Edit
                </Button>
                <Button
                  onClick={() => startRun(e.id)}
                  disabled={busy === e.id}
                  className="shrink-0"
                >
                  {busy === e.id ? "Starting…" : "Start run"}
                </Button>
                <Button
                  variant="danger"
                  onClick={() => {
                    if (
                      !window.confirm(
                        "Auto-approve ALL actions for this run?\n\n" +
                        "This skips the human approval gate for every tool invocation. " +
                        "Scope and policy checks still enforce — but you will not be " +
                        "asked to confirm P2 intrusive actions.\n\nFor LAB/TESTING only."
                      )
                    ) {
                      return;
                    }
                    const user = window.prompt(
                      "ADMIN web-login USERNAME (PRIMARY account).\n\n" +
                      "Recommended: an administrator — this unlocks /admin/* for " +
                      "authenticated scanning.\n\n" +
                      "Leave blank for an unauthenticated scan.\n" +
                      "Press Cancel to abort the run."
                    );
                    if (user === null) return;
                    let pass: string | null = "";
                    if (user.trim()) {
                      pass = window.prompt(
                        `ADMIN web-login PASSWORD for '${user.trim()}'.\n\n` +
                        "Stored only in Redis under this run id, with a TTL. " +
                        "Never written to the DB, the ledger, or logs."
                      );
                      if (pass === null) return;
                    }
                    let userB = "";
                    let passB: string | null = "";
                    let userC = "";
                    let passC: string | null = "";
                    if (user.trim() && pass) {
                      const u2 = window.prompt(
                        "OPTIONAL: FIRST normal-user USERNAME for IDOR probe " +
                        "(cross-tenant access testing).\n\n" +
                        "This is a REGULAR user account (not another admin). The " +
                        "idor_probe will compare what this user can see against " +
                        "the SECOND normal user (next prompt).\n\n" +
                        "Blank = skip IDOR, continue with single-account scan.\n" +
                        "Press Cancel to abort the run entirely."
                      );
                      if (u2 === null) return;
                      userB = u2.trim();
                      if (userB) {
                        passB = window.prompt(
                          `FIRST normal-user PASSWORD for '${userB}'.\n\n` +
                          "Same Redis TTL + fail-safe handling as the admin set."
                        );
                        if (passB === null) return;
                        const u3 = window.prompt(
                          "OPTIONAL: SECOND normal-user USERNAME for IDOR probe " +
                          "(enables the admin + 2-user model — RECOMMENDED).\n\n" +
                          "With this third account, idor_probe pairs the two normal " +
                          "users (B vs C) instead of admin vs user — eliminating " +
                          "false 'legitimate access' positives on admin pages a " +
                          "regular user is simply forbidden from.\n\n" +
                          "Blank = fall back to admin-vs-user comparison.\n" +
                          "Press Cancel to abort the run entirely."
                        );
                        if (u3 === null) return;
                        userC = u3.trim();
                        if (userC) {
                          passC = window.prompt(
                            `SECOND normal-user PASSWORD for '${userC}'.\n\n` +
                            "Same Redis TTL + fail-safe handling as the other accounts."
                          );
                          if (passC === null) return;
                        }
                      }
                    }
                    startRun(
                      e.id, true,
                      user.trim() || undefined, pass || undefined,
                      userB || undefined, passB || undefined,
                      userC || undefined, passC || undefined,
                    );
                  }}
                  disabled={busy === e.id}
                  className="shrink-0"
                >
                  {busy === e.id ? "Starting…" : "Auto-approve run"}
                </Button>
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

function SourceUpload({ engagementId }: { engagementId: string }) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [latest, setLatest] = useState<string | null>(null);
  const [state, setState] = useState<"idle" | "uploading" | "error">("idle");

  const refresh = useCallback(() => {
    api
      .listSource(engagementId)
      .then((b) => setLatest(b.length ? `${b[0].filename} · ${b[0].file_count} files` : null))
      .catch(() => setLatest(null));
  }, [engagementId]);
  useEffect(refresh, [refresh]);

  async function onPick(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    setState("uploading");
    try {
      await api.uploadSource(engagementId, file);
      setState("idle");
      refresh();
    } catch {
      setState("error");
    } finally {
      if (inputRef.current) inputRef.current.value = "";
    }
  }

  return (
    <span className="flex items-center gap-2 shrink-0">
      {latest && <span className="text-2xs text-ink-3 max-w-[160px] truncate">{latest}</span>}
      <input
        ref={inputRef}
        type="file"
        accept=".zip,.tar,.tar.gz,.tgz,.tar.bz2"
        className="hidden"
        onChange={onPick}
      />
      <Button variant="quiet" onClick={() => inputRef.current?.click()} disabled={state === "uploading"}>
        {state === "uploading" ? "Uploading…" : state === "error" ? "Retry upload" : latest ? "Replace source" : "Upload source"}
      </Button>
    </span>
  );
}

const INTERVAL_PRESETS: { label: string; minutes: number }[] = [
  { label: "Every hour", minutes: 60 },
  { label: "Every 6 hours", minutes: 360 },
  { label: "Every 12 hours", minutes: 720 },
  { label: "Daily", minutes: 1440 },
  { label: "Weekly", minutes: 10080 },
  { label: "Monthly", minutes: 43200 },
];

function formatInterval(m: number): string {
  if (m < 60) return `${m}m`;
  if (m < 1440) return m % 60 === 0 ? `${m / 60}h` : `${Math.floor(m / 60)}h ${m % 60}m`;
  if (m < 10080) return m % 1440 === 0 ? `${m / 1440}d` : `${Math.floor(m / 1440)}d ${Math.floor((m % 1440) / 60)}h`;
  if (m % 10080 === 0) return `${m / 10080}w`;
  return `${Math.floor(m / 1440)}d`;
}

function toLocalDatetime(d: Date): string {
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function ScheduleControl({ engagementId }: { engagementId: string }) {
  const [sched, setSched] = useState<Schedule | null>(null);
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);

  const [preset, setPreset] = useState(1440);
  const [customMinutes, setCustomMinutes] = useState("");
  const [useCustom, setUseCustom] = useState(false);
  const [startAt, setStartAt] = useState("");
  const [useStartAt, setUseStartAt] = useState(false);

  const popupRef = useRef<HTMLDivElement>(null);

  const refresh = useCallback(() => {
    api
      .listSchedules(engagementId)
      .then((rows) => setSched(rows.find((r) => r.enabled) ?? null))
      .catch(() => setSched(null));
  }, [engagementId]);
  useEffect(refresh, [refresh]);

  useEffect(() => {
    if (!open) return;
    function handleClick(ev: MouseEvent) {
      if (popupRef.current && !popupRef.current.contains(ev.target as Node)) {
        setOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, [open]);

  function openPopup() {
    setUseCustom(false);
    setPreset(1440);
    setCustomMinutes("");
    const tomorrow = new Date();
    tomorrow.setDate(tomorrow.getDate() + 1);
    tomorrow.setHours(9, 0, 0, 0);
    setStartAt(toLocalDatetime(tomorrow));
    setUseStartAt(false);
    setOpen(true);
  }

  const effectiveMinutes = useCustom ? parseInt(customMinutes, 10) : preset;
  const isValid = Number.isFinite(effectiveMinutes) && effectiveMinutes >= 5;

  async function create() {
    if (!isValid) return;
    setBusy(true);
    try {
      const start = useStartAt && startAt ? new Date(startAt).toISOString() : undefined;
      await api.createSchedule(engagementId, effectiveMinutes, start);
      setOpen(false);
      refresh();
    } finally {
      setBusy(false);
    }
  }

  async function remove() {
    if (!sched) return;
    setBusy(true);
    try {
      await api.deleteSchedule(engagementId, sched.id);
      refresh();
    } finally {
      setBusy(false);
    }
  }

  const inputCls =
    "w-full h-9 bg-input-bg border border-line rounded px-3 text-sm text-ink focus:border-primary outline-none";

  return (
    <span className="relative shrink-0">
      {sched ? (
        <span className="flex items-center gap-1.5 text-2xs text-ink-3">
          <button
            onClick={openPopup}
            className="hover:text-ink transition-colors"
            title={sched.next_fire_at ? `Next: ${new Date(sched.next_fire_at).toLocaleString()}` : ""}
          >
            {formatInterval(sched.interval_minutes ?? 0)}
          </button>
          <button onClick={remove} disabled={busy} className="text-ink-3 hover:text-sev-high">{"✕"}</button>
        </span>
      ) : (
        <Button variant="quiet" onClick={openPopup}>
          Schedule
        </Button>
      )}

      {open && (
        <div
          ref={popupRef}
          className="absolute right-0 top-full mt-1.5 z-50 w-[340px] bg-surface border border-line rounded-lg shadow-xl"
        >
          <div className="px-4 pt-3.5 pb-1.5 border-b border-line">
            <h3 className="text-sm font-medium text-ink">Schedule recurring scan</h3>
            <p className="text-2xs text-ink-3 mt-0.5">Automatically start a new run at the selected interval.</p>
          </div>

          <div className="px-4 py-3 space-y-3">
            <div>
              <span className="block text-xs text-ink-2 mb-2">Repeat interval</span>
              <div className="grid grid-cols-3 gap-1.5">
                {INTERVAL_PRESETS.map((p) => (
                  <button
                    key={p.minutes}
                    type="button"
                    onClick={() => { setPreset(p.minutes); setUseCustom(false); }}
                    className={`h-8 rounded text-xs border transition-colors ${
                      !useCustom && preset === p.minutes
                        ? "border-primary text-ink bg-surface-2 font-medium"
                        : "border-line text-ink-3 hover:text-ink-2 hover:border-line-strong"
                    }`}
                  >
                    {p.label}
                  </button>
                ))}
              </div>
            </div>

            <div>
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={useCustom}
                  onChange={(e) => setUseCustom(e.target.checked)}
                  className="accent-accent-deep"
                />
                <span className="text-xs text-ink-2">Custom interval</span>
              </label>
              {useCustom && (
                <div className="flex items-center gap-2 mt-2">
                  <input
                    className={inputCls + " max-w-[100px]"}
                    value={customMinutes}
                    onChange={(e) => setCustomMinutes(e.target.value)}
                    placeholder="1440"
                    inputMode="numeric"
                    autoFocus
                  />
                  <span className="text-xs text-ink-3">minutes</span>
                  {customMinutes && Number.isFinite(parseInt(customMinutes, 10)) && parseInt(customMinutes, 10) >= 60 && (
                    <span className="text-2xs text-ink-3">
                      = {formatInterval(parseInt(customMinutes, 10))}
                    </span>
                  )}
                </div>
              )}
            </div>

            <div className="border-t border-line pt-3">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={useStartAt}
                  onChange={(e) => setUseStartAt(e.target.checked)}
                  className="accent-accent-deep"
                />
                <span className="text-xs text-ink-2">Set start date &amp; time</span>
              </label>
              {useStartAt && (
                <input
                  type="datetime-local"
                  className={inputCls + " mt-2"}
                  value={startAt}
                  onChange={(e) => setStartAt(e.target.value)}
                />
              )}
              {!useStartAt && (
                <p className="text-2xs text-ink-3 mt-1.5">
                  First run starts in {isValid ? formatInterval(effectiveMinutes) : "—"} from now.
                </p>
              )}
            </div>

            {isValid && (
              <div className="bg-surface-2/50 rounded px-3 py-2 text-2xs text-ink-3">
                <span className="text-ink-2 font-medium">Summary:</span>{" "}
                Run every {formatInterval(effectiveMinutes)}
                {useStartAt && startAt
                  ? `, starting ${new Date(startAt).toLocaleString()}`
                  : `, first run ${formatInterval(effectiveMinutes)} from now`
                }
              </div>
            )}
          </div>

          <div className="flex items-center gap-2 px-4 py-3 border-t border-line">
            <Button
              variant="primary"
              onClick={create}
              disabled={busy || !isValid}
            >
              {busy ? "Saving…" : sched ? "Update schedule" : "Create schedule"}
            </Button>
            <Button variant="quiet" onClick={() => setOpen(false)}>
              Cancel
            </Button>
            {!isValid && useCustom && customMinutes && (
              <span className="text-2xs text-sev-high">Min 5 minutes</span>
            )}
          </div>
        </div>
      )}
    </span>
  );
}
