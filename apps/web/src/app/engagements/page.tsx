"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { api, type Engagement, type Playbook, type Schedule } from "@/lib/api";
import { Button, Empty, Panel, Row, ShortId } from "@/components/ui";

const MODE_LABEL: Record<string, string> = {
  black_box: "black box",
  gray_box: "gray box",
  white_box: "white box",
};

const MODES = ["black_box", "gray_box", "white_box"] as const;
const TARGETS = ["web", "network", "source"] as const;
const ACTION_CLASSES: { id: string; label: string }[] = [
  { id: "p0_passive", label: "P0 passive" },
  { id: "p1_low_impact", label: "P1 low-impact" },
  { id: "p2_intrusive", label: "P2 intrusive (needs approval)" },
];

// Split a free-text list on commas / whitespace / newlines.
function toList(s: string): string[] {
  return s.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);
}

const inputCls =
  "w-full h-9 bg-bg border border-line rounded px-3 text-sm focus:border-accent-deep outline-none";

export default function EngagementsPage() {
  const router = useRouter();
  const [items, setItems] = useState<Engagement[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);

  // --- form state ---
  const [name, setName] = useState("");
  const [mode, setMode] = useState<(typeof MODES)[number]>("black_box");
  const [target, setTarget] = useState<(typeof TARGETS)[number]>("web");
  const [domains, setDomains] = useState("");
  const [ipCidrs, setIpCidrs] = useState("");
  const [ports, setPorts] = useState("80,443");
  const [classes, setClasses] = useState<string[]>(["p0_passive", "p1_low_impact"]);
  const [exploit, setExploit] = useState(false);
  const [playbook, setPlaybook] = useState("http_evidence");
  const [playbooks, setPlaybooks] = useState<Playbook[]>([]);

  const reload = useCallback(() => {
    api.listEngagements().then(setItems).catch((e) => setError(String(e)));
  }, []);
  useEffect(reload, [reload]);
  useEffect(() => {
    api.listPlaybooks().then(setPlaybooks).catch(() => setPlaybooks([]));
  }, []);

  function resetForm() {
    setName("");
    setMode("black_box");
    setTarget("web");
    setDomains("");
    setIpCidrs("");
    setPorts("80,443");
    setClasses(["p0_passive", "p1_low_impact"]);
    setExploit(false);
    setPlaybook("http_evidence");
  }

  function toggleClass(id: string) {
    setClasses((cur) => (cur.includes(id) ? cur.filter((c) => c !== id) : [...cur, id]));
  }

  async function submit() {
    setBusy("new");
    setError(null);
    try {
      await api.createEngagement({
        name: name.trim() || "Untitled engagement",
        testing_mode: mode,
        target_type: target,
        scope: {
          domains: toList(domains),
          ip_cidrs: toList(ipCidrs),
          // Raw port spec so ranges survive (e.g. "1-65535", "80,443,8080"); the API
          // validates it and carries it straight to the nmap scan.
          allowed_ports: ports.replace(/\s+/g, ""),
          allowed_action_classes: classes,
          allow_exploitation: exploit,
          poc_playbook: playbook,
        },
      });
      resetForm();
      setShowForm(false);
      reload();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(null);
    }
  }

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
    <div className="max-w-[1180px]">
      <header className="flex items-end justify-between gap-4 mb-5">
        <div>
          <h1 className="text-2xl font-semibold leading-tight">Engagements</h1>
          <p className="text-sm text-ink-2 mt-0.5">
            An engagement fixes the authorized scope and testing mode. Runs can only act inside it.
          </p>
        </div>
        <Button
          variant={showForm ? "default" : "primary"}
          onClick={() => setShowForm((v) => !v)}
        >
          {showForm ? "Cancel" : "New engagement"}
        </Button>
      </header>

      {error && (
        <p className="text-sm text-ink-2 border border-line bg-surface rounded px-4 py-3 mb-4">
          {error}
        </p>
      )}

      {showForm && (
        <Panel title="New engagement" className="mb-4">
          <div className="px-4 py-4 space-y-4">
            <label className="block">
              <span className="block text-xs text-ink-2 mb-1.5">Name</span>
              <input
                className={inputCls}
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Q4 external web assessment"
                autoFocus
              />
            </label>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <label className="block">
                <span className="block text-xs text-ink-2 mb-1.5">Testing mode</span>
                <select
                  className={inputCls}
                  value={mode}
                  onChange={(e) => setMode(e.target.value as (typeof MODES)[number])}
                >
                  {MODES.map((m) => (
                    <option key={m} value={m}>
                      {MODE_LABEL[m]}
                    </option>
                  ))}
                </select>
              </label>
              <label className="block">
                <span className="block text-xs text-ink-2 mb-1.5">Target type</span>
                <select
                  className={inputCls}
                  value={target}
                  onChange={(e) => setTarget(e.target.value as (typeof TARGETS)[number])}
                >
                  {TARGETS.map((t) => (
                    <option key={t} value={t}>
                      {t}
                    </option>
                  ))}
                </select>
              </label>
            </div>

            {mode === "white_box" && (
              <p className="text-2xs text-ink-3 -mt-1">
                White-box still gates intrusive (P2+) actions for human approval — a signed
                scope never bypasses that.
              </p>
            )}

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <label className="block">
                <span className="block text-xs text-ink-2 mb-1.5">
                  In-scope domains <span className="text-ink-3">(space or comma separated)</span>
                </span>
                <input
                  className={inputCls}
                  value={domains}
                  onChange={(e) => setDomains(e.target.value)}
                  placeholder="example.com api.example.com"
                />
              </label>
              <label className="block">
                <span className="block text-xs text-ink-2 mb-1.5">
                  In-scope IP ranges <span className="text-ink-3">(CIDR)</span>
                </span>
                <input
                  className={inputCls}
                  value={ipCidrs}
                  onChange={(e) => setIpCidrs(e.target.value)}
                  placeholder="10.0.0.0/24"
                />
              </label>
            </div>

            <label className="block">
              <span className="block text-xs text-ink-2 mb-1.5">Allowed ports</span>
              <input
                className={inputCls}
                value={ports}
                onChange={(e) => setPorts(e.target.value)}
                placeholder="80,443,8080  ·  ranges ok: 1-65535"
              />
              <span className="block text-[11px] text-ink-3 mt-1">
                Bounds the nmap scan. Ranges allowed (e.g. 1-1024). Leave blank for the default service set.
              </span>
            </label>

            <div>
              <span className="block text-xs text-ink-2 mb-2">Permitted action classes</span>
              <div className="flex flex-wrap gap-2">
                {ACTION_CLASSES.map((c) => {
                  const on = classes.includes(c.id);
                  return (
                    <button
                      key={c.id}
                      type="button"
                      onClick={() => toggleClass(c.id)}
                      className={`h-7 px-3 rounded text-xs border transition-colors ${
                        on
                          ? "border-accent-deep text-ink bg-surface-2"
                          : "border-line text-ink-3 hover:text-ink-2"
                      }`}
                    >
                      {c.label}
                    </button>
                  );
                })}
              </div>
              <p className="text-2xs text-ink-3 mt-2">
                P3 is excluded by policy and can never be enabled. P2 is accepted into scope but
                still pauses for approval at run time.
              </p>
            </div>

            <div className="border-t border-line pt-4">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={exploit}
                  onChange={(e) => setExploit(e.target.checked)}
                  className="accent-accent-deep"
                />
                <span className="text-sm">Allow exploitation (approved PoC playbooks)</span>
              </label>
              {exploit && (
                <div className="mt-3">
                  <span className="block text-xs text-ink-2 mb-1.5">PoC playbook</span>
                  <select
                    className={inputCls + " max-w-xs"}
                    value={playbook}
                    onChange={(e) => setPlaybook(e.target.value)}
                  >
                    {(playbooks.length ? playbooks : [{ id: "http_evidence", title: "HTTP evidence capture", description: "", tool_id: "" }]).map((p) => (
                      <option key={p.id} value={p.id}>{p.title}</option>
                    ))}
                  </select>
                  <p className="text-2xs text-ink-3 mt-2">
                    Every PoC still pauses for explicit human approval — exploitation never runs
                    unattended, regardless of this setting.
                  </p>
                </div>
              )}
            </div>

            <div className="flex items-center gap-2 pt-1">
              <Button
                variant="primary"
                onClick={submit}
                disabled={busy === "new" || (!toList(domains).length && !toList(ipCidrs).length)}
              >
                {busy === "new" ? "Creating…" : "Create engagement"}
              </Button>
              {!toList(domains).length && !toList(ipCidrs).length && (
                <span className="text-2xs text-ink-3">
                  Add at least one domain or IP range to define scope.
                </span>
              )}
            </div>
          </div>
        </Panel>
      )}

      <Panel title="All engagements" meta={items.length ? `${items.length}` : undefined}>
        {items.length === 0 ? (
          <Empty>No engagements yet. Create one to define an authorized scope.</Empty>
        ) : (
          items.map((e) => (
            <Row key={e.id}>
              <span className="flex-1 min-w-0 truncate">{e.name}</span>
              <span className="text-xs text-ink-2 w-24 shrink-0">
                {MODE_LABEL[e.testing_mode] ?? e.testing_mode}
              </span>
              <span className="text-xs text-ink-2 w-16 shrink-0">{e.target_type}</span>
              <span className="text-xs text-ink-3 w-20 shrink-0 tnum">
                scope v{e.scope_version}
              </span>
              <ShortId id={e.id} />
              {e.target_type === "source" && <SourceUpload engagementId={e.id} />}
              <ScheduleControl engagementId={e.id} />
              <Button
                onClick={() => startRun(e.id)}
                disabled={busy === e.id}
                className="shrink-0"
              >
                {busy === e.id ? "Starting…" : "Start run"}
              </Button>
              <Button
                variant="quiet"
                onClick={() => {
                  // Confirm the auto-approve choice first — it bypasses the human gate
                  // on every tool action for this run.
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
                  // Then collect optional web-login credentials up-front. On a NORMAL
                  // run the operator supplies these when the webvuln credentials
                  // approval appears — but auto-approve bypasses that prompt, so the
                  // only chance to feed them is here. Empty = unauthenticated scan.
                  //
                  // Three-account model (recommended for IDOR coverage):
                  //   PRIMARY (A) → admin account — unlocks /admin/* scanning
                  //   SECOND  (B) → first normal user — IDOR source
                  //   THIRD   (C) → second normal user — IDOR cross-check
                  // When C is supplied, idor_probe compares B vs C (two users
                  // with the same role) and avoids false "legitimate access"
                  // positives on admin-only pages the normal user is simply
                  // forbidden from. Blank C falls back to the legacy A-vs-B.
                  const user = window.prompt(
                    "ADMIN web-login USERNAME (PRIMARY account).\n\n" +
                    "Recommended: an administrator — this unlocks /admin/* for " +
                    "authenticated scanning.\n\n" +
                    "Leave blank for an unauthenticated scan.\n" +
                    "Press Cancel to abort the run."
                  );
                  if (user === null) return;  // operator cancelled
                  let pass: string | null = "";
                  if (user.trim()) {
                    pass = window.prompt(
                      `ADMIN web-login PASSWORD for '${user.trim()}'.\n\n` +
                      "Stored only in Redis under this run id, with a TTL. " +
                      "Never written to the DB, the ledger, or logs."
                    );
                    if (pass === null) return;  // operator cancelled
                  }
                  // SECOND account — first normal user for IDOR. Prompted only
                  // when the primary set is in; same login endpoint. Blank =
                  // skip IDOR, scan continues single-account.
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
                      // THIRD account — second normal user. Only prompted when
                      // B was supplied, since the pair only makes sense together.
                      // Blank = legacy A-vs-B comparison (admin + one user).
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
                {busy === e.id ? "Starting…" : "⚠ Auto"}
              </Button>
            </Row>
          ))
        )}
      </Panel>
    </div>
  );
}

/* Upload a source bundle for a white-box (source) engagement. Shows the latest bundle
 * so the operator can see what a run will analyze. */
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

/* Recurring-schedule control: shows the active interval (with a remove), or a small
 * minutes input to create one. Interval-based for the beta. */
function ScheduleControl({ engagementId }: { engagementId: string }) {
  const [sched, setSched] = useState<Schedule | null>(null);
  const [editing, setEditing] = useState(false);
  const [minutes, setMinutes] = useState("1440");
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(() => {
    api
      .listSchedules(engagementId)
      .then((rows) => setSched(rows.find((r) => r.enabled) ?? null))
      .catch(() => setSched(null));
  }, [engagementId]);
  useEffect(refresh, [refresh]);

  async function create() {
    const n = parseInt(minutes, 10);
    if (!Number.isFinite(n) || n < 5) return;
    setBusy(true);
    try {
      await api.createSchedule(engagementId, n);
      setEditing(false);
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

  if (sched) {
    return (
      <span className="flex items-center gap-1.5 shrink-0 text-2xs text-ink-3">
        <span title={sched.next_fire_at ? `next ${new Date(sched.next_fire_at).toLocaleString()}` : ""}>
          every {sched.interval_minutes}m
        </span>
        <button onClick={remove} disabled={busy} className="text-ink-3 hover:text-sev-high">✕</button>
      </span>
    );
  }
  if (editing) {
    return (
      <span className="flex items-center gap-1.5 shrink-0">
        <input
          value={minutes}
          onChange={(e) => setMinutes(e.target.value)}
          className="w-16 h-7 bg-bg border border-line rounded px-2 text-xs outline-none focus:border-accent-deep"
          inputMode="numeric"
        />
        <span className="text-2xs text-ink-3">min</span>
        <Button variant="quiet" onClick={create} disabled={busy}>Save</Button>
      </span>
    );
  }
  return (
    <Button variant="quiet" className="shrink-0" onClick={() => setEditing(true)}>
      Schedule
    </Button>
  );
}
