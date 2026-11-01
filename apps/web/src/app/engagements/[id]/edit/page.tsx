"use client";

import { useCallback, useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { api, type Engagement, type Playbook } from "@/lib/api";
import { Button, Panel } from "@/components/ui";

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

function toList(s: string): string[] {
  return s
    .split(/[\s,]+/)
    .map((x) => x.trim())
    .filter(Boolean);
}

const inputCls =
  "w-full h-9 bg-input-bg border border-line rounded px-3 text-sm text-ink focus:border-primary outline-none";

export default function EditEngagementPage() {
  const router = useRouter();
  const params = useParams<{ id: string }>();
  const engagementId = params.id;

  const [engagement, setEngagement] = useState<Engagement | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [mode, setMode] = useState<(typeof MODES)[number]>("black_box");
  const [target, setTarget] = useState<(typeof TARGETS)[number]>("web");
  const [domains, setDomains] = useState("");
  const [ipCidrs, setIpCidrs] = useState("");
  const [ports, setPorts] = useState("");
  const [classes, setClasses] = useState<string[]>([]);
  const [exploit, setExploit] = useState(false);
  const [playbook, setPlaybook] = useState("http_evidence");
  const [playbooks, setPlaybooks] = useState<Playbook[]>([]);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [eng, scope] = await Promise.all([
        api.getEngagement(engagementId),
        api.getEngagementScope(engagementId),
      ]);
      setEngagement(eng);
      setName(eng.name);
      setDescription(eng.target_description ?? "");
      setMode(eng.testing_mode as (typeof MODES)[number]);
      setTarget(eng.target_type as (typeof TARGETS)[number]);
      setDomains(((scope.domains as string[]) ?? []).join(" "));
      setIpCidrs(((scope.ip_cidrs as string[]) ?? []).join(" "));
      setPorts((scope.allowed_ports as string) ?? "");
      setClasses((scope.allowed_action_classes as string[]) ?? []);
      setExploit((scope.allow_exploitation as boolean) ?? false);
      setPlaybook((scope.poc_playbook as string) ?? "http_evidence");
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, [engagementId]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    api.listPlaybooks().then(setPlaybooks).catch(() => setPlaybooks([]));
  }, []);

  function toggleClass(id: string) {
    setClasses((cur) => (cur.includes(id) ? cur.filter((c) => c !== id) : [...cur, id]));
  }

  async function save() {
    setBusy(true);
    setError(null);
    try {
      await api.updateEngagement(engagementId, {
        name: name.trim() || undefined,
        target_description: description.trim() || null,
        testing_mode: mode,
        target_type: target,
        scope: {
          domains: toList(domains),
          ip_cidrs: toList(ipCidrs),
          allowed_ports: ports.replace(/\s+/g, ""),
          allowed_action_classes: classes,
          allow_exploitation: exploit,
          poc_playbook: playbook,
        },
      });
      router.push("/engagements?success=updated");
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function handleDelete() {
    if (!engagement) return;
    if (
      !window.confirm(
        `Delete engagement "${engagement.name}"?\n\n` +
          "This will permanently remove the engagement and ALL its runs, findings, " +
          "reports, and approvals. This cannot be undone.",
      )
    )
      return;
    setBusy(true);
    setError(null);
    try {
      await api.deleteEngagement(engagementId);
      router.push("/engagements?success=deleted");
    } catch (e) {
      const msg = String(e);
      setError(msg.includes("409") ? "Cannot delete — a scan is still running." : msg);
    } finally {
      setBusy(false);
    }
  }

  if (loading) {
    return (
      <div className="max-w-[720px]">
        <p className="text-sm text-ink-2">Loading engagement…</p>
      </div>
    );
  }

  if (!engagement) {
    return (
      <div className="max-w-[720px]">
        <p className="text-sm text-ink-2">Engagement not found.</p>
        <Button variant="quiet" className="mt-3" onClick={() => router.push("/engagements")}>
          Back to engagements
        </Button>
      </div>
    );
  }

  return (
    <div className="max-w-[720px]">
      <header className="flex items-end justify-between gap-4 mb-5">
        <div>
          <h1 className="text-2xl font-semibold leading-tight">Edit engagement</h1>
          <p className="text-sm text-ink-2 mt-0.5">
            {engagement.name} &middot; scope v{engagement.scope_version}
          </p>
        </div>
        <Button variant="quiet" onClick={() => router.push("/engagements")}>
          Cancel
        </Button>
      </header>

      {error && (
        <p className="text-sm text-ink-2 border border-line bg-surface rounded px-4 py-3 mb-4">
          {error}
        </p>
      )}

      <Panel title="Engagement details">
        <div className="px-4 py-4 space-y-4">
          <label className="block">
            <span className="block text-xs text-ink-2 mb-1.5">Name</span>
            <input
              className={inputCls}
              value={name}
              onChange={(e) => setName(e.target.value)}
              autoFocus
            />
          </label>

          <label className="block">
            <span className="block text-xs text-ink-2 mb-1.5">
              Target description <span className="text-ink-3">(optional)</span>
            </span>
            <textarea
              className={inputCls + " h-auto py-2 resize-y min-h-[60px]"}
              rows={3}
              maxLength={2000}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Describe the target application and its business logic..."
            />
            <span className="block text-[11px] text-ink-3 mt-1">
              Describe the target application and its business logic. The AI uses this to plan targeted probes
              for race conditions, price manipulation, and workflow bypass.
            </span>
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
                placeholder="example.com *.example.com"
              />
              <span className="block text-[11px] text-ink-3 mt-1">
                Use <span className="font-mono text-ink-2">*.domain.com</span> for wildcard — triggers subdomain enumeration and scans all discovered live hosts.
              </span>
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
                        ? "border-primary text-ink bg-surface-2"
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

          <div className="flex items-center gap-2 pt-1 border-t border-line">
            <Button
              variant="primary"
              onClick={save}
              disabled={busy}
            >
              {busy ? "Saving…" : "Save changes"}
            </Button>
            <Button variant="quiet" onClick={() => router.push("/engagements")}>
              Cancel
            </Button>
            <span className="flex-1" />
            <Button
              variant="danger"
              onClick={handleDelete}
              disabled={busy}
            >
              Delete engagement
            </Button>
          </div>
          <p className="text-2xs text-ink-3">
            Saving scope changes creates a new scope version (v{engagement.scope_version + 1}). Existing runs keep their original scope.
          </p>
        </div>
      </Panel>
    </div>
  );
}
