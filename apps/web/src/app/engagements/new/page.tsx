"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { api, type Playbook } from "@/lib/api";
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

export default function NewEngagementPage() {
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

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
  const [description, setDescription] = useState("");

  // Credentials (gray/white box)
  const [adminUser, setAdminUser] = useState("");
  const [adminPass, setAdminPass] = useState("");
  const [userCreds, setUserCreds] = useState<{ username: string; password: string }[]>([]);

  useEffect(() => {
    api.listPlaybooks().then(setPlaybooks).catch(() => setPlaybooks([]));
  }, []);

  function toggleClass(id: string) {
    setClasses((cur) => (cur.includes(id) ? cur.filter((c) => c !== id) : [...cur, id]));
  }

  async function submit() {
    setBusy(true);
    setError(null);
    try {
      await api.createEngagement({
        name: name.trim() || "Untitled engagement",
        testing_mode: mode,
        target_type: target,
        target_description: description.trim() || undefined,
        scope: {
          domains: toList(domains),
          ip_cidrs: toList(ipCidrs),
          allowed_ports: ports.replace(/\s+/g, ""),
          allowed_action_classes: classes,
          allow_exploitation: exploit,
          poc_playbook: playbook,
          ...(mode !== "black_box"
            ? {
                web_credentials: {
                  admin: adminUser.trim()
                    ? { username: adminUser.trim(), password: adminPass }
                    : null,
                  users: userCreds
                    .filter((c) => c.username.trim())
                    .map((c) => ({ username: c.username.trim(), password: c.password })),
                },
              }
            : {}),
        },
      });
      router.push("/engagements?success=created");
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="max-w-[720px]">
      <header className="flex items-end justify-between gap-4 mb-5">
        <div>
          <h1 className="text-2xl font-semibold leading-tight">New engagement</h1>
          <p className="text-sm text-ink-2 mt-0.5">
            Define the authorized scope, testing mode, and action classes for a new assessment.
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
              placeholder="Q4 external web assessment"
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
              placeholder="E.g. E-commerce platform with checkout, payment processing via Stripe, user wallet with balance transfers, subscription tiers with upgrade/downgrade flows..."
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

          {mode !== "black_box" && (
            <div className="border border-line rounded-lg overflow-hidden">
              <div className="px-4 py-3 bg-surface-2/50 border-b border-line">
                <h3 className="text-sm font-medium text-ink">Web credentials</h3>
                <p className="text-2xs text-ink-3 mt-0.5">
                  Stored in the engagement scope. Passed to the scanner at run start — never logged.
                </p>
              </div>
              <div className="px-4 py-4 space-y-4">
                <div>
                  <span className="block text-xs text-ink-2 font-medium mb-2">Admin account</span>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <input
                      className={inputCls}
                      value={adminUser}
                      onChange={(e) => setAdminUser(e.target.value)}
                      placeholder="Username or email"
                      autoComplete="off"
                    />
                    <input
                      className={inputCls}
                      type="password"
                      value={adminPass}
                      onChange={(e) => setAdminPass(e.target.value)}
                      placeholder="Password"
                      autoComplete="new-password"
                    />
                  </div>
                  <p className="text-2xs text-ink-3 mt-1.5">
                    Recommended: an administrator account that unlocks /admin/* for authenticated scanning.
                  </p>
                </div>
                <div className="border-t border-line pt-4">
                  <div className="flex items-center justify-between mb-2">
                    <span className="block text-xs text-ink-2 font-medium">
                      User accounts <span className="text-ink-3 font-normal">(for IDOR probe)</span>
                    </span>
                    <button
                      type="button"
                      onClick={() => setUserCreds((prev) => [...prev, { username: "", password: "" }])}
                      className="h-7 px-2.5 rounded text-xs border border-line text-ink-2 hover:text-ink hover:border-primary transition-colors"
                    >
                      + Add user
                    </button>
                  </div>
                  {userCreds.length === 0 ? (
                    <p className="text-2xs text-ink-3">
                      No user accounts added. Add at least two regular users to enable cross-tenant IDOR testing.
                    </p>
                  ) : (
                    <div className="space-y-2">
                      {userCreds.map((cred, i) => (
                        <div key={i} className="flex items-center gap-2">
                          <span className="text-2xs text-ink-3 w-5 shrink-0 text-right">{i + 1}.</span>
                          <input
                            className={inputCls + " flex-1"}
                            value={cred.username}
                            onChange={(e) => {
                              const next = [...userCreds];
                              next[i] = { ...next[i], username: e.target.value };
                              setUserCreds(next);
                            }}
                            placeholder="Username or email"
                            autoComplete="off"
                          />
                          <input
                            className={inputCls + " flex-1"}
                            type="password"
                            value={cred.password}
                            onChange={(e) => {
                              const next = [...userCreds];
                              next[i] = { ...next[i], password: e.target.value };
                              setUserCreds(next);
                            }}
                            placeholder="Password"
                            autoComplete="new-password"
                          />
                          <button
                            type="button"
                            onClick={() => setUserCreds((prev) => prev.filter((_, j) => j !== i))}
                            className="text-ink-3 hover:text-sev-high text-sm px-1 shrink-0"
                            title="Remove"
                          >
                            ✕
                          </button>
                        </div>
                      ))}
                    </div>
                  )}
                  {userCreds.length === 1 && (
                    <p className="text-2xs text-ink-3 mt-1.5">
                      Add a second user to enable the recommended two-user IDOR model (B vs C) instead of admin-vs-user comparison.
                    </p>
                  )}
                </div>
              </div>
            </div>
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

          <div className="flex items-center gap-2 pt-1">
            <Button
              variant="primary"
              onClick={submit}
              disabled={busy || (!toList(domains).length && !toList(ipCidrs).length)}
            >
              {busy ? "Creating…" : "Create engagement"}
            </Button>
            <Button variant="quiet" onClick={() => router.push("/engagements")}>
              Cancel
            </Button>
            {!toList(domains).length && !toList(ipCidrs).length && (
              <span className="text-2xs text-ink-3">
                Add at least one domain or IP range to define scope.
              </span>
            )}
          </div>
        </div>
      </Panel>
    </div>
  );
}
