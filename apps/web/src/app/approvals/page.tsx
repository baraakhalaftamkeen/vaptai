"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { api, type Approval, type Decision } from "@/lib/api";
import { Button, Empty, Panel, PolicyTag, ShortId } from "@/components/ui";

export default function ApprovalsPage() {
  const [items, setItems] = useState<Approval[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  // Per-approval login-form input (authenticated scanning). Kept in the component only; it
  // is posted to the web-credentials endpoint on "Log in & approve" and never stored.
  // Fields:
  //   u / p   — PRIMARY account (admin recommended; required to log in at all)
  //   ub / pb — SECOND account (first normal user, optional; enables IDOR)
  //   uc / pc — THIRD account (second normal user, optional; enables the
  //             admin + 2-user IDOR model where idor_probe pairs B+C and
  //             avoids admin-vs-user false positives)
  type CredSet = {
    u: string; p: string;
    ub: string; pb: string;
    uc: string; pc: string;
  };
  const emptyCreds: CredSet = { u: "", p: "", ub: "", pb: "", uc: "", pc: "" };
  const [creds, setCreds] = useState<Record<string, CredSet>>({});
  // Operators who only need the primary account should see a clean form; the
  // extra IDOR fields open on demand. One flag per approval.
  const [showIdor, setShowIdor] = useState<Record<string, boolean>>({});

  function setCred(id: string, field: keyof CredSet, value: string) {
    setCreds((c) => ({ ...c, [id]: { ...(c[id] ?? emptyCreds), [field]: value } }));
  }

  const reload = useCallback(() => {
    api.listApprovals().then(setItems).catch((e) => setError(String(e)));
  }, []);
  useEffect(reload, [reload]);

  async function decide(id: string, decision: Decision) {
    setBusy(id);
    setError(null);
    try {
      await api.decideApproval(id, decision);
      reload();
    } catch (e) {
      const msg = String(e);
      setError(
        msg.includes("403") ? "You need the lead or reviewer role to decide approvals." : msg,
      );
    } finally {
      setBusy(null);
    }
  }

  // Authenticated scan: stash the operator's login credentials (optional), then approve.
  // Up to THREE accounts (admin + two normal users). The second (B) and third (C) only
  // ride along if both are filled in — the backend validates and silently drops any
  // partial pair.
  async function loginAndApprove(a: Approval) {
    setBusy(a.id);
    setError(null);
    try {
      const c = creds[a.id];
      if (c?.u && c?.p) {
        await api.submitWebCredentials(
          a.id, c.u, c.p,
          c.ub || undefined, c.pb || undefined,
          c.uc || undefined, c.pc || undefined,
        );
      }
      await api.decideApproval(a.id, "approve");
      reload();
    } catch (e) {
      const msg = String(e);
      setError(
        msg.includes("403")
          ? "You need the lead or reviewer role to decide approvals."
          : msg.includes("422")
            ? "Those credentials were rejected — check the username and password."
            : msg.includes("503")
              ? "Couldn't reach the credential store; credentials were not saved. Try again."
              : msg,
      );
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="max-w-[760px]">
      <header className="mb-5">
        <h1 className="text-2xl font-semibold leading-tight">Approvals</h1>
        <p className="text-sm text-ink-2 mt-0.5">
          Intrusive actions stop here. Nothing runs until you decide.
        </p>
      </header>

      {error && (
        <p className="text-sm text-sev-high border border-line bg-surface rounded px-4 py-3 mb-4">
          {error}
        </p>
      )}

      <Panel title="Pending" meta={items.length ? `${items.length}` : undefined}>
        {items.length === 0 ? (
          <Empty>
            Nothing awaiting a decision. When a run proposes an intrusive action it pauses
            and appears here.
          </Empty>
        ) : (
          items.map((a) => (
            <div key={a.id} className="px-4 py-4 border-b border-line last:border-0">
              <div className="flex items-start justify-between gap-4">
                <div className="min-w-0">
                  <div className="flex items-center gap-3 mb-2">
                    <PolicyTag policyClass={a.policy_class} />
                    {a.expires_at && (
                      <span className="text-xs text-ink-3">
                        expires {new Date(a.expires_at).toLocaleString()}
                      </span>
                    )}
                  </div>
                  <div className="text-sm text-ink mb-1">
                    {a.summary ?? (a.tool_id ? `Run ${a.tool_id}` : "A gated action")}
                  </div>
                  {a.target && <div className="mono text-xs text-ink-2 break-all mb-1">{a.target}</div>}
                  {a.detail && <div className="text-xs text-ink-3 mb-1">{a.detail}</div>}
                  {a.reason && <div className="text-xs text-ink-3 mb-2">{a.reason}</div>}
                  <dl className="grid grid-cols-[72px_1fr] gap-x-3 gap-y-1 text-xs">
                    <dt className="text-ink-3">Run</dt>
                    <dd>
                      <Link href={`/runs/${a.run_id}`} className="mono text-accent hover:underline">
                        {a.run_id.slice(0, 8)}
                      </Link>
                    </dd>
                    <dt className="text-ink-3">Action</dt>
                    <dd className="min-w-0">
                      <ShortId id={a.action_digest} />
                    </dd>
                  </dl>
                </div>
                <div className="flex gap-2 shrink-0">
                  {!a.needs_web_credentials && (
                    <Button
                      variant="primary"
                      disabled={busy === a.id}
                      onClick={() => decide(a.id, "approve")}
                    >
                      Approve
                    </Button>
                  )}
                  <Button
                    variant="danger"
                    disabled={busy === a.id}
                    onClick={() => decide(a.id, "reject")}
                  >
                    Reject
                  </Button>
                </div>
              </div>

              {a.needs_web_credentials && (
                <div className="mt-3 border-t border-line pt-3">
                  <div className="text-xs text-ink-3 mb-2">
                    Login form detected at{" "}
                    <span className="mono break-all text-ink-2">{a.login_url}</span>. Enter
                    an <strong>admin</strong> account to scan while logged in (unlocks
                    /admin/*), or approve without logging in.
                  </div>
                  <div className="flex flex-wrap gap-2 mb-2">
                    <input
                      className="flex-1 min-w-[8rem] h-7 px-2 rounded bg-surface border border-line text-xs text-ink placeholder:text-ink-3 outline-none focus:border-accent-deep"
                      placeholder="admin username"
                      autoComplete="off"
                      disabled={busy === a.id}
                      value={creds[a.id]?.u ?? ""}
                      onChange={(e) => setCred(a.id, "u", e.target.value)}
                    />
                    <input
                      className="flex-1 min-w-[8rem] h-7 px-2 rounded bg-surface border border-line text-xs text-ink placeholder:text-ink-3 outline-none focus:border-accent-deep"
                      type="password"
                      placeholder="admin password"
                      autoComplete="new-password"
                      disabled={busy === a.id}
                      value={creds[a.id]?.p ?? ""}
                      onChange={(e) => setCred(a.id, "p", e.target.value)}
                    />
                  </div>

                  {/* IDOR two-normal-user panel — collapsed by default so the
                      primary flow stays uncluttered. Expands when the operator
                      wants cross-tenant checks. */}
                  <button
                    type="button"
                    className="text-xs text-ink-3 hover:text-ink-2 underline decoration-dotted mb-2"
                    disabled={busy === a.id}
                    onClick={() =>
                      setShowIdor((s) => ({ ...s, [a.id]: !s[a.id] }))
                    }
                  >
                    {showIdor[a.id]
                      ? "— hide IDOR accounts"
                      : "+ add 2 normal-user accounts for IDOR (recommended)"}
                  </button>
                  {showIdor[a.id] && (
                    <div className="pl-3 border-l border-line mb-2 space-y-2">
                      <div>
                        <div className="text-xs text-ink-3 mb-1">
                          <strong>FIRST normal user (B)</strong> — a regular,
                          non-admin account. idor_probe compares what this user
                          can see against the second normal user.
                        </div>
                        <div className="flex flex-wrap gap-2">
                          <input
                            className="flex-1 min-w-[8rem] h-7 px-2 rounded bg-surface border border-line text-xs text-ink placeholder:text-ink-3 outline-none focus:border-accent-deep"
                            placeholder="user 1 username"
                            autoComplete="off"
                            disabled={busy === a.id}
                            value={creds[a.id]?.ub ?? ""}
                            onChange={(e) => setCred(a.id, "ub", e.target.value)}
                          />
                          <input
                            className="flex-1 min-w-[8rem] h-7 px-2 rounded bg-surface border border-line text-xs text-ink placeholder:text-ink-3 outline-none focus:border-accent-deep"
                            type="password"
                            placeholder="user 1 password"
                            autoComplete="new-password"
                            disabled={busy === a.id}
                            value={creds[a.id]?.pb ?? ""}
                            onChange={(e) => setCred(a.id, "pb", e.target.value)}
                          />
                        </div>
                      </div>
                      <div>
                        <div className="text-xs text-ink-3 mb-1">
                          <strong>SECOND normal user (C)</strong> — another
                          regular user. With C filled in, the probe uses the
                          two-user pair (B vs C) and avoids false
                          "admin-sees-more-than-user" positives.
                        </div>
                        <div className="flex flex-wrap gap-2">
                          <input
                            className="flex-1 min-w-[8rem] h-7 px-2 rounded bg-surface border border-line text-xs text-ink placeholder:text-ink-3 outline-none focus:border-accent-deep"
                            placeholder="user 2 username"
                            autoComplete="off"
                            disabled={busy === a.id || !(creds[a.id]?.ub && creds[a.id]?.pb)}
                            value={creds[a.id]?.uc ?? ""}
                            onChange={(e) => setCred(a.id, "uc", e.target.value)}
                          />
                          <input
                            className="flex-1 min-w-[8rem] h-7 px-2 rounded bg-surface border border-line text-xs text-ink placeholder:text-ink-3 outline-none focus:border-accent-deep"
                            type="password"
                            placeholder="user 2 password"
                            autoComplete="new-password"
                            disabled={busy === a.id || !(creds[a.id]?.ub && creds[a.id]?.pb)}
                            value={creds[a.id]?.pc ?? ""}
                            onChange={(e) => setCred(a.id, "pc", e.target.value)}
                          />
                        </div>
                      </div>
                    </div>
                  )}

                  <div className="flex gap-2">
                    <Button
                      variant="primary"
                      disabled={busy === a.id || !(creds[a.id]?.u && creds[a.id]?.p)}
                      onClick={() => loginAndApprove(a)}
                    >
                      Log in &amp; approve
                    </Button>
                    <Button
                      variant="quiet"
                      disabled={busy === a.id}
                      onClick={() => decide(a.id, "approve")}
                    >
                      Approve without login
                    </Button>
                  </div>
                </div>
              )}
            </div>
          ))
        )}
      </Panel>

      <p className="text-xs text-ink-3 mt-3">
        Approving re-checks scope immediately before the action dispatches. Rejecting blocks
        it and records a coverage gap.
      </p>
    </div>
  );
}
