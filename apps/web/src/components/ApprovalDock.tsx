"use client";

/* Floating approval dock: surfaces pending approvals anywhere in the app so a reviewer
 * can approve/reject inline without navigating to the run or the approvals page. Polls
 * the same endpoint as the approvals page; silently hides when there's nothing pending,
 * the viewer isn't signed in, or they lack the reviewer/lead role. */
import { useCallback, useEffect, useRef, useState } from "react";
import Link from "next/link";
import { api, type Approval, type Decision } from "@/lib/api";
import { Button, PolicyTag, ShortId } from "@/components/ui";

interface OTPRequest {
  runId: string;
  message: string;
}

export default function ApprovalDock() {
  const [items, setItems] = useState<Approval[]>([]);
  const [busy, setBusy] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [dismissed, setDismissed] = useState<Set<string>>(new Set());
  const [otpRequests, setOtpRequests] = useState<OTPRequest[]>([]);
  const [otpCode, setOtpCode] = useState("");
  const alive = useRef(true);

  const poll = useCallback(async () => {
    try {
      const list = await api.listApprovals();
      if (alive.current) setItems(list);
    } catch {
      if (alive.current) setItems([]);
    }
    // Check for OTP-requiring runs by looking at awaiting_approval runs with otp events
    try {
      const runs = await api.listRuns();
      const otps: OTPRequest[] = [];
      for (const r of runs) {
        if (r.status === "awaiting_approval") {
          try {
            const events = await api.runEvents(r.id);
            const otpEvt = events.find((e: { kind: string }) => e.kind === "webvuln.otp_required");
            if (otpEvt) {
              otps.push({ runId: r.id, message: "OTP/2FA code required for login" });
            }
          } catch { /* ignore */ }
        }
      }
      if (alive.current) setOtpRequests(otps);
    } catch { /* ignore */ }
  }, []);

  useEffect(() => {
    alive.current = true;
    poll();
    const t = setInterval(poll, 4000);
    return () => {
      alive.current = false;
      clearInterval(t);
    };
  }, [poll]);

  async function decide(id: string, decision: Decision) {
    setBusy(id);
    setNote(null);
    try {
      await api.decideApproval(id, decision);
      setItems((prev) => prev.filter((a) => a.id !== id)); // optimistic
      poll();
    } catch (e) {
      const msg = String(e);
      setNote(
        msg.includes("403")
          ? "You need the lead or reviewer role to decide approvals."
          : msg.includes("409")
            ? "That approval was already decided."
            : msg,
      );
      poll();
    } finally {
      setBusy(null);
    }
  }

  async function submitOtp(runId: string) {
    if (!otpCode.trim()) return;
    setBusy(runId);
    setNote(null);
    try {
      await api.submitOtp(runId, otpCode.trim());
      setOtpRequests((prev) => prev.filter((o) => o.runId !== runId));
      setOtpCode("");
      poll();
    } catch (e) {
      setNote(String(e));
    } finally {
      setBusy(null);
    }
  }

  const visible = items.filter((a) => !dismissed.has(a.id));
  if (visible.length === 0 && otpRequests.length === 0) return null;

  return (
    <div className="fixed bottom-4 right-4 z-50 w-[min(92vw,22rem)] space-y-2">
      {note && (
        <div className="text-xs text-ink-2 bg-surface border border-line rounded px-3 py-2 shadow-lg">
          {note}
        </div>
      )}
      {visible.slice(0, 4).map((a) => (
        <div
          key={a.id}
          className="bg-surface border border-line-strong rounded-lg shadow-xl p-3 animate-[fadeIn_120ms_ease-out]"
        >
          <div className="flex items-center justify-between gap-2 mb-1.5">
            <div className="flex items-center gap-2 min-w-0">
              <span className="relative flex h-2 w-2 shrink-0">
                <span className="absolute inline-flex h-full w-full rounded-full bg-primary opacity-60 animate-ping" />
                <span className="relative inline-flex h-2 w-2 rounded-full bg-primary" />
              </span>
              <span className="text-sm font-medium">Approval required</span>
            </div>
            <PolicyTag policyClass={a.policy_class} />
          </div>

          {/* What will actually run if approved. */}
          <div className="text-sm text-ink mb-1">
            {a.summary ?? (a.tool_id ? `Run ${a.tool_id}` : "A gated action")}
          </div>
          {a.target && (
            <div className="mono text-2xs text-ink-2 break-all mb-1">{a.target}</div>
          )}
          {a.reason && <div className="text-2xs text-ink-3 mb-2">{a.reason}</div>}

          <div className="text-2xs text-ink-3 mb-2">
            Run{" "}
            <Link href={`/runs/${a.run_id}`} className="text-primary hover:underline">
              <ShortId id={a.run_id} />
            </Link>{" "}
            · <span className="mono">{a.action_digest.slice(0, 10)}</span>
          </div>

          {a.needs_web_credentials && (
            <div className="text-2xs text-ink-3 mb-2">
              A login form was found — open Approvals to scan logged in, or approve here to
              scan without logging in.
            </div>
          )}

          <div className="flex items-center gap-2">
            {a.needs_web_credentials ? (
              <Link
                href="/approvals"
                className="inline-flex items-center justify-center h-7 px-3 rounded text-xs bg-primary text-white hover:bg-primary-hover font-medium"
              >
                Log in to approve
              </Link>
            ) : (
              <Button variant="primary" onClick={() => decide(a.id, "approve")} disabled={busy === a.id}>
                {busy === a.id ? "…" : "Approve"}
              </Button>
            )}
            <Button variant="danger" onClick={() => decide(a.id, "reject")} disabled={busy === a.id}>
              Reject
            </Button>
            <button
              className="ml-auto text-2xs text-ink-3 hover:text-ink-2"
              onClick={() => setDismissed((d) => new Set(d).add(a.id))}
              title="Hide (stays pending)"
            >
              Hide
            </button>
          </div>
        </div>
      ))}
      {visible.length > 4 && (
        <div className="text-2xs text-ink-3 text-right pr-1">+{visible.length - 4} more pending</div>
      )}
      {otpRequests.map((otp) => (
        <div
          key={`otp-${otp.runId}`}
          className="bg-surface border border-line-strong rounded-lg shadow-xl p-3 animate-[fadeIn_120ms_ease-out]"
        >
          <div className="flex items-center gap-2 mb-1.5">
            <span className="relative flex h-2 w-2 shrink-0">
              <span className="absolute inline-flex h-full w-full rounded-full bg-accent opacity-60 animate-ping" />
              <span className="relative inline-flex h-2 w-2 rounded-full bg-accent" />
            </span>
            <span className="text-sm font-medium">OTP / 2FA Required</span>
          </div>
          <div className="text-sm text-ink mb-2">{otp.message}</div>
          <div className="flex items-center gap-2">
            <input
              type="text"
              className="flex-1 h-8 bg-input-bg border border-line rounded px-2 text-sm text-ink focus:border-primary outline-none font-mono tracking-widest"
              placeholder="Enter code"
              value={otpCode}
              onChange={(e) => setOtpCode(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && submitOtp(otp.runId)}
              autoFocus
            />
            <Button
              variant="primary"
              onClick={() => submitOtp(otp.runId)}
              disabled={busy === otp.runId || !otpCode.trim()}
            >
              {busy === otp.runId ? "..." : "Submit"}
            </Button>
          </div>
          <div className="text-2xs text-ink-3 mt-1.5">
            Run <ShortId id={otp.runId} />
          </div>
        </div>
      ))}
    </div>
  );
}
