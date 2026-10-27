"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { api } from "@/lib/api";

export default function LoginPage() {
  const router = useRouter();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.login(username, password);
      const next = new URLSearchParams(window.location.search).get("next") || "/dashboard";
      router.push(next);
      router.refresh();
    } catch (e) {
      const msg = String(e);
      setError(msg.includes("401") ? "That username and password don't match." : msg);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center p-6">
      <div className="w-full max-w-[340px]">
        <div className="flex items-center gap-1.5 mb-8">
          <span className="mono text-accent text-lg leading-none">[</span>
          <span className="font-semibold tracking-tight text-lg">VAPT-AI</span>
          <span className="mono text-2xs text-ink-3 border border-line rounded-sm px-1">v2</span>
          <span className="mono text-accent text-lg leading-none">]</span>
        </div>

        <h1 className="text-xl font-semibold mb-1">Sign in</h1>
        <p className="text-sm text-ink-2 mb-6">
          Authorized assessment platform. Access is logged.
        </p>

        <form onSubmit={onSubmit} className="space-y-3">
          <label className="block">
            <span className="block text-xs text-ink-2 mb-1.5">Username</span>
            <input
              className="w-full h-9 bg-bg border border-line rounded px-3 text-sm focus:border-accent-deep outline-none"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
              autoFocus
            />
          </label>
          <label className="block">
            <span className="block text-xs text-ink-2 mb-1.5">Password</span>
            <input
              className="w-full h-9 bg-bg border border-line rounded px-3 text-sm focus:border-accent-deep outline-none"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
            />
          </label>

          {error && (
            <p className="text-xs text-sev-high border border-line bg-surface rounded px-3 py-2">
              {error}
            </p>
          )}

          <button
            className="w-full h-9 bg-accent text-[#06212b] rounded text-sm font-medium hover:bg-[#7bdcf7] transition-colors disabled:opacity-40"
            disabled={busy || !username || !password}
          >
            {busy ? "Signing in…" : "Sign in"}
          </button>
        </form>
      </div>
    </div>
  );
}
