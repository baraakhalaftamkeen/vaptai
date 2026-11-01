"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
/* eslint-disable @next/next/no-img-element */
import { api } from "@/lib/api";
import { useTheme } from "@/components/ThemeProvider";

export default function LoginPage() {
  const router = useRouter();
  const { theme, toggle } = useTheme();
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
    <div className="h-screen flex overflow-hidden">
      {/* Left panel — brand */}
      <div className={`hidden lg:flex lg:w-[480px] xl:w-[560px] flex-col justify-between p-10 ${theme === "dark" ? "bg-sidebar-bg" : "bg-[#f5f0eb]"}`}>
        <img
          src={theme === "dark" ? "/tamkeen-logo.svg" : "/tamkeen-logo-dark.svg"}
          alt="Tamkeen Technologies"
          width={160}
          height={48}
        />
        <div>
          <h2 className={`text-3xl font-bold leading-tight mb-3 ${theme === "dark" ? "text-white" : "text-[#1a1a2e]"}`}>
            Authorized Security<br />
            <span className="text-accent">Assessment Platform</span>
          </h2>
          <p className={`text-sm leading-relaxed max-w-[360px] ${theme === "dark" ? "text-sidebar-ink-2" : "text-[#555]"}`}>
            VAPT-AI provides governed, multi-agent vulnerability assessment
            and penetration testing with full audit trails.
          </p>
        </div>
        <p className={`text-2xs ${theme === "dark" ? "text-sidebar-ink-2/60" : "text-[#999]"}`}>
          Tamkeen Technologies — Cyber Security Division
        </p>
      </div>

      {/* Right panel — form */}
      <div className="flex-1 flex items-center justify-center p-6 bg-surface relative">
        {/* Theme toggle */}
        <button
          onClick={toggle}
          className="absolute top-5 right-5 w-9 h-9 flex items-center justify-center rounded-lg border border-line text-ink-3 hover:text-ink hover:border-line-strong transition-colors"
          title={theme === "light" ? "Switch to dark mode" : "Switch to light mode"}
        >
          {theme === "light" ? (
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
            </svg>
          ) : (
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="5" /><line x1="12" y1="1" x2="12" y2="3" /><line x1="12" y1="21" x2="12" y2="23" /><line x1="4.22" y1="4.22" x2="5.64" y2="5.64" /><line x1="18.36" y1="18.36" x2="19.78" y2="19.78" /><line x1="1" y1="12" x2="3" y2="12" /><line x1="21" y1="12" x2="23" y2="12" /><line x1="4.22" y1="19.78" x2="5.64" y2="18.36" /><line x1="18.36" y1="5.64" x2="19.78" y2="4.22" />
            </svg>
          )}
        </button>

        <div className="w-full max-w-[380px]">
          <div className="lg:hidden mb-8">
            <img
              src={theme === "dark" ? "/tamkeen-logo.svg" : "/tamkeen-logo-dark.svg"}
              alt="Tamkeen Technologies"
              width={140}
              height={42}
            />
          </div>

          <h1 className="text-2xl font-bold text-ink mb-1">Sign in</h1>
          <p className="text-sm text-ink-2 mb-8">
            Access is logged and governed by policy.
          </p>

          <form onSubmit={onSubmit} className="space-y-4">
            <label className="block">
              <span className="block text-sm font-medium text-ink mb-1.5">Username</span>
              <input
                className="w-full h-10 bg-input-bg border border-line rounded-md px-3 text-sm text-ink focus:border-primary focus:ring-1 focus:ring-primary/20 outline-none transition-colors"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoComplete="username"
                autoFocus
              />
            </label>
            <label className="block">
              <span className="block text-sm font-medium text-ink mb-1.5">Password</span>
              <input
                className="w-full h-10 bg-input-bg border border-line rounded-md px-3 text-sm text-ink focus:border-primary focus:ring-1 focus:ring-primary/20 outline-none transition-colors"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="current-password"
              />
            </label>

            {error && (
              <p className="text-sm text-primary border border-primary/20 bg-primary/5 rounded-md px-3 py-2.5">
                {error}
              </p>
            )}

            <button
              className="w-full h-10 bg-primary text-white rounded-md text-sm font-semibold hover:bg-primary-hover transition-colors disabled:opacity-40"
              disabled={busy || !username || !password}
            >
              {busy ? "Signing in..." : "Sign in"}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}
