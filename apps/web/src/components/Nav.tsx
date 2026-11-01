"use client";

import Link from "next/link";
/* eslint-disable @next/next/no-img-element */
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { api, type Me } from "@/lib/api";
import { useTheme } from "@/components/ThemeProvider";

const LINKS = [
  { href: "/dashboard", label: "Overview", icon: "grid" },
  { href: "/engagements", label: "Engagements", icon: "briefcase" },
  { href: "/runs", label: "Runs", icon: "play" },
  { href: "/findings", label: "Findings", icon: "alert" },
  { href: "/approvals", label: "Approvals", icon: "check" },
  { href: "/tools", label: "Tools", icon: "wrench" },
  { href: "/cves", label: "CVEs", icon: "shield" },
];

const ICONS: Record<string, React.ReactElement> = {
  grid: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="3" width="7" height="7" /><rect x="14" y="3" width="7" height="7" /><rect x="3" y="14" width="7" height="7" /><rect x="14" y="14" width="7" height="7" />
    </svg>
  ),
  briefcase: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="2" y="7" width="20" height="14" rx="2" /><path d="M16 7V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v2" />
    </svg>
  ),
  play: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10" /><polygon points="10 8 16 12 10 16 10 8" />
    </svg>
  ),
  alert: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" /><line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" />
    </svg>
  ),
  check: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M9 11l3 3L22 4" /><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11" />
    </svg>
  ),
  wrench: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z" />
    </svg>
  ),
  shield: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
  ),
  users: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" /><circle cx="9" cy="7" r="4" /><path d="M23 21v-2a4 4 0 0 0-3-3.87" /><path d="M16 3.13a4 4 0 0 1 0 7.75" />
    </svg>
  ),
};

export default function Nav() {
  const pathname = usePathname();
  const router = useRouter();
  const { theme, toggle } = useTheme();
  const [me, setMe] = useState<Me | null>(null);
  const [pending, setPending] = useState(0);

  useEffect(() => {
    api.me().then(setMe).catch(() => setMe(null));
    api
      .listApprovals()
      .then((a) => setPending(a.length))
      .catch(() => setPending(0));
  }, [pathname]);

  if (pathname === "/login") return null;

  const isAdmin = me ? Object.values(me.roles).includes("admin") : false;
  const links = isAdmin
    ? [...LINKS, { href: "/users", label: "Users", icon: "users" }]
    : LINKS;

  async function signOut() {
    try {
      await api.logout();
    } finally {
      setMe(null);
      router.push("/login");
    }
  }

  return (
    <aside className="w-full md:w-[232px] shrink-0 bg-sidebar-bg flex flex-col">
      {/* Logo */}
      <div className="h-16 flex items-center px-5 border-b border-sidebar-line">
        <img
          src="/tamkeen-logo.svg"
          alt="Tamkeen Technologies"
          width={140}
          height={42}
        />
      </div>

      {/* Product label */}
      <div className="px-5 pt-4 pb-2">
        <span className="text-2xs font-semibold uppercase tracking-widest text-sidebar-ink-2">
          VAPT Platform
        </span>
      </div>

      <nav className="flex-1 px-3 flex flex-row md:flex-col gap-0.5 overflow-x-auto">
        {links.map((l) => {
          const active = pathname.startsWith(l.href);
          return (
            <Link
              key={l.href}
              href={l.href}
              className={`flex items-center justify-between gap-2.5 h-9 px-3 rounded-md text-sm transition-colors shrink-0 ${
                active
                  ? "bg-primary text-white font-medium"
                  : "text-sidebar-ink hover:text-white hover:bg-white/[0.06]"
              }`}
            >
              <span className="flex items-center gap-2.5">
                <span className={active ? "text-white" : "text-sidebar-ink-2"}>
                  {ICONS[l.icon]}
                </span>
                {l.label}
              </span>
              {l.href === "/approvals" && pending > 0 && (
                <span className="flex items-center gap-1.5">
                  <span className="signal-dot w-1.5 h-1.5 rounded-full bg-accent" />
                  <span className="text-xs tnum text-accent font-medium">{pending}</span>
                </span>
              )}
            </Link>
          );
        })}
      </nav>

      <div className="hidden md:block border-t border-sidebar-line">
        <div className="px-3 pt-3 pb-2">
          <button
            onClick={toggle}
            className="flex items-center gap-2.5 w-full h-9 px-3 rounded-md text-sm text-sidebar-ink hover:text-white hover:bg-white/[0.06] transition-colors"
            title={theme === "light" ? "Switch to dark mode" : "Switch to light mode"}
          >
            <span className="text-sidebar-ink-2">
              {theme === "light" ? (
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
                </svg>
              ) : (
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <circle cx="12" cy="12" r="5" /><line x1="12" y1="1" x2="12" y2="3" /><line x1="12" y1="21" x2="12" y2="23" /><line x1="4.22" y1="4.22" x2="5.64" y2="5.64" /><line x1="18.36" y1="18.36" x2="19.78" y2="19.78" /><line x1="1" y1="12" x2="3" y2="12" /><line x1="21" y1="12" x2="23" y2="12" /><line x1="4.22" y1="19.78" x2="5.64" y2="18.36" /><line x1="18.36" y1="5.64" x2="19.78" y2="4.22" />
                </svg>
              )}
            </span>
            {theme === "light" ? "Dark mode" : "Light mode"}
          </button>
        </div>
        <div className="px-4 pb-4">
          {me ? (
            <div className="flex items-center justify-between gap-2">
              <div className="min-w-0">
                <div className="text-sm text-sidebar-ink truncate">{me.username}</div>
                <div className="text-2xs text-sidebar-ink-2">
                  {Object.values(me.roles)[0] ?? "no role"}
                </div>
              </div>
              <button
                onClick={signOut}
                className="text-xs text-sidebar-ink-2 hover:text-white shrink-0 transition-colors"
              >
                Sign out
              </button>
            </div>
          ) : (
            <Link href="/login" className="text-xs text-sidebar-ink-2 hover:text-white">
              Sign in
            </Link>
          )}
        </div>
      </div>
    </aside>
  );
}
