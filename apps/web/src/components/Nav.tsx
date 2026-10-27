"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { api, type Me } from "@/lib/api";

const LINKS = [
  { href: "/dashboard", label: "Overview" },
  { href: "/engagements", label: "Engagements" },
  { href: "/runs", label: "Runs" },
  { href: "/approvals", label: "Approvals" },
  { href: "/cves", label: "CVEs" },
];

export default function Nav() {
  const pathname = usePathname();
  const router = useRouter();
  const [me, setMe] = useState<Me | null>(null);
  const [pending, setPending] = useState(0);

  useEffect(() => {
    api.me().then(setMe).catch(() => setMe(null));
    api
      .listApprovals()
      .then((a) => setPending(a.length))
      .catch(() => setPending(0));
  }, [pathname]);

  // The login page renders without the app chrome.
  if (pathname === "/login") return null;

  // Admins also get the Users link.
  const isAdmin = me ? Object.values(me.roles).includes("admin") : false;
  const links = isAdmin ? [...LINKS, { href: "/users", label: "Users" }] : LINKS;

  async function signOut() {
    try {
      await api.logout();
    } finally {
      setMe(null);
      router.push("/login");
    }
  }

  return (
    <aside className="w-full md:w-[216px] shrink-0 bg-surface border-b md:border-b-0 md:border-r border-line flex flex-col">
      <div className="h-14 flex items-center gap-1.5 px-4 border-b border-line">
        {/* Mark: a bracketed scope — the product's whole premise is a bounded target. */}
        <span className="mono text-accent text-base leading-none">[</span>
        <span className="font-semibold tracking-tight">VAPT-AI</span>
        <span className="mono text-2xs text-ink-3 border border-line rounded-sm px-1">v2</span>
        <span className="mono text-accent text-base leading-none">]</span>
      </div>

      <nav className="flex-1 p-2 flex flex-row md:flex-col gap-1 md:gap-0 overflow-x-auto">
        {links.map((l) => {
          const active = pathname.startsWith(l.href);
          return (
            <Link
              key={l.href}
              href={l.href}
              className={`flex items-center justify-between gap-2 h-8 px-2.5 rounded text-sm transition-colors shrink-0 ${
                active ? "bg-surface-2 text-ink" : "text-ink-2 hover:text-ink hover:bg-surface-2"
              }`}
            >
              <span className="flex items-center gap-2">
                <span
                  aria-hidden
                  className={`w-[2px] h-4 rounded-full ${active ? "bg-accent" : "bg-transparent"}`}
                />
                {l.label}
              </span>
              {l.href === "/approvals" && pending > 0 && (
                <span className="flex items-center gap-1.5">
                  <span className="signal-dot w-1.5 h-1.5 rounded-full bg-accent" />
                  <span className="text-xs tnum text-accent">{pending}</span>
                </span>
              )}
            </Link>
          );
        })}
      </nav>

      <div className="hidden md:block p-3 border-t border-line">
        {me ? (
          <div className="flex items-center justify-between gap-2">
            <div className="min-w-0">
              <div className="text-sm truncate">{me.username}</div>
              <div className="text-2xs text-ink-3">
                {Object.values(me.roles)[0] ?? "no role"}
              </div>
            </div>
            <button
              onClick={signOut}
              className="text-xs text-ink-3 hover:text-ink shrink-0"
            >
              Sign out
            </button>
          </div>
        ) : (
          <Link href="/login" className="text-xs text-ink-2 hover:text-ink">
            Sign in
          </Link>
        )}
      </div>
    </aside>
  );
}
