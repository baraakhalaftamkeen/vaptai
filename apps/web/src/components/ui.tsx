"use client";

import type { ReactNode } from "react";

/* ------------------------------------------------------------------ *
 * Panel — a bordered region with a hairline header. No drop shadows:
 * structure comes from hairlines, so hierarchy stays readable at density.
 * ------------------------------------------------------------------ */
export function Panel({
  title,
  meta,
  action,
  children,
  className = "",
}: {
  title: string;
  meta?: ReactNode;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`bg-surface border border-line rounded ${className}`}>
      <header className="flex items-baseline justify-between gap-3 px-4 h-11 border-b border-line">
        <div className="flex items-baseline gap-2.5 min-w-0">
          <h2 className="text-sm font-semibold text-ink truncate">{title}</h2>
          {meta && <span className="text-xs text-ink-3 tnum shrink-0">{meta}</span>}
        </div>
        {action}
      </header>
      {children}
    </section>
  );
}

/* Rows, not cards. A list is a stack of hairline-separated rows. */
export function Row({
  children,
  className = "",
  onClick,
}: {
  children: ReactNode;
  className?: string;
  onClick?: () => void;
}) {
  const interactive = onClick
    ? "hover:bg-surface-2 cursor-pointer w-full text-left"
    : "";
  const Tag = onClick ? "button" : "div";
  return (
    <Tag
      onClick={onClick}
      className={`flex items-center gap-3 px-4 py-2.5 border-b border-line last:border-0 ${interactive} ${className}`}
    >
      {children}
    </Tag>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  // An empty screen is an invitation to act, not a shrug.
  return <p className="px-4 py-6 text-sm text-ink-3">{children}</p>;
}

/* ------------------------------------------------------------------ *
 * Severity — a validated warm chroma ramp. The word is always present,
 * so severity is never carried by color alone.
 * ------------------------------------------------------------------ */
export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
export type Severity = (typeof SEVERITIES)[number];

export const SEV_VAR: Record<string, string> = {
  critical: "var(--sev-critical)",
  high: "var(--sev-high)",
  medium: "var(--sev-medium)",
  low: "var(--sev-low)",
  info: "var(--sev-info)",
};

export function SeverityTag({ severity }: { severity: string }) {
  const c = SEV_VAR[severity] ?? SEV_VAR.info;
  return (
    <span className="inline-flex items-center gap-1.5 text-xs shrink-0" style={{ color: c }}>
      <span
        aria-hidden
        className="w-1.5 h-3 rounded-sm shrink-0"
        style={{ background: c }}
      />
      {severity}
    </span>
  );
}

/* Finding lifecycle. Cool/neutral — risk is the only warm thing in the UI. */
export function StatusTag({ status }: { status: string }) {
  const map: Record<string, string> = {
    confirmed: "text-ok",
    candidate: "text-ink-2",
    inconclusive: "text-ink-3",
    false_positive: "text-ink-3 line-through",
    running: "text-accent",
    queued: "text-ink-2",
    paused: "text-accent",
    awaiting_approval: "text-accent",
    completed: "text-ink-3",
    failed: "text-sev-high",
    cancelled: "text-ink-3",
    cancelling: "text-ink-2",
  };
  return (
    <span className={`text-xs ${map[status] ?? "text-ink-3"}`}>
      {status.replace(/_/g, " ")}
    </span>
  );
}

/* Policy class reads as governance, not risk: neutral chip + mono code. */
export function PolicyTag({ policyClass }: { policyClass: string }) {
  const code = policyClass.split("_")[0].toUpperCase();
  const label: Record<string, string> = {
    P0: "passive",
    P1: "low impact",
    P2: "intrusive",
    P3: "excluded",
  };
  return (
    <span className="inline-flex items-baseline gap-1.5 shrink-0 whitespace-nowrap">
      <span className="mono text-2xs px-1.5 py-0.5 rounded-sm bg-surface-2 border border-line text-ink">
        {code}
      </span>
      <span className="text-xs text-ink-3">{label[code] ?? ""}</span>
    </span>
  );
}

/* ------------------------------------------------------------------ *
 * SeverityMeter — a proportional stacked bar for ordered magnitude.
 * 2px surface gaps between segments, direct counts, hover titles.
 * ------------------------------------------------------------------ */
export function SeverityMeter({ counts }: { counts: Record<string, number> }) {
  const present = SEVERITIES.filter((s) => (counts[s] ?? 0) > 0);
  const total = present.reduce((n, s) => n + (counts[s] ?? 0), 0);

  if (total === 0) {
    return <Empty>No findings yet. Start a run to collect evidence.</Empty>;
  }

  return (
    <div className="px-4 py-4">
      <div className="flex items-end justify-between mb-2.5">
        <span className="text-3xl font-semibold tnum leading-none">{total}</span>
        <span className="text-xs text-ink-3">
          {total === 1 ? "finding" : "findings"}
        </span>
      </div>
      <div className="flex gap-0.5 h-2.5 mb-3" role="img" aria-label={`Findings by severity: ${present.map((s) => `${counts[s]} ${s}`).join(", ")}`}>
        {present.map((s) => (
          <div
            key={s}
            title={`${counts[s]} ${s}`}
            className="first:rounded-l-sm last:rounded-r-sm"
            style={{
              background: SEV_VAR[s],
              width: `${((counts[s] ?? 0) / total) * 100}%`,
            }}
          />
        ))}
      </div>
      <ul className="space-y-1.5">
        {present.map((s) => (
          <li key={s} className="flex items-center justify-between">
            <SeverityTag severity={s} />
            <span className="text-xs tnum text-ink-2">{counts[s]}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

/* Short id for display; the full value stays in the title attribute. */
export function ShortId({ id }: { id: string }) {
  return (
    <span className="mono text-xs text-ink-3" title={id}>
      {id.slice(0, 8)}
    </span>
  );
}

export function Button({
  children,
  onClick,
  variant = "default",
  disabled,
  className = "",
}: {
  children: ReactNode;
  onClick?: () => void;
  variant?: "default" | "primary" | "quiet" | "danger";
  disabled?: boolean;
  className?: string;
}) {
  const styles: Record<string, string> = {
    primary: "bg-accent text-[#06212b] hover:bg-[#7bdcf7] font-medium",
    default: "bg-surface-2 border border-line-strong text-ink hover:border-accent-deep",
    quiet: "text-ink-2 hover:text-ink",
    danger: "bg-surface-2 border border-line-strong text-sev-high hover:border-sev-high",
  };
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className={`inline-flex items-center justify-center h-7 px-3 rounded text-xs transition-colors disabled:opacity-40 disabled:cursor-not-allowed ${styles[variant]} ${className}`}
    >
      {children}
    </button>
  );
}
