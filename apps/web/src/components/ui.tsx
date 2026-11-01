"use client";

import type { ReactNode } from "react";

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
    <section className={`bg-surface border border-line rounded-lg shadow-card ${className}`}>
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
  return <p className="px-4 py-6 text-sm text-ink-3">{children}</p>;
}

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

export function StatusTag({ status }: { status: string }) {
  const map: Record<string, string> = {
    confirmed: "text-ok",
    candidate: "text-ink-2",
    inconclusive: "text-ink-3",
    false_positive: "text-ink-3 line-through",
    running: "text-primary",
    queued: "text-ink-2",
    paused: "text-accent-deep",
    awaiting_approval: "text-accent-deep",
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
      <span className="mono text-2xs px-1.5 py-0.5 rounded bg-surface-2 border border-line text-ink font-medium">
        {code}
      </span>
      <span className="text-xs text-ink-3">{label[code] ?? ""}</span>
    </span>
  );
}

export function SeverityMeter({ counts }: { counts: Record<string, number> }) {
  const present = SEVERITIES.filter((s) => (counts[s] ?? 0) > 0);
  const total = present.reduce((n, s) => n + (counts[s] ?? 0), 0);

  if (total === 0) {
    return <Empty>No findings yet. Start a run to collect evidence.</Empty>;
  }

  return (
    <div className="px-4 py-4">
      <div className="flex items-end justify-between mb-2.5">
        <span className="text-3xl font-bold tnum leading-none">{total}</span>
        <span className="text-xs text-ink-3">
          {total === 1 ? "finding" : "findings"}
        </span>
      </div>
      <div className="flex gap-0.5 h-2.5 mb-3" role="img" aria-label={`Findings by severity: ${present.map((s) => `${counts[s]} ${s}`).join(", ")}`}>
        {present.map((s) => (
          <div
            key={s}
            title={`${counts[s]} ${s}`}
            className="first:rounded-l last:rounded-r"
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
    primary: "bg-primary text-white hover:bg-primary-hover font-medium",
    default: "bg-surface border border-line text-ink hover:border-line-strong hover:shadow-card",
    quiet: "text-ink-2 hover:text-ink",
    danger: "bg-surface border border-line text-sev-high hover:border-sev-high",
  };
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className={`inline-flex items-center justify-center h-8 px-3.5 rounded-md text-xs transition-colors disabled:opacity-40 disabled:cursor-not-allowed ${styles[variant]} ${className}`}
    >
      {children}
    </button>
  );
}
