import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        bg: "var(--bg)",
        surface: "var(--surface)",
        "surface-2": "var(--surface-2)",
        line: "var(--line)",
        "line-strong": "var(--line-strong)",
        ink: "var(--ink)",
        "ink-2": "var(--ink-2)",
        "ink-3": "var(--ink-3)",
        primary: "var(--primary)",
        "primary-hover": "var(--primary-hover)",
        accent: "var(--accent)",
        "accent-deep": "var(--accent-deep)",
        ok: "var(--ok)",
        "sidebar-bg": "var(--sidebar-bg)",
        "sidebar-ink": "var(--sidebar-ink)",
        "sidebar-ink-2": "var(--sidebar-ink-2)",
        "sidebar-line": "var(--sidebar-line)",
        "sidebar-active": "var(--sidebar-active)",
        "input-bg": "var(--input-bg)",
        sev: {
          info: "var(--sev-info)",
          low: "var(--sev-low)",
          medium: "var(--sev-medium)",
          high: "var(--sev-high)",
          critical: "var(--sev-critical)",
        },
      },
      fontFamily: {
        sans: ['"Inter"', "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ['"IBM Plex Mono"', "ui-monospace", "monospace"],
      },
      borderRadius: { DEFAULT: "6px", sm: "4px", md: "6px", lg: "8px", xl: "12px" },
      fontSize: {
        "2xs": ["11px", "1.35"],
        xs: ["12px", "1.4"],
        sm: ["13px", "1.5"],
        base: ["14px", "1.5"],
        lg: ["16px", "1.4"],
        xl: ["20px", "1.3"],
        "2xl": ["26px", "1.2"],
        "3xl": ["34px", "1.1"],
      },
      boxShadow: {
        card: "var(--shadow-card)",
        "card-hover": "var(--shadow-card-hover)",
      },
    },
  },
  plugins: [],
};
export default config;
