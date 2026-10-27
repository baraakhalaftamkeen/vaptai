import type { Config } from "tailwindcss";

// Tokens live in globals.css as CSS custom properties; Tailwind just exposes them
// so component classes stay readable and there is one source of truth.
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
        accent: "var(--accent)",
        "accent-deep": "var(--accent-deep)",
        ok: "var(--ok)",
        sev: {
          info: "var(--sev-info)",
          low: "var(--sev-low)",
          medium: "var(--sev-medium)",
          high: "var(--sev-high)",
          critical: "var(--sev-critical)",
        },
      },
      fontFamily: {
        sans: ['"IBM Plex Sans"', "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ['"IBM Plex Mono"', "ui-monospace", "monospace"],
      },
      borderRadius: { DEFAULT: "4px", sm: "3px", md: "4px", lg: "6px" },
      fontSize: {
        // Compact operational scale.
        "2xs": ["11px", "1.35"],
        xs: ["12px", "1.4"],
        sm: ["13px", "1.5"],
        base: ["14px", "1.5"],
        lg: ["16px", "1.4"],
        xl: ["20px", "1.3"],
        "2xl": ["26px", "1.2"],
        "3xl": ["34px", "1.1"],
      },
    },
  },
  plugins: [],
};
export default config;
