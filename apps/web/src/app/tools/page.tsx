"use client";

import { useState } from "react";
import {
  api,
  type LLMTestResult,
  type ReachabilityResult,
  type NmapResult,
  type DNSResult,
} from "@/lib/api";
import { Button, Panel } from "@/components/ui";

export default function ToolsPage() {
  return (
    <div className="max-w-[1180px]">
      <header className="mb-5">
        <h1 className="text-2xl font-semibold leading-tight">Tools</h1>
        <p className="text-sm text-ink-2 mt-0.5">
          Manual verification tools — test connections, check targets, scan ports.
        </p>
      </header>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
        <LLMTestCard />
        <ReachabilityCard />
        <NmapCard />
        <DNSCard />
      </div>
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/*  Shared                                                                     */
/* -------------------------------------------------------------------------- */

function StatusDot({ ok }: { ok: boolean }) {
  return (
    <span className={`inline-block w-2 h-2 rounded-full shrink-0 ${ok ? "bg-ok" : "bg-sev-critical"}`} />
  );
}

function Spinner() {
  return (
    <span className="inline-block rounded-full border-2 border-line-strong border-t-accent animate-spin w-3.5 h-3.5" />
  );
}

function InfoRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  if (!value) return null;
  return (
    <div className="flex items-start gap-2 text-xs">
      <span className="text-ink-3 w-20 shrink-0">{label}</span>
      <span className={`text-ink break-all ${mono ? "mono" : ""}`}>{value}</span>
    </div>
  );
}

function ErrorBox({ error }: { error: string }) {
  if (!error) return null;
  return (
    <div className="bg-sev-critical/10 border border-sev-critical/30 rounded-sm px-3 py-2">
      <div className="text-2xs text-sev-critical uppercase tracking-wider mb-1">Error</div>
      <div className="text-xs text-ink break-all">{error}</div>
    </div>
  );
}

const inputCls =
  "h-8 flex-1 min-w-0 rounded bg-surface-2 border border-line text-xs text-ink px-3 placeholder:text-ink-3 focus:outline-none focus:border-primary mono";

const selectCls =
  "h-8 rounded bg-surface-2 border border-line text-xs text-ink px-2 pr-6 appearance-none " +
  "bg-[url('data:image/svg+xml;charset=utf-8,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%20width%3D%2210%22%20height%3D%226%22%3E%3Cpath%20d%3D%22M0%200l5%206%205-6z%22%20fill%3D%22%236b7c8f%22%2F%3E%3C%2Fsvg%3E')] " +
  "bg-[length:10px_6px] bg-[right_6px_center] bg-no-repeat focus:outline-none focus:border-primary";

/* -------------------------------------------------------------------------- */
/*  LLM Connection                                                             */
/* -------------------------------------------------------------------------- */

function LLMTestCard() {
  const [result, setResult] = useState<LLMTestResult | null>(null);
  const [loading, setLoading] = useState(false);

  async function run() {
    setLoading(true);
    setResult(null);
    try {
      setResult(await api.testLLM());
    } catch (e) {
      setResult({
        connected: false, provider: "", model: "", endpoint: "",
        response_text: "", latency_ms: 0, error: String(e), profiles: [],
      });
    } finally {
      setLoading(false);
    }
  }

  return (
    <Panel
      title="LLM Connection"
      meta={result ? (result.connected ? "connected" : "failed") : undefined}
    >
      <div className="px-4 py-3 space-y-3">
        <p className="text-xs text-ink-2">
          Test the connection to the LLM backend used for finding enrichment, report
          generation, and agent reasoning.
        </p>

        <Button onClick={run} disabled={loading}>
          {loading ? "Testing…" : "Test connection"}
        </Button>

        {loading && (
          <div className="flex items-center gap-2 text-xs text-ink-3">
            <Spinner /> Sending test prompt to LLM…
          </div>
        )}

        {result && (
          <div className="space-y-2.5">
            <div className="flex items-center gap-2">
              <StatusDot ok={result.connected} />
              <span className={`text-sm font-medium ${result.connected ? "text-ok" : "text-sev-critical"}`}>
                {result.connected ? "Connected" : "Connection failed"}
              </span>
              {result.latency_ms > 0 && (
                <span className="text-2xs text-ink-3 tnum ml-auto">{result.latency_ms}ms</span>
              )}
            </div>

            <div className="bg-surface-2 border border-line rounded-sm px-3 py-2 space-y-1.5">
              <InfoRow label="Provider" value={result.provider} />
              <InfoRow label="Model" value={result.model} />
              <InfoRow label="Endpoint" value={result.endpoint} mono />
              {result.profiles.length > 0 && (
                <InfoRow label="Profiles" value={result.profiles.join(", ")} />
              )}
              {result.response_text && (
                <InfoRow label="Response" value={result.response_text} />
              )}
            </div>

            <ErrorBox error={result.error} />

            {!result.connected && (
              <div className="text-xs text-ink-3 space-y-1">
                <p>Set these environment variables and restart the API server:</p>
                <div className="mono text-2xs bg-surface-2 border border-line rounded-sm px-3 py-2 space-y-0.5">
                  <div>VAPT_LLM_PROVIDER=ollama</div>
                  <div>VAPT_LLM_BASE_URL=http://localhost:11434</div>
                  <div>VAPT_LLM_MODEL=qwen2.5:14b-instruct</div>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </Panel>
  );
}

/* -------------------------------------------------------------------------- */
/*  Reachability                                                               */
/* -------------------------------------------------------------------------- */

function ReachabilityCard() {
  const [target, setTarget] = useState("");
  const [result, setResult] = useState<ReachabilityResult | null>(null);
  const [loading, setLoading] = useState(false);

  async function run() {
    if (!target.trim()) return;
    setLoading(true);
    setResult(null);
    try {
      setResult(await api.checkReachability(target));
    } catch (e) {
      setResult({
        target, reachable: false, ping_ok: false, ping_latency_ms: null,
        http_ok: false, http_status: null, http_title: "", http_server: "",
        http_latency_ms: null, dns_resolved: "", error: String(e),
      });
    } finally {
      setLoading(false);
    }
  }

  return (
    <Panel
      title="Reachability Check"
      meta={result ? (result.reachable ? "reachable" : "unreachable") : undefined}
    >
      <div className="px-4 py-3 space-y-3">
        <p className="text-xs text-ink-2">
          Check if an IP address or URL is reachable via ping, DNS resolution, and HTTP.
        </p>

        <div className="flex gap-2">
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && run()}
            placeholder="e.g. 192.168.1.1 or example.com"
            className={inputCls}
          />
          <Button onClick={run} disabled={loading || !target.trim()}>
            {loading ? "Checking…" : "Check"}
          </Button>
        </div>

        {loading && (
          <div className="flex items-center gap-2 text-xs text-ink-3">
            <Spinner /> Checking {target}…
          </div>
        )}

        {result && (
          <div className="space-y-2.5">
            <div className="flex items-center gap-2">
              <StatusDot ok={result.reachable} />
              <span className={`text-sm font-medium ${result.reachable ? "text-ok" : "text-sev-critical"}`}>
                {result.reachable ? "Reachable" : "Unreachable"}
              </span>
            </div>

            <div className="bg-surface-2 border border-line rounded-sm px-3 py-2 space-y-1.5">
              <InfoRow label="Target" value={result.target} mono />
              {result.dns_resolved && (
                <InfoRow label="DNS" value={result.dns_resolved} mono />
              )}

              {/* Ping result */}
              <div className="flex items-center gap-2 text-xs">
                <span className="text-ink-3 w-20 shrink-0">Ping</span>
                {result.ping_ok ? (
                  <span className="text-ok">
                    OK{result.ping_latency_ms != null ? ` (${result.ping_latency_ms.toFixed(1)}ms avg)` : ""}
                  </span>
                ) : (
                  <span className="text-ink-3">No response</span>
                )}
              </div>

              {/* HTTP result */}
              <div className="flex items-center gap-2 text-xs">
                <span className="text-ink-3 w-20 shrink-0">HTTP</span>
                {result.http_ok ? (
                  <span className="text-ok">
                    {result.http_status}{result.http_latency_ms != null ? ` (${result.http_latency_ms}ms)` : ""}
                  </span>
                ) : result.http_status ? (
                  <span className="text-sev-high">
                    {result.http_status}
                  </span>
                ) : (
                  <span className="text-ink-3">No response</span>
                )}
              </div>

              {result.http_title && <InfoRow label="Title" value={result.http_title} />}
              {result.http_server && <InfoRow label="Server" value={result.http_server} />}
            </div>

            <ErrorBox error={result.error} />
          </div>
        )}
      </div>
    </Panel>
  );
}

/* -------------------------------------------------------------------------- */
/*  Nmap                                                                       */
/* -------------------------------------------------------------------------- */

const SCAN_TYPES = [
  { value: "quick", label: "Quick (-F)" },
  { value: "top100", label: "Top 100 ports" },
  { value: "service", label: "Service detection (-sV)" },
  { value: "full", label: "Full port scan (-p-)" },
  { value: "custom", label: "Custom ports" },
];

function NmapCard() {
  const [target, setTarget] = useState("");
  const [scanType, setScanType] = useState("quick");
  const [ports, setPorts] = useState("");
  const [result, setResult] = useState<NmapResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [showRaw, setShowRaw] = useState(false);

  async function run() {
    if (!target.trim()) return;
    setLoading(true);
    setResult(null);
    setShowRaw(false);
    try {
      setResult(await api.runNmap(target, scanType, ports));
    } catch (e) {
      setResult({
        target, command: "", open_ports: [], os_guess: "",
        raw_output: "", latency_ms: 0, error: String(e),
      });
    } finally {
      setLoading(false);
    }
  }

  return (
    <Panel
      title="Nmap Scan"
      meta={result ? `${result.open_ports.length} open` : undefined}
    >
      <div className="px-4 py-3 space-y-3">
        <p className="text-xs text-ink-2">
          Run an nmap port scan against a target to discover open ports and services.
        </p>

        <div className="flex flex-wrap gap-2">
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && run()}
            placeholder="e.g. 192.168.1.1 or example.com"
            className={inputCls}
          />
          <select value={scanType} onChange={(e) => setScanType(e.target.value)} className={selectCls}>
            {SCAN_TYPES.map((s) => (
              <option key={s.value} value={s.value}>{s.label}</option>
            ))}
          </select>
          <Button onClick={run} disabled={loading || !target.trim()}>
            {loading ? "Scanning…" : "Scan"}
          </Button>
        </div>

        {scanType === "custom" && (
          <input
            type="text"
            value={ports}
            onChange={(e) => setPorts(e.target.value)}
            placeholder="e.g. 80,443,8080 or 1-1000"
            className={inputCls + " w-full"}
          />
        )}

        {loading && (
          <div className="flex items-center gap-2 text-xs text-ink-3">
            <Spinner /> Running nmap on {target}… this may take a minute.
          </div>
        )}

        {result && (
          <div className="space-y-2.5">
            {result.command && (
              <div className="mono text-2xs text-ink-3 bg-surface-2 border border-line rounded-sm px-3 py-1.5 break-all">
                $ {result.command}
              </div>
            )}

            {result.open_ports.length > 0 ? (
              <div className="border border-line rounded-sm overflow-hidden">
                <div className="flex items-center gap-3 px-3 py-1.5 bg-surface-2 border-b border-line text-2xs text-ink-3 uppercase tracking-wider">
                  <span className="w-16">Port</span>
                  <span className="w-14">State</span>
                  <span className="flex-1">Service</span>
                </div>
                {result.open_ports.map((p) => (
                  <div
                    key={`${p.port}/${p.protocol}`}
                    className="flex items-center gap-3 px-3 py-1.5 border-b border-line last:border-0 text-xs"
                  >
                    <span className="w-16 mono tnum text-primary">
                      {p.port}/{p.protocol}
                    </span>
                    <span className={`w-14 ${p.state === "open" ? "text-ok" : "text-ink-3"}`}>
                      {p.state}
                    </span>
                    <span className="flex-1 text-ink">{p.service || "—"}</span>
                  </div>
                ))}
              </div>
            ) : !result.error ? (
              <div className="text-xs text-ink-3 px-1">No open ports found.</div>
            ) : null}

            {result.os_guess && <InfoRow label="OS guess" value={result.os_guess} />}
            {result.latency_ms > 0 && (
              <div className="text-2xs text-ink-3 tnum">Completed in {(result.latency_ms / 1000).toFixed(1)}s</div>
            )}

            <ErrorBox error={result.error} />

            {result.raw_output && (
              <div>
                <button
                  type="button"
                  onClick={() => setShowRaw((v) => !v)}
                  className="text-xs text-ink-3 hover:text-ink"
                >
                  {showRaw ? "▴ Hide" : "▾ Show"} raw output
                </button>
                {showRaw && (
                  <pre className="mt-1.5 bg-surface-2 border border-line rounded-sm px-3 py-2 text-2xs mono text-ink-2 overflow-x-auto max-h-[300px] whitespace-pre-wrap">
                    {result.raw_output}
                  </pre>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    </Panel>
  );
}

/* -------------------------------------------------------------------------- */
/*  DNS Lookup                                                                 */
/* -------------------------------------------------------------------------- */

function DNSCard() {
  const [target, setTarget] = useState("");
  const [result, setResult] = useState<DNSResult | null>(null);
  const [loading, setLoading] = useState(false);

  async function run() {
    if (!target.trim()) return;
    setLoading(true);
    setResult(null);
    try {
      setResult(await api.dnsLookup(target));
    } catch (e) {
      setResult({ target, records: [], error: String(e) });
    } finally {
      setLoading(false);
    }
  }

  const grouped = result
    ? result.records.reduce<Record<string, string[]>>((acc, r) => {
        (acc[r.type] ??= []).push(r.value);
        return acc;
      }, {})
    : {};

  return (
    <Panel
      title="DNS Lookup"
      meta={result ? `${result.records.length} records` : undefined}
    >
      <div className="px-4 py-3 space-y-3">
        <p className="text-xs text-ink-2">
          Resolve DNS records (A, AAAA, MX, NS, TXT, CNAME) for a hostname.
        </p>

        <div className="flex gap-2">
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && run()}
            placeholder="e.g. example.com"
            className={inputCls}
          />
          <Button onClick={run} disabled={loading || !target.trim()}>
            {loading ? "Resolving…" : "Lookup"}
          </Button>
        </div>

        {loading && (
          <div className="flex items-center gap-2 text-xs text-ink-3">
            <Spinner /> Resolving {target}…
          </div>
        )}

        {result && (
          <div className="space-y-2.5">
            {Object.keys(grouped).length > 0 ? (
              <div className="bg-surface-2 border border-line rounded-sm px-3 py-2 space-y-2">
                {Object.entries(grouped).map(([type, values]) => (
                  <div key={type}>
                    <div className="text-2xs text-ink-3 uppercase tracking-wider mb-0.5">{type}</div>
                    {values.map((v, i) => (
                      <div key={i} className="mono text-xs text-ink break-all">{v}</div>
                    ))}
                  </div>
                ))}
              </div>
            ) : !result.error ? (
              <div className="text-xs text-ink-3">No records found.</div>
            ) : null}

            <ErrorBox error={result.error} />
          </div>
        )}
      </div>
    </Panel>
  );
}
