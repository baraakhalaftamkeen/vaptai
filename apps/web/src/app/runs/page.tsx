"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { api, type Run } from "@/lib/api";
import { Empty, Panel, Row, ShortId, StatusTag } from "@/components/ui";

export default function RunsPage() {
  const router = useRouter();
  const [runs, setRuns] = useState<Run[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.listRuns().then(setRuns).catch((e) => setError(String(e)));
  }, []);

  const sorted = [...runs].sort((a, b) => b.created_at.localeCompare(a.created_at));

  return (
    <div className="max-w-[1180px]">
      <header className="mb-5">
        <h1 className="text-2xl font-semibold leading-tight">Runs</h1>
        <p className="text-sm text-ink-2 mt-0.5">
          Every run keeps a full execution ledger. Open one to see its timeline and findings.
        </p>
      </header>

      {error && (
        <p className="text-sm text-ink-2 border border-line bg-surface rounded px-4 py-3 mb-4">
          {error}
        </p>
      )}

      <Panel title="All runs" meta={sorted.length ? `${sorted.length}` : undefined}>
        {sorted.length === 0 ? (
          <Empty>No runs yet. Start one from an engagement.</Empty>
        ) : (
          sorted.map((r) => (
            <Row key={r.id} onClick={() => router.push(`/runs/${r.id}`)}>
              <ShortId id={r.id} />
              <span className="flex-1 min-w-0 text-xs text-ink-2 truncate">{r.phase ?? "—"}</span>
              <span className="w-28 shrink-0">
                <StatusTag status={r.status} />
              </span>
              <span className="text-xs text-ink-3 tnum shrink-0">
                {new Date(r.created_at).toLocaleString()}
              </span>
            </Row>
          ))
        )}
      </Panel>
    </div>
  );
}
