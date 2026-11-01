"use client";

import { Suspense, useCallback, useEffect, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { api, type PortalUser } from "@/lib/api";
import { Button, Empty, Panel } from "@/components/ui";

function SuccessBanner() {
  const sp = useSearchParams();
  const msg = sp.get("success");
  if (!msg) return null;
  const labels: Record<string, string> = {
    created: "User created successfully.",
    updated: "User updated successfully.",
    deleted: "User deleted successfully.",
  };
  return (
    <div className="border border-green-600/30 bg-green-600/10 text-green-400 rounded px-4 py-2.5 mb-4 text-sm">
      {labels[msg] ?? "Done."}
    </div>
  );
}

function UsersInner() {
  const router = useRouter();
  const [users, setUsers] = useState<PortalUser[] | null>(null);
  const [forbidden, setForbidden] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const reload = useCallback(() => {
    api
      .listUsers()
      .then((u) => { setUsers(u); setForbidden(false); })
      .catch((e) => {
        if (String(e).includes("403")) setForbidden(true);
        else setError(String(e));
      });
  }, []);
  useEffect(reload, [reload]);

  if (forbidden) {
    return (
      <div className="max-w-[960px]">
        <h1 className="text-2xl font-semibold leading-tight mb-2">Users</h1>
        <p className="text-sm text-ink-2">
          User management is available to administrators only.
        </p>
      </div>
    );
  }

  return (
    <div className="max-w-[960px]">
      <header className="flex items-end justify-between gap-4 mb-5">
        <div>
          <h1 className="text-2xl font-semibold leading-tight">Users</h1>
          <p className="text-sm text-ink-2 mt-0.5">
            Portal accounts and permissions.
          </p>
        </div>
        <Button variant="primary" onClick={() => router.push("/users/new")}>
          Add user
        </Button>
      </header>

      <SuccessBanner />

      {error && (
        <p className="text-sm text-sev-high border border-line bg-surface rounded px-4 py-3 mb-4">
          {error}
        </p>
      )}

      <Panel title="All users" meta={users ? `${users.length}` : undefined}>
        {!users ? (
          <Empty>Loading...</Empty>
        ) : users.length === 0 ? (
          <Empty>No users yet.</Empty>
        ) : (
          users.map((u) => (
            <div key={u.id} className="flex items-center gap-3 px-4 py-2.5 border-b border-line last:border-0">
              <span className="flex-1 min-w-0 truncate text-sm text-ink font-medium">
                {u.username}
                {!u.is_active && <span className="ml-2 text-2xs text-ink-3 font-normal">(inactive)</span>}
              </span>
              <span className="hidden sm:block text-xs text-ink-3 w-40 truncate">{u.email ?? "---"}</span>
              <span className="text-xs text-ink-2 capitalize w-20">{u.role ?? "---"}</span>
              <Button variant="default" onClick={() => router.push(`/users/${u.id}/edit`)}>
                Edit
              </Button>
            </div>
          ))
        )}
      </Panel>
    </div>
  );
}

export default function UsersPage() {
  return (
    <Suspense>
      <UsersInner />
    </Suspense>
  );
}
