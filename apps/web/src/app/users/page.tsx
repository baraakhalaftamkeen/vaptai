"use client";

import { useCallback, useEffect, useState } from "react";
import { api, type PortalUser, type Role } from "@/lib/api";
import { Button, Empty, Panel, Row } from "@/components/ui";

const ROLES: Role[] = ["admin", "lead", "analyst", "reviewer", "viewer"];
const ROLE_HELP: Record<Role, string> = {
  admin: "Full control, incl. user management",
  lead: "Runs engagements, approves high-risk",
  analyst: "Creates & runs engagements",
  reviewer: "Approves actions, signs off reports",
  viewer: "Read-only",
};

const inputCls =
  "h-9 bg-bg border border-line rounded px-3 text-sm focus:border-accent-deep outline-none";

export default function UsersPage() {
  const [users, setUsers] = useState<PortalUser[] | null>(null);
  const [forbidden, setForbidden] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  // new-user form
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<Role>("analyst");

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

  async function create() {
    if (username.length < 3 || password.length < 8) {
      setError("Username needs 3+ characters and password 8+.");
      return;
    }
    setBusy("new");
    setError(null);
    try {
      await api.createUser({ username, password, role, email: email || undefined });
      setUsername(""); setPassword(""); setEmail(""); setRole("analyst");
      reload();
    } catch (e) {
      const msg = String(e);
      setError(msg.includes("409") ? "That username is already taken." : msg);
    } finally {
      setBusy(null);
    }
  }

  async function changeRole(u: PortalUser, newRole: Role) {
    setBusy(u.id);
    setError(null);
    try {
      await api.updateUser(u.id, { role: newRole });
      reload();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(null);
    }
  }

  async function toggleActive(u: PortalUser) {
    setBusy(u.id);
    setError(null);
    try {
      await api.updateUser(u.id, { is_active: !u.is_active });
      reload();
    } catch (e) {
      const msg = String(e);
      setError(msg.includes("400") ? "You can't deactivate your own account." : msg);
    } finally {
      setBusy(null);
    }
  }

  if (forbidden) {
    return (
      <div className="max-w-[760px]">
        <h1 className="text-2xl font-semibold leading-tight mb-2">Users</h1>
        <p className="text-sm text-ink-2">
          User management is available to administrators only.
        </p>
      </div>
    );
  }

  return (
    <div className="max-w-[900px]">
      <header className="mb-5">
        <h1 className="text-2xl font-semibold leading-tight">Users</h1>
        <p className="text-sm text-ink-2 mt-0.5">
          Add people to the portal and set what each can do. Passwords are stored hashed.
        </p>
      </header>

      {error && (
        <p className="text-sm text-sev-high border border-line bg-surface rounded px-4 py-3 mb-4">
          {error}
        </p>
      )}

      <Panel title="Add a user" className="mb-4">
        <div className="px-4 py-4 flex flex-wrap items-end gap-3">
          <label className="block">
            <span className="block text-xs text-ink-2 mb-1.5">Username</span>
            <input className={inputCls} value={username} onChange={(e) => setUsername(e.target.value)} />
          </label>
          <label className="block">
            <span className="block text-xs text-ink-2 mb-1.5">Password</span>
            <input type="password" className={inputCls} value={password}
                   onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" />
          </label>
          <label className="block">
            <span className="block text-xs text-ink-2 mb-1.5">Email (optional)</span>
            <input className={inputCls} value={email} onChange={(e) => setEmail(e.target.value)} />
          </label>
          <label className="block">
            <span className="block text-xs text-ink-2 mb-1.5">Role</span>
            <select className={inputCls} value={role} onChange={(e) => setRole(e.target.value as Role)}>
              {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
            </select>
          </label>
          <Button variant="primary" onClick={create} disabled={busy === "new"}>
            {busy === "new" ? "Adding…" : "Add user"}
          </Button>
        </div>
        <p className="text-2xs text-ink-3 px-4 pb-3">{ROLE_HELP[role]}</p>
      </Panel>

      <Panel title="All users" meta={users ? `${users.length}` : undefined}>
        {!users ? (
          <Empty>Loading…</Empty>
        ) : users.length === 0 ? (
          <Empty>No users yet.</Empty>
        ) : (
          users.map((u) => (
            <Row key={u.id}>
              <span className="flex-1 min-w-0 truncate">
                {u.username}
                {!u.is_active && <span className="ml-2 text-2xs text-ink-3">(inactive)</span>}
              </span>
              <span className="hidden sm:block text-xs text-ink-3 w-40 truncate">{u.email ?? "—"}</span>
              <select
                className={inputCls + " h-7 text-xs"}
                value={u.role ?? ""}
                disabled={busy === u.id}
                onChange={(e) => changeRole(u, e.target.value as Role)}
              >
                {!u.role && <option value="">no role</option>}
                {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
              </select>
              <Button
                variant={u.is_active ? "default" : "primary"}
                onClick={() => toggleActive(u)}
                disabled={busy === u.id}
                className="shrink-0"
              >
                {u.is_active ? "Deactivate" : "Activate"}
              </Button>
            </Row>
          ))
        )}
      </Panel>
    </div>
  );
}
