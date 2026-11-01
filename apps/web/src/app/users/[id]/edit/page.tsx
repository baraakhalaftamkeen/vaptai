"use client";

import { useCallback, useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { api, PERMISSION_LABELS, type PermissionKey, type PortalUser, type Role } from "@/lib/api";
import { Button, Panel } from "@/components/ui";

const ROLES: Role[] = ["admin", "lead", "analyst", "reviewer", "viewer"];
const ROLE_HELP: Record<Role, string> = {
  admin: "Full control, incl. user management",
  lead: "Runs engagements, approves high-risk",
  analyst: "Creates & runs engagements",
  reviewer: "Approves actions, signs off reports",
  viewer: "Read-only",
};

const PERM_KEYS = Object.keys(PERMISSION_LABELS) as PermissionKey[];

function Toggle({ on, onChange, disabled }: { on: boolean; onChange: (v: boolean) => void; disabled?: boolean }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={on}
      disabled={disabled}
      onClick={() => onChange(!on)}
      className={`relative inline-flex h-5 w-9 shrink-0 rounded-full transition-colors duration-200 focus:outline-none disabled:opacity-40 disabled:cursor-not-allowed ${on ? "bg-primary" : "bg-line-strong"}`}
    >
      <span
        className={`pointer-events-none inline-block h-4 w-4 rounded-full bg-white shadow transform transition-transform duration-200 mt-0.5 ${on ? "translate-x-[18px]" : "translate-x-0.5"}`}
      />
    </button>
  );
}

export default function EditUserPage() {
  const router = useRouter();
  const params = useParams<{ id: string }>();
  const userId = params.id;

  const [user, setUser] = useState<PortalUser | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const [role, setRole] = useState<Role>("analyst");
  const [isActive, setIsActive] = useState(true);
  const [permissions, setPermissions] = useState<Record<string, boolean>>({});

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const u = await api.getUser(userId);
      setUser(u);
      setRole((u.role as Role) ?? "analyst");
      setIsActive(u.is_active);
      setPermissions({ ...u.permissions });
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, [userId]);

  useEffect(() => { load(); }, [load]);

  function togglePermission(key: PermissionKey) {
    setPermissions((prev) => ({ ...prev, [key]: !prev[key] }));
  }

  async function save() {
    setBusy(true);
    setError(null);
    try {
      await api.updateUser(userId, { role, is_active: isActive, permissions });
      router.push("/users?success=updated");
    } catch (e) {
      const msg = String(e);
      setError(
        msg.includes("400")
          ? "You cannot deactivate or demote your own account."
          : msg,
      );
    } finally {
      setBusy(false);
    }
  }

  async function handleDelete() {
    if (!user) return;
    if (
      !window.confirm(
        `Delete user "${user.username}"?\n\n` +
          "This will permanently remove this account and revoke all sessions. This cannot be undone.",
      )
    )
      return;
    setBusy(true);
    setError(null);
    try {
      await api.deleteUser(userId);
      router.push("/users?success=deleted");
    } catch (e) {
      const msg = String(e);
      setError(
        msg.includes("400")
          ? "You cannot delete your own account."
          : msg,
      );
    } finally {
      setBusy(false);
    }
  }

  if (loading) {
    return (
      <div className="max-w-[600px]">
        <p className="text-sm text-ink-2">Loading user...</p>
      </div>
    );
  }

  if (!user) {
    return (
      <div className="max-w-[600px]">
        <p className="text-sm text-ink-2">User not found.</p>
        <Button variant="quiet" className="mt-3" onClick={() => router.push("/users")}>
          Back to users
        </Button>
      </div>
    );
  }

  return (
    <div className="max-w-[600px]">
      <header className="flex items-end justify-between gap-4 mb-5">
        <div>
          <h1 className="text-2xl font-semibold leading-tight">Edit user</h1>
          <p className="text-sm text-ink-2 mt-0.5">{user.username}</p>
        </div>
        <Button variant="quiet" onClick={() => router.push("/users")}>
          Cancel
        </Button>
      </header>

      {error && (
        <p className="text-sm text-sev-high border border-line bg-surface rounded px-4 py-3 mb-4">
          {error}
        </p>
      )}

      <Panel title="Account">
        <div className="px-4 py-4 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <span className="text-sm text-ink font-medium">{user.username}</span>
              <span className="block text-2xs text-ink-3">{user.email ?? "No email"}</span>
            </div>
            <div className="flex items-center gap-3">
              <span className="text-xs text-ink-2">{isActive ? "Active" : "Inactive"}</span>
              <Toggle on={isActive} onChange={setIsActive} />
            </div>
          </div>
        </div>
      </Panel>

      <Panel title="Role" className="mt-4">
        <div className="px-4 py-4">
          <div className="space-y-1.5">
            {ROLES.map((r) => (
              <label
                key={r}
                className={`flex items-center gap-3 px-3 py-2 rounded border cursor-pointer transition-colors ${
                  role === r
                    ? "border-primary bg-surface-2"
                    : "border-line hover:border-line-strong"
                }`}
              >
                <input
                  type="radio"
                  name="role"
                  value={r}
                  checked={role === r}
                  onChange={() => setRole(r)}
                  className="accent-accent-deep"
                />
                <div>
                  <span className="text-sm text-ink font-medium capitalize">{r}</span>
                  <span className="block text-2xs text-ink-3">{ROLE_HELP[r]}</span>
                </div>
              </label>
            ))}
          </div>
        </div>
      </Panel>

      <Panel title="Permissions" className="mt-4">
        <div className="px-4 py-4">
          <p className="text-2xs text-ink-3 mb-3">
            Override the role defaults. Changes apply immediately on save.
          </p>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-2">
            {PERM_KEYS.map((key) => (
              <div key={key} className="flex items-center justify-between gap-3 py-1.5">
                <span className="text-sm text-ink">{PERMISSION_LABELS[key]}</span>
                <Toggle
                  on={permissions[key] ?? false}
                  onChange={() => togglePermission(key)}
                />
              </div>
            ))}
          </div>
        </div>
      </Panel>

      <div className="flex items-center gap-2 mt-5">
        <Button variant="primary" onClick={save} disabled={busy}>
          {busy ? "Saving..." : "Save changes"}
        </Button>
        <Button variant="quiet" onClick={() => router.push("/users")}>
          Cancel
        </Button>
        <span className="flex-1" />
        <Button variant="danger" onClick={handleDelete} disabled={busy}>
          Delete user
        </Button>
      </div>
    </div>
  );
}
