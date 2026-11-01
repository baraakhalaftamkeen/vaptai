"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { api, type Role } from "@/lib/api";
import { Button, Panel } from "@/components/ui";

const ROLES: Role[] = ["admin", "lead", "analyst", "reviewer", "viewer"];
const ROLE_HELP: Record<Role, string> = {
  admin: "Full control, incl. user management",
  lead: "Runs engagements, approves high-risk",
  analyst: "Creates & runs engagements",
  reviewer: "Approves actions, signs off reports",
  viewer: "Read-only",
};

const inputCls =
  "w-full h-9 bg-input-bg border border-line rounded px-3 text-sm text-ink focus:border-primary outline-none";

export default function NewUserPage() {
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<Role>("analyst");

  async function submit() {
    if (username.length < 3 || password.length < 8) {
      setError("Username needs 3+ characters and password 8+.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await api.createUser({ username, password, role, email: email || undefined });
      router.push("/users?success=created");
    } catch (e) {
      const msg = String(e);
      setError(msg.includes("409") ? "That username is already taken." : msg);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="max-w-[600px]">
      <header className="flex items-end justify-between gap-4 mb-5">
        <div>
          <h1 className="text-2xl font-semibold leading-tight">Add user</h1>
          <p className="text-sm text-ink-2 mt-0.5">
            Create a new portal account. Passwords are stored hashed.
          </p>
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

      <Panel title="User details">
        <div className="px-4 py-4 space-y-4">
          <label className="block">
            <span className="block text-xs text-ink-2 mb-1.5">Username</span>
            <input
              className={inputCls}
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="jsmith"
              autoFocus
            />
          </label>

          <label className="block">
            <span className="block text-xs text-ink-2 mb-1.5">Password</span>
            <input
              type="password"
              className={inputCls}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="new-password"
              placeholder="Minimum 8 characters"
            />
          </label>

          <label className="block">
            <span className="block text-xs text-ink-2 mb-1.5">
              Email <span className="text-ink-3">(optional)</span>
            </span>
            <input
              className={inputCls}
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="user@company.com"
            />
          </label>

          <div>
            <span className="block text-xs text-ink-2 mb-2">Role</span>
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

          <div className="flex items-center gap-2 pt-1">
            <Button variant="primary" onClick={submit} disabled={busy}>
              {busy ? "Adding..." : "Add user"}
            </Button>
            <Button variant="quiet" onClick={() => router.push("/users")}>
              Cancel
            </Button>
          </div>
        </div>
      </Panel>
    </div>
  );
}
