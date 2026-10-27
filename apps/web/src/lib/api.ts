// Thin typed API client. Requests are same-origin (/api/*) and rely on the
// HttpOnly session cookie, so no tokens are ever stored in the browser.

export type Role = "admin" | "lead" | "analyst" | "reviewer" | "viewer";

export interface Me {
  id: string;
  username: string;
  roles: Record<string, Role>;
}

export interface Engagement {
  id: string;
  project_id: string;
  name: string;
  testing_mode: "black_box" | "gray_box" | "white_box";
  target_type: "web" | "network" | "source";
  scope_version: number;
  created_at: string;
}

export interface Run {
  id: string;
  engagement_id: string;
  status: string;
  phase: string | null;
  retest_of: string | null;
  auto_approve: boolean;
  created_at: string;
  updated_at: string;
}

export interface Schedule {
  id: string;
  engagement_id: string;
  interval_minutes: number | null;
  enabled: boolean;
  cron: string;
  next_fire_at: string | null;
  last_fired_at: string | null;
  created_at: string;
}

export interface RetestComparison {
  current_run_id: string;
  prior_run_id: string;
  counts: { fixed: number; still_open: number; new: number };
  fixed: { title: string; severity: string }[];
  still_open: { title: string; severity: string }[];
  new: { title: string; severity: string }[];
}

export interface Approval {
  id: string;
  run_id: string;
  action_digest: string;
  policy_class: string;
  state: string;
  expires_at: string | null;
  // What the reviewer is actually approving (derived server-side).
  tool_id?: string | null;
  target?: string | null;
  summary?: string | null;
  detail?: string | null;
  reason?: string | null;
  // Authenticated scanning: set when the action is a web scan that discovered a login form.
  // The UI then offers an optional login dialog; credentials go to the web-credentials
  // endpoint (the ephemeral slot), never onto the approval itself.
  needs_web_credentials?: boolean;
  login_url?: string | null;
}

export interface RunEvent {
  seq: number;
  kind: string;
  payload: Record<string, unknown>;
  created_at: string;
}

export type Decision = "approve" | "approve_batch" | "reject" | "request_changes";

export interface Observation {
  id: string;
  source_tool: string;
  detail: Record<string, unknown>;
  created_at: string;
}

export interface Finding {
  id: string;
  run_id: string;
  title: string;
  status: string;
  severity: string;
  description: string;
  observations: Observation[];
  created_at: string;
}

export interface PortalUser {
  id: string;
  username: string;
  email: string | null;
  is_active: boolean;
  role: Role | null;
  created_at: string;
}

export interface Playbook {
  id: string;
  title: string;
  description: string;
  tool_id: string;
}

export interface CveFeedItem {
  id: string;
  score: number;
  severity: string;
  published: string;
  description: string;
}

export interface CveDetail {
  cve_id: string;
  cvss: number | null;
  vector: string;
  severity: string;
  description: string;
  references: string[];
  exploited: boolean;
  exploit_basis: string;
}

export interface Report {
  id: string;
  run_id: string;
  fmt: string;
  status: "draft" | "final";
  title: string;
  summary: string;
  remediation: string;
  stats: { counts?: Record<string, number>; coverage_gaps?: string[] };
  signed_off_by: string | null;
  created_at: string;
}

export interface SourceBundle {
  id: string;
  engagement_id: string;
  filename: string;
  sha256: string;
  byte_length: number;
  file_count: number;
  created_at: string;
}

export interface Dashboard {
  run_counts: Record<string, number>;
  severity_counts: Record<string, number>;
  finding_status_counts: Record<string, number>;
  action_class_counts: Record<string, number>;
  pending_approvals: {
    id: string;
    run_id: string;
    policy_class: string;
    action_digest: string;
    tool_id: string | null;
    target_ref: string | null;
  }[];
  active_runs: {
    id: string;
    engagement_name: string;
    status: string;
    phase: string | null;
    updated_at: string;
  }[];
  recent_findings: {
    id: string;
    run_id: string;
    title: string;
    severity: string;
    status: string;
  }[];
  totals: Record<string, number>;
}

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...init,
    headers: { "Content-Type": "application/json", ...(init?.headers || {}) },
    credentials: "include",
  });
  // Session expired / revoked while the UI was still mounted: a background poller
  // (approvals, me, runs, …) 401s. The API also sends a Max-Age=0 Set-Cookie that clears
  // the stale cookie, but we still redirect proactively so the user doesn't see a 401
  // loop in dev tools. Login endpoints are exempt — their own 401 is "wrong password",
  // not a session problem, and must be surfaced to the login form.
  if (
    res.status === 401 &&
    typeof window !== "undefined" &&
    !window.location.pathname.startsWith("/login") &&
    !path.startsWith("/api/v2/auth/session")
  ) {
    const next = encodeURIComponent(window.location.pathname + window.location.search);
    window.location.href = `/login?next=${next}`;
    // Throw anyway so pending callers unwind cleanly while the navigation starts.
    throw new Error("401: session expired");
  }
  if (!res.ok) {
    const detail = await res.text();
    throw new Error(`${res.status}: ${detail}`);
  }
  return (res.status === 204 ? undefined : await res.json()) as T;
}

export const api = {
  login: (username: string, password: string) =>
    req<{ status: string }>("/api/v2/auth/session", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    }),
  logout: () => req<{ status: string }>("/api/v2/auth/session", { method: "DELETE" }),
  me: () => req<Me>("/api/v2/auth/me"),
  listUsers: () => req<PortalUser[]>("/api/v2/users"),
  createUser: (body: { username: string; password: string; role: Role; email?: string }) =>
    req<PortalUser>("/api/v2/users", { method: "POST", body: JSON.stringify(body) }),
  updateUser: (id: string, body: { role?: Role; is_active?: boolean }) =>
    req<PortalUser>(`/api/v2/users/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
  listEngagements: () => req<Engagement[]>("/api/v2/engagements"),
  getEngagement: (id: string) => req<Engagement>(`/api/v2/engagements/${id}`),
  createEngagement: (body: unknown) =>
    req<Engagement>("/api/v2/engagements", { method: "POST", body: JSON.stringify(body) }),
  listRuns: () => req<Run[]>("/api/v2/runs"),
  getRun: (runId: string) => req<Run>(`/api/v2/runs/${runId}`),
  createRun: (
    engagement_id: string,
    auto_approve = false,
    web_username?: string,
    web_password?: string,
    web_username_b?: string,  // optional 2nd account for IDOR probe
    web_password_b?: string,
    // Optional 3rd account enables the admin + 2-user IDOR model. When present
    // (requires _b too), idor_probe pairs B+C — two normal users with the same
    // role — instead of A+B (admin+user), which eliminates false positives on
    // pages the normal user is simply forbidden from.
    web_username_c?: string,
    web_password_c?: string,
  ) =>
    req<Run>("/api/v2/runs", {
      method: "POST",
      body: JSON.stringify({
        engagement_id,
        auto_approve,
        // Only send primary creds if BOTH are present; backend treats empty/null as unauth.
        ...(web_username && web_password
          ? { web_username, web_password }
          : {}),
        // 2nd account is only accepted if primary is also set; backend enforces this too.
        ...(web_username && web_password && web_username_b && web_password_b
          ? { web_username_b, web_password_b }
          : {}),
        // 3rd account requires both A and B to be set.
        ...(web_username && web_password
            && web_username_b && web_password_b
            && web_username_c && web_password_c
          ? { web_username_c, web_password_c }
          : {}),
      }),
    }),
  pauseRun: (runId: string) => req<Run>(`/api/v2/runs/${runId}/pause`, { method: "POST" }),
  cancelRun: (runId: string) => req<Run>(`/api/v2/runs/${runId}/cancel`, { method: "POST" }),
  runEvents: (runId: string, afterSeq = 0) =>
    req<RunEvent[]>(`/api/v2/runs/${runId}/events?after_seq=${afterSeq}`),
  listApprovals: (runId?: string) =>
    req<Approval[]>(`/api/v2/approvals${runId ? `?run_id=${runId}` : ""}`),
  decideApproval: (approvalId: string, decision: Decision) =>
    req<Approval>(`/api/v2/approvals/${approvalId}/decision`, {
      method: "POST",
      body: JSON.stringify({ decision }),
    }),
  // Attach web-login credentials to an authenticated-scan approval. They go only to the
  // server's ephemeral slot (never persisted); call this before decideApproval("approve").
  // Up to THREE accounts: primary (admin recommended), B (first normal user),
  // C (second normal user). B+C present → idor_probe uses the two-user pair
  // and skips the admin-vs-user comparison that produces false positives.
  submitWebCredentials: (
    approvalId: string,
    username: string,
    password: string,
    username_b?: string,
    password_b?: string,
    username_c?: string,
    password_c?: string,
  ) =>
    req<void>(`/api/v2/approvals/${approvalId}/web-credentials`, {
      method: "POST",
      body: JSON.stringify({
        username,
        password,
        ...(username_b && password_b ? { username_b, password_b } : {}),
        ...(username_b && password_b && username_c && password_c
          ? { username_c, password_c }
          : {}),
      }),
    }),
  runFindings: (runId: string) => req<Finding[]>(`/api/v2/runs/${runId}/findings`),
  getFinding: (findingId: string) => req<Finding>(`/api/v2/findings/${findingId}`),
  dashboard: () => req<Dashboard>("/api/v2/dashboard"),
  getReport: (runId: string) => req<Report>(`/api/v2/runs/${runId}/report`),
  regenerateReport: (runId: string) =>
    req<Report>(`/api/v2/runs/${runId}/report/regenerate`, { method: "POST" }),
  signoffReport: (runId: string) =>
    req<Report>(`/api/v2/runs/${runId}/report/signoff`, { method: "POST" }),
  reportDownloadUrl: (runId: string, format: "html" | "pdf" = "html") =>
    `/api/v2/runs/${runId}/report/download?format=${format}`,
  listSchedules: (engagementId: string) =>
    req<Schedule[]>(`/api/v2/engagements/${engagementId}/schedules`),
  createSchedule: (engagementId: string, interval_minutes: number) =>
    req<Schedule>(`/api/v2/engagements/${engagementId}/schedules`, {
      method: "POST",
      body: JSON.stringify({ interval_minutes }),
    }),
  deleteSchedule: (engagementId: string, scheduleId: string) =>
    req<void>(`/api/v2/engagements/${engagementId}/schedules/${scheduleId}`, { method: "DELETE" }),
  retestRun: (runId: string) => req<Run>(`/api/v2/runs/${runId}/retest`, { method: "POST" }),
  getRetest: (runId: string) => req<RetestComparison>(`/api/v2/runs/${runId}/retest`),
  listPlaybooks: () => req<Playbook[]>("/api/v2/playbooks"),
  cveFeed: (opts?: { days?: number; minScore?: number; keyword?: string; limit?: number }) => {
    const q = new URLSearchParams();
    if (opts?.days) q.set("days", String(opts.days));
    if (opts?.minScore != null) q.set("min_score", String(opts.minScore));
    if (opts?.keyword) q.set("keyword", opts.keyword);
    if (opts?.limit) q.set("limit", String(opts.limit));
    const qs = q.toString();
    return req<CveFeedItem[]>(`/api/v2/cve/feed${qs ? `?${qs}` : ""}`);
  },
  cveLookup: (cveId: string) => req<CveDetail>(`/api/v2/cve/${encodeURIComponent(cveId)}`),
  listSource: (engagementId: string) =>
    req<SourceBundle[]>(`/api/v2/engagements/${engagementId}/source`),
  // Multipart upload: don't set Content-Type — the browser adds the boundary.
  uploadSource: async (engagementId: string, file: File): Promise<SourceBundle> => {
    const fd = new FormData();
    fd.append("file", file);
    const res = await fetch(`/api/v2/engagements/${engagementId}/source`, {
      method: "POST",
      body: fd,
      credentials: "include",
    });
    if (!res.ok) throw new Error(`${res.status}: ${await res.text()}`);
    return (await res.json()) as SourceBundle;
  },
};
