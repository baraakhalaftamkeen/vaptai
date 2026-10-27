"""Versioned agent manifests (plan §5).

Each specialized agent runs under a manifest: a declared, versioned contract that
bounds what the agent may do. The manifest is enforced at the node boundary BEFORE
anything reaches the harness, so it is a second, agent-scoped gate in front of the
deterministic policy engine — defense in depth, not a replacement for it.

A manifest can only ever *narrow* what the platform allows:

  * it lists the exact tool IDs the agent may propose (a tool absent here is refused
    even if the tool registry would let that role use it);
  * it sets a risk ceiling — the highest PolicyClass the agent may even propose
    (so a recon agent can never propose a P2 intrusive action, approval or not);
  * it declares which EngagementState fields the agent may read and write
    (so a node cannot quietly mutate scope, approvals, or another agent's output);
  * it bounds iterations / wall-clock / tokens / cost, and says what to do on retry,
    what to redact, and when to escalate to a human.

Nothing here authorizes an action. The model still only proposes; the policy engine
still decides; a human still approves anything intrusive. The manifest decides what an
agent is even *allowed to ask for*.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from vapt_domain.enums import AgentRole, PolicyClass
from vapt_tools.catalog import tool_ids_for as _cat_ids  # declarative pentest-tool catalog

# Risk ordering so a manifest can cap the classes an agent may propose.
_CLASS_RANK: dict[PolicyClass, int] = {
    PolicyClass.P0_PASSIVE: 0,
    PolicyClass.P1_LOW_IMPACT: 1,
    PolicyClass.P2_INTRUSIVE: 2,
    PolicyClass.P3_EXCLUDED: 3,
}


class ManifestError(RuntimeError):
    """Raised when an agent tries to step outside its manifest. Never a policy decision —
    this is a hard contract violation (a bug or a tampered plan), recorded and refused."""


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 1          # total attempts for a failed tool/model step
    backoff_seconds: float = 0.0   # advisory; the worker, not the node, sleeps


@dataclass(frozen=True)
class AgentManifest:
    agent_id: str                       # stable id, e.g. "recon@1"
    role: AgentRole
    prompt_version: str                 # which system-prompt revision this agent uses
    description: str

    # Capability surface (all *narrowing* — never widens registry/policy).
    allowed_tool_ids: tuple[str, ...] = ()
    risk_ceiling: PolicyClass = PolicyClass.P0_PASSIVE

    # State-field permissions on EngagementState.
    state_reads: tuple[str, ...] = ()
    state_writes: tuple[str, ...] = ()

    # Which model profile (if any) this agent may call through the gateway.
    model_profile: str | None = None

    # Budgets. Enforced by ManifestGuard; a breach escalates, never silently continues.
    max_iterations: int = 1
    max_wall_seconds: int = 300
    max_tokens: int = 0                 # 0 = agent makes no model calls
    max_cost_usd: float = 0.0

    retry: RetryPolicy = field(default_factory=RetryPolicy)

    # Redaction rules: keys whose values must be stripped from anything this agent
    # emits into state, logs, or model prompts (secrets, creds, raw captures).
    redaction_keys: tuple[str, ...] = ("api_key", "authorization", "token", "password", "secret")

    # Conditions (free-form, matched by the node) that force a human escalation.
    escalation_conditions: tuple[str, ...] = ()

    def may_use(self, tool_id: str) -> bool:
        return tool_id in self.allowed_tool_ids

    def within_risk_ceiling(self, policy_class: PolicyClass) -> bool:
        return _CLASS_RANK[policy_class] <= _CLASS_RANK[self.risk_ceiling]

    def may_write(self, field_name: str) -> bool:
        return field_name in self.state_writes


# --------------------------------------------------------------------------- #
# The manifests. Versioned: bump the id + prompt_version when the contract changes.
# These are deliberately tight for the internal beta.
# --------------------------------------------------------------------------- #
PLANNING = AgentManifest(
    agent_id="planning@1",
    role=AgentRole.PLANNING,
    prompt_version="plan-v1",
    description="Proposes an ordered, bounded scan plan from scope + the available tools.",
    allowed_tool_ids=(),                # planning proposes a plan; it runs no tools itself
    risk_ceiling=PolicyClass.P1_LOW_IMPACT,  # it may propose up to P1; P2 must be asked for explicitly downstream
    state_reads=("scope_ref", "testing_mode", "target_type", "budget_remaining"),
    state_writes=("plan", "phase", "log", "coverage_gaps"),
    model_profile="planning",
    max_iterations=1,
    max_wall_seconds=60,
    max_tokens=4096,
    max_cost_usd=0.05,
    escalation_conditions=("model_unavailable", "empty_plan"),
)

RECON = AgentManifest(
    agent_id="recon@1",
    role=AgentRole.RECON,
    prompt_version="recon-v1",
    description="Establishes that an approved asset is reachable (passive, bounded).",
    allowed_tool_ids=("dns_resolve", "http_probe", "nmap_service_scan",
                      *_cat_ids(AgentRole.RECON)),
    risk_ceiling=PolicyClass.P1_LOW_IMPACT,
    state_reads=("scope_ref", "testing_mode"),
    state_writes=("proposed_asset_refs", "approved_asset_refs", "phase", "log", "evidence_refs"),
    model_profile=None,
    max_iterations=4,
    max_wall_seconds=600,
)

SCAN = AgentManifest(
    agent_id="scan@1",
    role=AgentRole.SCAN,
    prompt_version="scan-v1",
    description="Runs the planned scan adapters through the harness; emits candidate findings.",
    # NOTE: burp_request / poc_screenshot are intentionally NOT here. Those are PoC tools
    # the ATTACK agent uses, and every PoC must pass a human gate. If the scan agent could
    # use burp_request, the planner could schedule it as an auto-allowed (signed P1) scan
    # step and issue a request with no approval — defeating the gate. Keep PoC tools to
    # the ATTACK manifest only.
    allowed_tool_ids=(
        "nmap_service_scan", "http_probe", "nuclei_safe", "nuclei_intrusive", "nuclei_dast",
        "zap_baseline", "tls_check", "nessus_import", "tenable_scan", "host_scripts",
        # Non-destructive detection variants for CONFIRMATION on discovered param URLs. The
        # catalog `sstimap` is ATTACK-only (that invariant is tested); this is a separate id.
        "ssti_detect",
        # SQLi Tier-2 confirmer. Bounded sqlmap wrapper — --technique=BE, --level/--risk 1,
        # NEVER --os-shell/--os-cmd/--dump/--eval. Promotes nondeterministic wapiti SQLi
        # candidates to proof-confirmed on hit; stays silent (no finding) on miss.
        "sqli_detect",
        # Bounded HTTP primitive the LLM-webvuln planner can propose when it wants to
        # chase a specific URL (JS file, API endpoint, admin route) that no catalog
        # scanner directly covers. Hardcoded safe curl flags, whitelisted headers,
        # 1MB body cap, 10s wall-clock. The LLM can only pick the URL + method +
        # body + headers — the argv shape is fixed.
        "vapt_http_fetch",
        # Stored-XSS probe — POSTs a unique canary payload to a submit endpoint,
        # GETs the view URL, confirms persistence by matching the canary in the
        # rendered body. Closes dalfox's POST-only blind spot. Argv-only shim.
        "stored_xss_probe",
        # CSP posture evaluator — fetches one URL, parses Content-Security-Policy,
        # flags unsafe-inline/eval, wildcards, missing strict-dynamic, missing
        # Trusted Types, missing frame-ancestors. P1 (no payloads).
        "csp_check",
        # Deterministic in-band probe for open-redirect / LFI / SSRF-local / sensitive-
        # content / XXE on a specific URL — payloads are bounded, in-band proof only.
        "web_param_probe",
        # XSS fuzzer (reflected + DOM via headless Chrome). Covers the DOM-XSS gap our
        # server-side normalizers can't see — the sink lives in JS and only a headless
        # browser can observe the payload fire.
        "dalfox",
        # IDOR probe — two authenticated sessions, numeric-ID path rewriting, cross-
        # tenant diff detection. Only fires when the operator supplied TWO credential
        # sets at run creation (lives in Redis under :A and :B suffixes).
        "idor_probe",
        # DOM-XSS probe — static JS taint analysis. Catches fragment (location.hash)
        # and other DOM sinks that never reach the server and that dalfox's param
        # mining misses. P1 (read-only: fetches pages + scripts, no payloads).
        "dom_xss_probe",
        # Recon fetch — bounded authenticated GET/POST returning structured JSON
        # (status, forms, hrefs, allow, content_type). The LLM-driven recon loop
        # (Stage 3) uses this to explore the authenticated surface and derive
        # targeted probes from real form shapes, instead of guessing. P1.
        "recon_fetch",
        *_cat_ids(AgentRole.SCAN),
    ),
    risk_ceiling=PolicyClass.P2_INTRUSIVE,   # may PROPOSE intrusive; policy + human still gate it
    state_reads=("scope_ref", "plan", "testing_mode"),
    state_writes=("candidate_finding_refs", "pending_action_refs", "approval_refs",
                  "phase", "log", "coverage_gaps"),
    model_profile=None,
    # The probe phase runs MANY deterministic sub-steps under one SCAN guard: per-port httpx,
    # host scripts, Windows vuln checks, service→CVE, the service-driven tool router (up to ~16
    # tools across several web endpoints) AND per-endpoint parameter discovery (arjun). 16 was
    # sized before the router + param sweep existed and silently starved the later steps (arjun
    # never ran). Bounded generously; the work is deterministic, not an LLM loop.
    #
    # Raised 64 → 160 (2026-10-26): the dynamic LLM webvuln pipeline (primary +
    # reactive + recon-agent) appends up to ~15 extra items to the plan AFTER
    # the deterministic tiers finish; on an app whose deterministic plan is
    # ~110 items the LLM items were silently starved at iter 64. 160 leaves
    # comfortable headroom; max_wall_seconds=3600 is still the real wall-clock
    # ceiling, so overshoot can't actually waste operator time.
    max_iterations=160,
    max_wall_seconds=3600,
    escalation_conditions=("approval_required",),
)

VALIDATE = AgentManifest(
    agent_id="validate@1",
    role=AgentRole.VALIDATE,
    prompt_version="validate-v1",
    description="Independently re-checks each candidate; only this step marks confirmed.",
    allowed_tool_ids=("http_probe", "nmap_service_scan", "nuclei_safe", "tls_check",
                      *_cat_ids(AgentRole.VALIDATE)),
    risk_ceiling=PolicyClass.P1_LOW_IMPACT,
    state_reads=("scope_ref", "candidate_finding_refs"),
    state_writes=("validated_finding_refs", "phase", "log"),
    model_profile="validation",
    max_iterations=32,
    max_wall_seconds=1800,
    max_tokens=2048,
    max_cost_usd=0.05,
)

# Declared now so the risk ceilings exist from day one; wired in later weeks.
ATTACK = AgentManifest(
    agent_id="attack@1",
    role=AgentRole.ATTACK,
    prompt_version="attack-v1",
    description="Runs only narrow, pre-approved PoC playbooks. Every action is P2+ and human-gated.",
    allowed_tool_ids=("burp_request", "poc_screenshot", *_cat_ids(AgentRole.ATTACK)),
    risk_ceiling=PolicyClass.P2_INTRUSIVE,
    state_reads=("scope_ref", "validated_finding_refs"),
    state_writes=("evidence_refs", "phase", "log"),
    model_profile=None,
    max_iterations=4,
    max_wall_seconds=900,
    escalation_conditions=("approval_required", "always_escalate"),
)

REMEDIATION = AgentManifest(
    agent_id="remediation@1",
    role=AgentRole.REMEDIATION,
    prompt_version="remediation-v1",
    description="Drafts remediation guidance from confirmed findings. Runs no tools.",
    allowed_tool_ids=(),
    risk_ceiling=PolicyClass.P0_PASSIVE,
    state_reads=("validated_finding_refs",),
    state_writes=("phase", "log"),
    model_profile="reporting",
    max_iterations=1,
    max_wall_seconds=300,
    max_tokens=4096,
    max_cost_usd=0.10,
)

REPORTING = AgentManifest(
    agent_id="reporting@1",
    role=AgentRole.REPORTING,
    prompt_version="reporting-v1",
    description="Assembles the evidence-linked report draft. Runs no tools.",
    allowed_tool_ids=(),
    risk_ceiling=PolicyClass.P0_PASSIVE,
    state_reads=("validated_finding_refs", "evidence_refs"),
    state_writes=("report_ref", "phase", "log"),
    model_profile="reporting",
    max_iterations=1,
    max_wall_seconds=600,
    max_tokens=8192,
    max_cost_usd=0.20,
)

MANIFESTS: dict[AgentRole, AgentManifest] = {
    AgentRole.PLANNING: PLANNING,
    AgentRole.RECON: RECON,
    AgentRole.SCAN: SCAN,
    AgentRole.VALIDATE: VALIDATE,
    AgentRole.ATTACK: ATTACK,
    AgentRole.REMEDIATION: REMEDIATION,
    AgentRole.REPORTING: REPORTING,
}


def manifest_for(role: AgentRole) -> AgentManifest:
    try:
        return MANIFESTS[role]
    except KeyError as exc:  # pragma: no cover - every role is declared above
        raise ManifestError(f"no manifest declared for agent role {role!r}") from exc


def redact(manifest: AgentManifest, data: dict) -> dict:
    """Return a shallow copy with manifest-listed secret-bearing keys masked.

    Matching is case-insensitive and substring-based, so 'X-Api-Key' and
    'authorization_header' are both caught. Used before anything an agent produced
    is written to state, a log line, or a model prompt.
    """
    out: dict = {}
    lowered = tuple(k.lower() for k in manifest.redaction_keys)
    for k, v in data.items():
        if any(marker in str(k).lower() for marker in lowered):
            out[k] = "***redacted***"
        else:
            out[k] = v
    return out


class ManifestGuard:
    """Tracks an agent's per-run budget. The node calls step() before each unit of work
    and charge_tokens()/charge_cost() after a model call. A breach raises ManifestError,
    which the node turns into a recorded escalation rather than silently continuing."""

    def __init__(self, manifest: AgentManifest):
        self.manifest = manifest
        self.iterations = 0
        self.tokens = 0
        self.cost_usd = 0.0

    def step(self) -> None:
        self.iterations += 1
        if self.iterations > self.manifest.max_iterations:
            raise ManifestError(
                f"{self.manifest.agent_id} exceeded max_iterations={self.manifest.max_iterations}"
            )

    def charge_tokens(self, n: int) -> None:
        self.tokens += max(0, int(n))
        if self.manifest.max_tokens and self.tokens > self.manifest.max_tokens:
            raise ManifestError(
                f"{self.manifest.agent_id} exceeded max_tokens={self.manifest.max_tokens}"
            )

    def charge_cost(self, usd: float) -> None:
        self.cost_usd += max(0.0, float(usd))
        if self.manifest.max_cost_usd and self.cost_usd > self.manifest.max_cost_usd:
            raise ManifestError(
                f"{self.manifest.agent_id} exceeded max_cost_usd={self.manifest.max_cost_usd}"
            )
