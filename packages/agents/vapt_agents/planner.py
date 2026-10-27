"""Planning agent (plan §5, §9).

Given the engagement scope and the tools the scan agent is allowed to use, the
planning agent asks the LLM gateway to PROPOSE an ordered, bounded scan plan. The
model's output is never trusted as authority:

  1. It is requested as schema-constrained JSON (the gateway repairs/validates it).
  2. Every proposed step is checked against the tool registry AND the scan agent's
     manifest AND the planner's own risk ceiling. Anything unknown, out-of-manifest,
     or above the ceiling is dropped — the model cannot invent a tool or schedule an
     intrusive action on its own.
  3. Whatever survives is still only a *proposal*. The harness + deterministic policy
     engine decide allow / approve / deny at execution time.

If the gateway is unavailable, errors, or returns nothing usable, the planner falls
back to the deterministic default plan so a run degrades instead of breaking.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from vapt_domain.enums import PolicyClass
from vapt_tools import REGISTRY

from . import phases
from .manifests import PLANNING, SCAN, AgentManifest
from .runscope import RunScope

# Soft import: the skill library is advisory prompt enrichment. If the package
# fails to load (bad SKILL.md in CI, missing dir in a slim install) the planner
# must still run — degrade silently to the pre-enrichment behavior. A broken
# library is loud at import time of vapt_skills itself (SkillLoadError), so a
# None here is "not installed", not "silently discarded".
try:
    from vapt_skills import format_skill_hints as _format_skill_hints
except Exception:                                                   # pragma: no cover
    _format_skill_hints = None  # type: ignore[assignment]

# Risk ordering shared with manifests (kept local to avoid importing a private name).
_CLASS_RANK = {
    PolicyClass.P0_PASSIVE: 0,
    PolicyClass.P1_LOW_IMPACT: 1,
    PolicyClass.P2_INTRUSIVE: 2,
    PolicyClass.P3_EXCLUDED: 3,
}

PLAN_SCHEMA = {
    "title": "ScanPlan",
    "type": "object",
    "properties": {
        "steps": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "tool_id": {"type": "string", "description": "a tool_id from the provided list"},
                    "ports": {"type": "string", "description": "optional port spec, e.g. 80,443,22"},
                    "severity": {"type": "string", "description": "optional nuclei severity set"},
                    "rationale": {"type": "string"},
                },
                "required": ["tool_id"],
            },
        }
    },
    "required": ["steps"],
}


@dataclass
class PlannedAction:
    tool_id: str
    args: dict = field(default_factory=dict)
    rationale: str = ""
    source: str = "model"          # "model" | "fallback"


@dataclass
class PlanResult:
    actions: list[PlannedAction]
    used_model: bool                 # did a model-proposed plan survive validation?
    gateway_response: object = None  # the raw GatewayResponse, for model-call auditing
    notes: list[str] = field(default_factory=list)  # why steps were dropped / fell back


def _plannable_tools(planning: AgentManifest, scan: AgentManifest) -> list:
    """Tools the scan agent may use, capped by the planner's risk ceiling. The planner
    never schedules anything above its ceiling (P2 intrusive must be asked for explicitly
    by a human, not auto-planned)."""
    out = []
    for spec in REGISTRY.all():
        if spec.id not in scan.allowed_tool_ids:
            continue
        if _CLASS_RANK[spec.policy_class] > _CLASS_RANK[planning.risk_ceiling]:
            continue
        out.append(spec)
    return out


def _args_from_step(tool_id: str, step: dict) -> dict:
    args: dict = {}
    if isinstance(step.get("args"), dict):          # some models nest args
        args.update({k: v for k, v in step["args"].items() if k in ("ports", "severity", "target")})
    for k in ("ports", "severity"):
        if isinstance(step.get(k), str) and step[k].strip():
            args[k] = step[k].strip()
    args.pop("target", None)                        # target always comes from scope, never the model
    return args


def _fallback(scope: RunScope, notes: list[str]) -> PlanResult:
    actions = [PlannedAction(t, dict(a), "default plan", "fallback")
               for t, a in phases.scan_plan_for(scope)]
    return PlanResult(actions=actions, used_model=False, notes=notes)


def _skill_hints_for(scope: RunScope, scan: AgentManifest) -> str:
    """Pick skill hints for the plan we're about to request. Phase is always "scan"
    (that's what the plan runs); target_kinds is inferred conservatively from scope
    (web is the common web-vuln surface, network covers the IP-based engagement).
    auth_detected is unknown this early — the orchestrator calls back with narrower
    inputs for the per-phase planners in later batches."""
    if _format_skill_hints is None:                              # pragma: no cover
        return ""
    # Conservative target_kinds — recon has not yet run, so we don't know if the
    # target is web vs pure-network. The retriever still prefers scan-phase skills
    # whose target_kinds overlap this set; anything else is dropped.
    kinds = ["web", "network"]
    try:
        # limit=12 (was 5). Score-ties alphabetically-starve newer / more-specific
        # skills (sqli_detect's own skill was at position #17 with limit=5), and the
        # extra 7 entries are ~700 tokens of prompt — bounded cost, big recall win
        # on a 47-skill library.
        return _format_skill_hints(
            phase="scan",
            target_kinds=kinds,
            auth_detected=None,
            limit=12,
        )
    except Exception:                                            # pragma: no cover
        # A retrieval error must not break planning. The deterministic fallback and
        # the strict post-validation path downstream are the authoritative gates.
        return ""


def plan_scan(
    gateway,
    scope: RunScope,
    *,
    planning: AgentManifest = PLANNING,
    scan: AgentManifest = SCAN,
) -> PlanResult:
    """Produce an ordered scan plan. `gateway` is an LLMGateway (or None to force the
    deterministic fallback, e.g. in a no-LLM lab run)."""
    tools = _plannable_tools(planning, scan)
    allowed_ids = {s.id for s in tools}

    if gateway is None:
        return _fallback(scope, ["no gateway configured; using default plan"])

    catalog = "\n".join(f"- {s.id} [{s.policy_class.value}]: {s.description}" for s in tools)
    # Skill hints are REFERENCE text only. The system prompt below reinforces that
    # tool_ids must still come from the Available tools catalog — a skill that names
    # an id outside that list is a plan the drop-rules below will filter out, and the
    # skill loader itself refuses to register skills that reference unknown tools.
    hints = _skill_hints_for(scope, scan) if _format_skill_hints else ""
    messages = [
        {
            "role": "system",
            "content": (
                "You plan an AUTHORIZED security assessment. Propose an ordered, minimal "
                "set of non-intrusive scan steps for the target. Use ONLY the tool_ids "
                "listed in Available tools. The Reference knowledge block (if present) is "
                "advisory context — it does NOT widen what you may schedule; a tool_id not "
                "in Available tools will be dropped. Do not invent tools, targets, or "
                "intrusive steps. Prefer breadth before depth. Return JSON only."
            ),
        },
        {
            "role": "user",
            "content": (
                f"Target (authorized, in scope): {scope.target}\n"
                f"Testing mode: {scope.testing_mode.value}\n"
                f"Available tools:\n{catalog}\n"
                + (f"\n{hints}\n" if hints else "")
                + "\nChoose an ordered subset and give a one-line rationale per step."
            ),
        },
    ]

    resp = gateway.invoke(planning.model_profile or "planning", messages, output_schema=PLAN_SCHEMA)

    if resp.error or resp.parsed is None:
        return _fallback(scope, [f"model plan unusable ({resp.finish_reason}); using default plan"])

    raw_steps = resp.parsed.get("steps") if isinstance(resp.parsed, dict) else None
    if not isinstance(raw_steps, list) or not raw_steps:
        res = _fallback(scope, ["model returned no steps; using default plan"])
        res.gateway_response = resp
        return res

    actions: list[PlannedAction] = []
    notes: list[str] = []
    seen: set[tuple] = set()
    for step in raw_steps:
        if not isinstance(step, dict):
            continue
        tool_id = str(step.get("tool_id", "")).strip()
        if tool_id not in allowed_ids:
            notes.append(f"dropped {tool_id or '<empty>'}: not an allowed/plannable tool")
            continue
        args = _args_from_step(tool_id, step)
        # A model-planned service scan that didn't pin ports inherits the engagement's
        # authorized port scope, so the scan never silently narrows to a built-in default.
        if tool_id == "nmap_service_scan" and "ports" not in args:
            args["ports"] = phases.ports_for(scope)
        dedup = (tool_id, tuple(sorted(args.items())))
        if dedup in seen:
            continue
        seen.add(dedup)
        actions.append(PlannedAction(tool_id, args, str(step.get("rationale", "")), "model"))

    if not actions:
        res = _fallback(scope, ["no proposed step survived validation; using default plan"] + notes)
        res.gateway_response = resp
        return res

    return PlanResult(actions=actions, used_model=True, gateway_response=resp, notes=notes)
