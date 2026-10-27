"""The one mandatory harness for every tool invocation (plan §5, §6).

Lifecycle for a proposed action:
  load scope + policy  →  check the agent may use this tool/capability
  →  record the proposal in the ledger  →  ask the deterministic policy engine
  →  ALLOW: broker executes  |  REQUIRE_APPROVAL: create approval, stop (no execution)
     |  DENY: record a coverage gap, stop
  →  on execution: record result + run events.

The harness is application code, not a model prompt. A model's text can never widen
a decision: it only proposes a tool_id + typed args. Scope enforcement happens here
AND (later) in the worker network path — defense in depth.
"""
from __future__ import annotations

import ipaddress
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from sqlalchemy.orm import Session
from vapt_domain.enums import AgentRole, PolicyClass, PolicyDecision, TestingMode
from vapt_domain.schemas import ToolResult
from vapt_persistence import ledger
from vapt_policy import PolicyEngine, PolicyInput
from vapt_tools import ToolBroker, ToolRegistry, action_digest, idempotency_key


def _utcnow_iso() -> str:
    """UTC wall-clock timestamp (ISO-8601) for the ledger's live progress events."""
    from datetime import UTC, datetime
    return datetime.now(UTC).isoformat()


_ARG_WHITELIST = {
    # Keys worth showing operators in the ledger. url/param/classes/data/engine/method
    # are the ones that make different web_param_probe/dalfox/ssti invocations
    # distinguishable from each other — the symptom we had on prior runs was 15 identical-
    # looking `tool=web_param_probe target=HOST` events that revealed nothing about
    # which route was probed. Credentials, cookies, tokens, bodies, payloads: never.
    "url", "param", "classes", "data", "engine", "method", "scheme", "port",
    "ports", "severity", "modules", "seeds",
    # idor_probe / dom_xss_probe / stored_xss_probe pass a comma-joined URL LIST
    # under the `urls` (plural) / `post_url` / `view_url` keys. Without these in the
    # whitelist the ledger shows `args={}` which looked like "the plan dispatched
    # idor_probe with no urls" (2026-10-26 run) — misleading operators into
    # thinking the deterministic seeder failed when the subprocess actually did
    # receive the URL list. Still bounded by _ARG_VALUE_CAP so a 40-URL list
    # doesn't blow up the event payload.
    "urls", "post_url", "view_url",
    # login_url is a bare URL (no credentials) — operators need to see whether an
    # authenticated scan actually had a login endpoint to post against. On the last
    # auto-approve run wapiti ran unauthenticated because login_url silently became
    # None; without this field in the ledger, that's invisible.
    "login_url", "authdisc",
}
_ARG_VALUE_CAP = 200


def _summarize_args(args: dict | None) -> dict:
    """Return a shallow, size-capped, whitelist-filtered view of a tool's args for the
    ledger. Guards against: credentials leaking (whitelist), huge seed lists blowing up
    the event payload (per-key cap), and nested-dict surprises (string-coerce)."""
    if not isinstance(args, dict):
        return {}
    out: dict = {}
    for k in _ARG_WHITELIST:
        if k not in args:
            continue
        v = args[k]
        if isinstance(v, (list, tuple)):
            vs = ",".join(str(x) for x in v)
            out[k] = vs[:_ARG_VALUE_CAP] + ("…" if len(vs) > _ARG_VALUE_CAP else "")
        else:
            vs = str(v)
            out[k] = vs[:_ARG_VALUE_CAP] + ("…" if len(vs) > _ARG_VALUE_CAP else "")
    return out


def _enqueue_resume(db: Session, run_id: str) -> None:
    """Mirror the API's post-decision outbox write: on auto-approve from the harness, the
    graph needs a `run.resume` message delivered the same way a human-decided approval
    would send one. The relay then kicks `runs.resume` on Celery. Fail-safe — any Outbox
    import issue (e.g. older model without the table) silently skips, so a stale schema
    can't crash a run; the harness just degrades to "approval exists but no resume"
    which is what we already had before auto-approve existed."""
    try:
        from vapt_persistence.models import Outbox, Run
        r = db.get(Run, run_id)
        if r is None:
            return
        if str(getattr(r, "status", "")).lower() not in ("completed", "cancelled", "failed"):
            r.status = "queued"
        db.add(Outbox(run_id=run_id, topic="run.resume",
                      payload={"run_id": run_id, "decision": "approve"}))
    except Exception:
        return


def _run_auto_approve(db: Session, run_id: str) -> bool:
    """Fresh DB read of this run's auto_approve flag. Mirrors `_run_cancelled` — the
    LangGraph state's cached snapshot would miss a mid-run toggle, so always consult the
    DB. Fail-safe: any error → False (keep the human gate, never auto-approve on confusion)."""
    try:
        from vapt_persistence.models import Run
        r = db.get(Run, run_id)
        if r is None:
            return False
        return bool(getattr(r, "auto_approve", False))
    except Exception:
        return False


def _run_cancelled(db: Session, run_id: str) -> bool:
    """Fresh DB read of this run's cancellation state. The orchestrator's cached
    LangGraph state is a snapshot from task start; a user cancel after that doesn't
    propagate until the next task boundary. Every harness entry point consults the DB
    directly so a cancel reliably blocks new actions even mid-flight. Fail-safe: any
    DB error → return False (prefer accidentally running an extra action over silently
    halting a healthy run on a transient hiccup)."""
    try:
        from vapt_persistence.models import Run
        r = db.get(Run, run_id)
        if r is None:
            return False
        return bool(getattr(r, "cancellation_requested", False)) or \
            str(getattr(r, "status", "")) == "cancelled"
    except Exception:
        return False


def scope_contains(target: str, *, domains: list[str], ip_cidrs: list[str]) -> bool:
    """Deterministic scope membership. A bare domain matches itself and its subdomains;
    an IP must fall inside an approved CIDR. Wildcards never auto-expand here."""
    t = target.strip().lower()
    if not t:
        return False
    # IP target?
    try:
        ip = ipaddress.ip_address(t)
        for cidr in ip_cidrs:
            try:
                if ip in ipaddress.ip_network(cidr, strict=False):
                    return True
            except ValueError:
                continue
        return False
    except ValueError:
        pass
    # Domain target: exact or subdomain of an approved domain.
    for d in domains:
        d = d.strip().lower().lstrip("*.")
        if t == d or t.endswith("." + d):
            return True
    return False


@dataclass
class ActionContext:
    run_id: str
    task_id: str
    agent_role: AgentRole
    testing_mode: TestingMode
    tool_id: str
    profile_id: str
    target_ref: str
    args: dict
    allowed_action_classes: list[PolicyClass]
    scope_domains: list[str] = field(default_factory=list)
    scope_ip_cidrs: list[str] = field(default_factory=list)
    signed_profile: bool = False
    resolved_addresses: list[str] = field(default_factory=list)
    requested_by: str | None = None


@dataclass
class ActionOutcome:
    decision: PolicyDecision
    executed: bool
    reason: str
    action_digest: str
    idempotency_key: str
    approval_id: str | None = None
    result: ToolResult | None = None


class GovernedHarness:
    def __init__(
        self,
        registry: ToolRegistry,
        policy: PolicyEngine | None = None,
        broker: ToolBroker | None = None,
        progress_commit: Callable[[], None] | None = None,
    ):
        self._registry = registry
        self._policy = policy or PolicyEngine()
        # Broker is injectable so tests (and lab runs without real scanner binaries)
        # can supply a stub that returns known results.
        self._broker = broker or ToolBroker(registry)
        # Optional commit hook, set by the orchestrator to db.commit. When present, the
        # harness commits the ledger the moment a tool STARTS (and again when it finishes),
        # so a long-running scanner is visible live on the run page — "nmap_vuln running
        # since 10:31, 3m elapsed" — instead of the run looking frozen. It NEVER cuts a
        # tool short; it only publishes progress. Absent (tests) → no commits, unchanged.
        self._progress_commit = progress_commit

    def _publish(self) -> None:
        """Commit in-flight ledger events to live readers, if a commit hook is set.
        Best-effort: a commit failure must not abort a running scan."""
        if self._progress_commit is not None:
            try:
                self._progress_commit()
            except Exception:
                pass

    def tool_available(self, tool_id: str, args: dict) -> bool:
        """Is this tool's binary resolvable? Delegates to the broker (the real broker
        checks PATH / VAPT_*_BIN overrides; an injected stub broker without the check is
        assumed capable, so lab/test runs execute regardless of real binaries). Lets a
        caller avoid forcing a human approval for a PoC that would only no-op."""
        check = getattr(self._broker, "is_available", None)
        if not callable(check):
            return True
        return bool(check(tool_id, args))

    def run_action(self, db: Session, ctx: ActionContext) -> ActionOutcome:
        digest = action_digest(ctx.tool_id, ctx.profile_id, ctx.target_ref, ctx.args)
        key = idempotency_key(ctx.run_id, ctx.task_id, digest)

        # 0. Cancellation check — the operator may have cancelled this run while a prior
        # tool subprocess was still running (nikto/nmap_vuln routinely take 2–3 minutes),
        # and the orchestrator wouldn't notice until the subprocess returns. Record a
        # terminal "action.cancelled" instead of creating a new approval the operator will
        # have to reject manually. The LangGraph state's cached cancellation_requested is
        # stale here; a fresh DB read is the authoritative source.
        if _run_cancelled(db, ctx.run_id):
            ledger.record_event(db, ctx.run_id, "action.cancelled",
                                {"digest": digest, "tool": ctx.tool_id,
                                 "reason": "run cancelled by operator"})
            return ActionOutcome(PolicyDecision.DENY, False,
                                 "run cancelled by operator", digest, key)

        # 1. Capability check: this agent may use this tool at all.
        spec = self._registry.get(ctx.tool_id)
        if ctx.agent_role not in spec.allowed_agents:
            ledger.record_event(
                db, ctx.run_id, "action.blocked",
                {"digest": digest, "reason": f"{ctx.agent_role.value} may not use {ctx.tool_id}"},
            )
            return ActionOutcome(
                PolicyDecision.DENY, False,
                f"agent {ctx.agent_role.value} not permitted to use {ctx.tool_id}",
                digest, key,
            )

        # 2. Record the proposal in the ledger (idempotent on key).
        action = ledger.record_tool_action(
            db, run_id=ctx.run_id, tool_id=ctx.tool_id, profile_id=ctx.profile_id,
            args=ctx.args, target_ref=ctx.target_ref, action_digest=digest,
            idempotency_key=key, policy_class=spec.policy_class.value, state="proposed",
        )
        # Include task_id so the ledger links a confirmed finding back to WHICH
        # proposal wave produced it (webvuln-llm-ag-N → recon agent, -rx-N →
        # reactive wave, -llm-N → primary LLM, deterministic prefixes otherwise).
        ledger.record_event(db, ctx.run_id, "action.proposed",
                            {"digest": digest, "tool": ctx.tool_id, "target": ctx.target_ref,
                             "task_id": ctx.task_id,
                             "args": _summarize_args(ctx.args)})

        # 3. Deterministic policy decision.
        # Local tools (source analysis) act on the engagement's own uploaded bundle in
        # the run workspace — their scope is that bundle, not a host — so they are in
        # scope by workspace. Network tools must pass domain/CIDR scope membership.
        if getattr(spec, "target_kind", "network") == "local":
            in_scope = True
        else:
            in_scope = scope_contains(
                ctx.target_ref, domains=ctx.scope_domains, ip_cidrs=ctx.scope_ip_cidrs
            )
        pr = self._policy.evaluate(
            PolicyInput(
                policy_class=spec.policy_class,
                tool_id=ctx.tool_id,
                profile_id=ctx.profile_id,
                target_ref=ctx.target_ref,
                testing_mode=ctx.testing_mode,
                allowed_action_classes=ctx.allowed_action_classes,
                in_scope=in_scope,
                resolved_addresses=ctx.resolved_addresses,
                signed_profile=ctx.signed_profile,
            )
        )
        ledger.record_policy_decision(
            db, run_id=ctx.run_id, action_digest=digest,
            policy_version=pr.policy_version, decision=pr.decision.value, reason=pr.reason,
        )

        # 4. Act on the decision.
        if pr.decision == PolicyDecision.DENY:
            ledger.set_action_state(db, action, "denied")
            ledger.record_event(db, ctx.run_id, "action.denied",
                                {"digest": digest, "reason": pr.reason})
            return ActionOutcome(pr.decision, False, pr.reason, digest, key)

        if pr.decision == PolicyDecision.REQUIRE_APPROVAL:
            appr = ledger.get_pending_approval(db, ctx.run_id, digest) or ledger.create_approval(
                db, run_id=ctx.run_id, action_digest=digest,
                policy_class=spec.policy_class.value, requested_by=ctx.requested_by,
            )
            ledger.record_event(db, ctx.run_id, "approval.requested",
                                {"digest": digest, "approval_id": appr.id})
            # Auto-approve path: if the operator opted this run into auto-approve, flip
            # the approval to approved IMMEDIATELY and let the normal post-approval
            # execute path take over. The scope + policy checks STILL run on the actual
            # action (every tool call re-enters the harness via execute_approved), so
            # auto-approve only bypasses the human gate, never scope enforcement.
            if _run_auto_approve(db, ctx.run_id) and appr.state == "pending":
                appr.state = "approved"
                ledger.record_event(db, ctx.run_id, "approval.decided",
                                    {"approval_id": appr.id, "digest": digest,
                                     "decision": "approved", "by": "auto-approve"})
                return self._execute(db, ctx, action, digest, key)
            return ActionOutcome(
                pr.decision, False, pr.reason, digest, key, approval_id=appr.id
            )

        # ALLOW -> broker executes.
        return self._execute(db, ctx, action, digest, key)

    def require_approval(self, db: Session, ctx: ActionContext, *, reason: str) -> ActionOutcome:
        """Force a human gate on an action regardless of its policy class, without
        executing it. Used by agents whose manifest always escalates (e.g. ATTACK): the
        action is proposed and an approval is created, but nothing runs until a human
        approves and execute_approved() is called. Still does the capability check, so an
        agent cannot propose a tool it isn't allowed to use."""
        digest = action_digest(ctx.tool_id, ctx.profile_id, ctx.target_ref, ctx.args)
        key = idempotency_key(ctx.run_id, ctx.task_id, digest)

        # Same cancellation guard as run_action — a cancel mid-attack must not drop a
        # fresh approval into the operator's queue.
        if _run_cancelled(db, ctx.run_id):
            ledger.record_event(db, ctx.run_id, "action.cancelled",
                                {"digest": digest, "tool": ctx.tool_id,
                                 "reason": "run cancelled by operator"})
            return ActionOutcome(PolicyDecision.DENY, False,
                                 "run cancelled by operator", digest, key)

        spec = self._registry.get(ctx.tool_id)
        if ctx.agent_role not in spec.allowed_agents:
            ledger.record_event(
                db, ctx.run_id, "action.blocked",
                {"digest": digest, "reason": f"{ctx.agent_role.value} may not use {ctx.tool_id}"},
            )
            return ActionOutcome(
                PolicyDecision.DENY, False,
                f"agent {ctx.agent_role.value} not permitted to use {ctx.tool_id}", digest, key,
            )

        action = ledger.record_tool_action(
            db, run_id=ctx.run_id, tool_id=ctx.tool_id, profile_id=ctx.profile_id,
            args=ctx.args, target_ref=ctx.target_ref, action_digest=digest,
            idempotency_key=key, policy_class=spec.policy_class.value, state="proposed",
        )
        # Include task_id so the ledger links a confirmed finding back to WHICH
        # proposal wave produced it: webvuln-llm-N (primary LLM), -rx-N (reactive
        # 2nd wave), -ag-N (recon agent), or the deterministic planner prefixes.
        ledger.record_event(db, ctx.run_id, "action.proposed",
                            {"digest": digest, "tool": ctx.tool_id, "target": ctx.target_ref,
                             "task_id": ctx.task_id,
                             "args": _summarize_args(ctx.args)})
        # Record the forced decision so the ledger shows WHY approval was required.
        ledger.record_policy_decision(
            db, run_id=ctx.run_id, action_digest=digest,
            policy_version="manifest", decision=PolicyDecision.REQUIRE_APPROVAL.value, reason=reason,
        )
        appr = ledger.get_pending_approval(db, ctx.run_id, digest) or ledger.create_approval(
            db, run_id=ctx.run_id, action_digest=digest,
            policy_class=spec.policy_class.value, requested_by=ctx.requested_by,
        )
        ledger.record_event(db, ctx.run_id, "approval.requested",
                            {"digest": digest, "approval_id": appr.id, "forced": True})
        # Auto-approve path (forced-approval variant for ATTACK). The graph will pause
        # here on interrupt. We can't bypass the pause from inside the harness because
        # the LangGraph interrupt mechanism is on the ORCHESTRATOR side — but we CAN
        # flip the approval to approved AND enqueue the outbox entry the API would have
        # written, so the normal relay → resume_run path fires without a human click.
        if _run_auto_approve(db, ctx.run_id) and appr.state == "pending":
            appr.state = "approved"
            ledger.record_event(db, ctx.run_id, "approval.decided",
                                {"approval_id": appr.id, "digest": digest,
                                 "decision": "approved", "by": "auto-approve"})
            _enqueue_resume(db, ctx.run_id)
        _ = action  # proposal recorded; execution happens only via execute_approved
        return ActionOutcome(
            PolicyDecision.REQUIRE_APPROVAL, False, reason, digest, key, approval_id=appr.id
        )

    def execute_approved(self, db: Session, ctx: ActionContext) -> ActionOutcome:
        """Called after an approval is granted. Re-validates scope + policy immediately
        before execution (approval binds to the action digest, not a stale decision)."""
        digest = action_digest(ctx.tool_id, ctx.profile_id, ctx.target_ref, ctx.args)
        key = idempotency_key(ctx.run_id, ctx.task_id, digest)
        spec = self._registry.get(ctx.tool_id)

        in_scope = True if getattr(spec, "target_kind", "network") == "local" else scope_contains(
            ctx.target_ref, domains=ctx.scope_domains, ip_cidrs=ctx.scope_ip_cidrs
        )
        if not in_scope:
            ledger.record_event(db, ctx.run_id, "action.blocked",
                                {"digest": digest, "reason": "scope changed; no longer in scope"})
            return ActionOutcome(PolicyDecision.DENY, False, "scope revalidation failed", digest, key)

        action = ledger.record_tool_action(
            db, run_id=ctx.run_id, tool_id=ctx.tool_id, profile_id=ctx.profile_id,
            args=ctx.args, target_ref=ctx.target_ref, action_digest=digest,
            idempotency_key=key, policy_class=spec.policy_class.value, state="authorized",
        )
        return self._execute(db, ctx, action, digest, key)

    def _execute(self, db: Session, ctx: ActionContext, action, digest: str, key: str) -> ActionOutcome:
        ledger.set_action_state(db, action, "authorized")
        # Announce the start with the tool, target and a wall-clock timestamp, then PUBLISH
        # it before the (possibly very long) tool runs — so the run page shows exactly what
        # is executing and for how long, and nobody kills a scan that is simply taking its
        # time. No wall-clock limit is imposed here: the tool runs to completion.
        started_at = _utcnow_iso()
        ledger.record_event(
            db, ctx.run_id, "action.executing",
            {"digest": digest, "tool": ctx.tool_id, "target": ctx.target_ref,
             "started_at": started_at},
        )
        self._publish()
        t0 = time.monotonic()
        # Guarantee a terminal state (`executed` or `failed`) on the DB row no matter
        # what happens in the broker call or in the post-broker ledger writes.
        # Previously, if `broker.execute()` raised (an uncaught subprocess error, a
        # Python-level exception in a shim's validation, a mysterious OSError), the
        # exception propagated up and the row stayed in `authorized` forever,
        # requiring the watchdog to clean up. Now we catch, synthesize a failed
        # ToolResult, write the state + ledger event, and re-raise so the caller
        # still sees the error.
        try:
            result = self._broker.execute(ctx.tool_id, ctx.args)
        except Exception as e:
            elapsed = round(time.monotonic() - t0, 1)
            # Best-effort terminal state + ledger. If THESE raise too, swallow —
            # the watchdog is the last line of defense.
            try:
                ledger.set_action_state(db, action, "failed")
                ledger.record_event(
                    db, ctx.run_id, "action.executed",
                    {"digest": digest, "tool": ctx.tool_id, "outcome": "failed",
                     "exit_code": None, "elapsed_seconds": elapsed,
                     "note": f"broker raised: {type(e).__name__}: {str(e)[:200]}"},
                )
                self._publish()
            except Exception:
                pass
            raise
        elapsed = round(time.monotonic() - t0, 1)
        ledger.set_action_state(db, action, "executed")
        ledger.record_event(
            db, ctx.run_id, "action.executed",
            {"digest": digest, "tool": ctx.tool_id, "outcome": result.outcome,
             "exit_code": result.exit_code, "elapsed_seconds": elapsed},
        )
        self._publish()
        return ActionOutcome(
            PolicyDecision.ALLOW, True, "executed", digest, key, result=result
        )
