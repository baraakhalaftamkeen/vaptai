"""Celery tasks that drive runs.

The API writes an Outbox row + Celery message in one transaction. These tasks are
idempotent on run_id. Web/network runs are driven by the real multi-agent LangGraph
engagement graph (intake→plan→recon→scan→validate→report) with a durable MariaDB
checkpointer, so a run paused for approval resumes on the same thread after a restart.
Other target types fall back to the minimal Week-1 graph for now.
"""
from __future__ import annotations

import ipaddress
import os
import uuid
from datetime import UTC, datetime, timedelta

import vapt_persistence.db as dbmod
from vapt_agents.runscope import RunScope
from vapt_domain.enums import PolicyClass, TestingMode
from vapt_harness import GovernedHarness
from vapt_persistence import init_engine, session_scope

# Importing `watchdog` registers the celery `worker_ready` signal handler that
# sweeps orphaned tool_actions on worker boot. The handler fires ONCE per worker,
# before accepting tasks — see vapt_orch/watchdog.py for the full rationale.
from . import watchdog  # noqa: F401 — signal registration via import side-effect
# `preflight` registers a second `worker_ready` handler that verifies every
# worker binary (vapt-recon-fetch etc.) exists and is executable, logging a
# loud warning per missing file. Prevents the silent-degradation failure mode
# where a missing binary makes features (e.g. the Stage-3 recon agent) return
# [] with no ledger trace. See vapt_orch/preflight.py for the full rationale.
from . import preflight  # noqa: F401 — signal registration via import side-effect
from vapt_persistence.models import (
    Engagement,
    Outbox,
    Run,
    RunEvent,
    Schedule,
    ScopeVersion,
    SourceBundle,
)
from vapt_tools import REGISTRY

from .celery_app import celery_app
from .graph.checkpointer import SqlAlchemyCheckpointer
from .graph.engagement import build_engagement_graph
from .graph.source import build_source_graph
from .graph.workflow import build_graph
from .relay import celery_dispatcher, dispatch_pending
from .runner import make_tool_runner

_engine_ready = False


def _ensure_engine() -> None:
    global _engine_ready
    if not _engine_ready:
        init_engine(os.environ.get("VAPT_DATABASE_URL", "sqlite:///./vapt_v2_dev.db"))
        _engine_ready = True


def _next_seq(db, run_id: str) -> int:
    # Flush pending events first (session is autoflush=False) so a just-added event is
    # counted and two events can't collide on the same seq (uq_run_event_seq).
    db.flush()
    seqs = [e.seq for e in db.query(RunEvent).filter(RunEvent.run_id == run_id).all()]
    return (max(seqs) + 1) if seqs else 1


def _latest_scope(db, engagement_id: str) -> dict:
    sv = (
        db.query(ScopeVersion)
        .filter(ScopeVersion.engagement_id == engagement_id)
        .order_by(ScopeVersion.version.desc())
        .first()
    )
    return sv.scope if sv else {}


def _build_gateway():
    """Build the LLM gateway from env, or return None so the planner uses its
    deterministic fallback. A missing/unknown model must never crash a run."""
    try:
        from vapt_llm import LLMGateway, profiles_from_env

        return LLMGateway(profiles_from_env())
    except Exception:
        return None


def _resolve_scope(domains, ip_cidrs) -> tuple[list[str], list[str], str]:
    """Partition raw scope entries into hostnames + CIDRs for membership checks, and
    derive ONE concrete probe host. Separating the authorization boundary (what is in
    scope) from the probe target (a single host to hit) is what prevents a CIDR like
    172.25.188.23/32 from being used verbatim as a target — that is a network, not a
    host, so the scope check and the scanner arg builders both reject it.

    Tolerant of a bare IP typed into the domains box (folded into the CIDR scope as a
    /32 or /128). A /32 CIDR yields its single host; a broader CIDR yields its first
    usable host (per-host expansion across a range is not done here)."""
    hostnames: list[str] = []
    cidrs: list[str] = []
    target: str | None = None
    for raw in [*(domains or []), *(ip_cidrs or [])]:
        v = str(raw).strip()
        if not v:
            continue
        try:                                   # bare IP -> single-host CIDR scope entry
            ip = ipaddress.ip_address(v)
            cidrs.append(f"{v}/{ip.max_prefixlen}")
            target = target or v
            continue
        except ValueError:
            pass
        try:                                   # CIDR -> keep as scope, derive a host
            net = ipaddress.ip_network(v, strict=False)
            cidrs.append(v)
            if target is None:
                if net.num_addresses == 1:
                    target = str(net.network_address)
                else:
                    hosts = list(net.hosts())
                    target = str(hosts[0]) if hosts else str(net.network_address)
            continue
        except ValueError:
            pass
        hostnames.append(v)                    # hostname
        target = target or v
    return hostnames, cidrs, (target or "example.com")


def _run_scope(db, run: Run, eng: Engagement) -> RunScope:
    scope = _latest_scope(db, eng.id)
    domains, ip_cidrs, target = _resolve_scope(scope.get("domains", []), scope.get("ip_cidrs", []))
    allowed = [PolicyClass(c) for c in scope.get("allowed_action_classes",
                                                 ["p0_passive", "p1_low_impact"])]
    return RunScope(
        run_id=run.id,
        testing_mode=TestingMode(eng.testing_mode),
        target=target,
        domains=domains,
        ip_cidrs=ip_cidrs,
        allowed_action_classes=allowed,
        signed_profile=True,
        allowed_ports=_ports_spec(scope.get("allowed_ports", "")),
        allow_exploitation=bool(scope.get("allow_exploitation", False)),
        poc_playbook=str(scope.get("poc_playbook", "http_evidence")),
        # Optional .nessus import: a workspace-relative path from the scope, or a global
        # VAPT_NESSUS_FILE fallback. Tenable.sc live intel needs no scope field (env-gated).
        nessus_path=(str(scope.get("nessus_path")) if scope.get("nessus_path")
                     else os.environ.get("VAPT_NESSUS_FILE") or None),
    )


def _ports_spec(value) -> str:
    """Normalize a stored allowed_ports value to a port-spec string. New scopes store a
    string; a legacy scope may hold a list[int]."""
    if isinstance(value, (list, tuple)):
        return ",".join(str(int(p)) for p in value)
    return str(value or "").strip()


def _latest_bundle(db, engagement_id: str) -> SourceBundle | None:
    return (
        db.query(SourceBundle)
        .filter(SourceBundle.engagement_id == engagement_id)
        .order_by(SourceBundle.created_at.desc())
        .first()
    )


def _source_scope(db, run: Run, eng: Engagement, bundle_path: str | None) -> RunScope:
    scope = _latest_scope(db, eng.id)
    allowed = [PolicyClass(c) for c in scope.get("allowed_action_classes",
                                                 ["p0_passive", "p1_low_impact"])]
    return RunScope(
        run_id=run.id,
        testing_mode=TestingMode(eng.testing_mode),
        target=bundle_path or "source://none",
        domains=[],
        ip_cidrs=[],
        allowed_action_classes=allowed,
        signed_profile=True,
    )


def _graph_for_run(db, run: Run, eng: Engagement):
    """Build the right graph for a run. Returns (graph, scope_target) for a real
    engagement/source graph, or (None, None) to use the minimal fallback graph."""
    checkpointer = SqlAlchemyCheckpointer(lambda: dbmod.SessionLocal())
    # progress_commit=db.commit makes each tool's start/finish visible on the run page the
    # moment it happens (live per-tool ledger), so a long scan never looks frozen.
    harness = GovernedHarness(REGISTRY, progress_commit=db.commit)
    gateway = _build_gateway()
    if eng and eng.target_type in ("web", "network"):
        scope = _run_scope(db, run, eng)
        g = build_engagement_graph(db=db, scope=scope, harness=harness,
                                   gateway=gateway, checkpointer=checkpointer)
        return g, scope.target
    if eng and eng.target_type == "source":
        bundle = _latest_bundle(db, eng.id)
        bundle_path = bundle.extracted_path if bundle else None
        scope = _source_scope(db, run, eng, bundle_path)
        g = build_source_graph(db=db, scope=scope, harness=harness, bundle_path=bundle_path,
                               gateway=gateway, checkpointer=checkpointer)
        return g, scope.target
    return None, None


def _drive_graph(graph, inputs, config, db) -> dict:
    """Run the graph while committing after each super-step, so the execution ledger fills
    in LIVE — phase by phase, as each node finishes — instead of all at once when the whole
    run completes. Without this, the entire graph.invoke() sits inside one transaction that
    commits only at the end, so a reader on another connection (the run page) sees nothing
    until the run is done, then every event at once.

    Each commit lands on a node boundary, which is also where the checkpointer persists
    state, so committing there stays crash-consistent (recovery resumes from the last
    completed node). Returns an invoke-compatible final state: '__interrupt__' is set when
    the graph paused for approval, detected via the checkpoint's pending `next` nodes;
    '__cancelled__' is set when a mid-flight operator cancel was observed between super-
    steps, so finalize marks the run cancelled instead of paused."""
    from vapt_persistence.models import Run

    run_id = inputs.get("run_id") if isinstance(inputs, dict) else None
    last: dict = {}
    for chunk in graph.stream(inputs, config, stream_mode="values"):
        if isinstance(chunk, dict):
            last = chunk
        db.commit()   # publish this super-step's ledger events to live readers
        # Fresh DB check for cancellation — the LangGraph state's cached flag is a snapshot
        # from task start, so the only way to observe an operator cancel issued AFTER the
        # task started is to re-read the Run row at every super-step boundary. Breaking out
        # here stops the graph from proposing a fresh approval the operator will have to
        # dismiss by hand.
        if run_id:
            try:
                db.expire_all()                    # drop stale snapshots
                r = db.get(Run, run_id)
                if r is not None and (r.cancellation_requested or r.status == "cancelled"):
                    return {**last, "__cancelled__": True}
            except Exception:
                pass
    snap = graph.get_state(config)
    if getattr(snap, "next", None):        # paused at an interrupt (approval) — not complete
        return {**last, "__interrupt__": True}
    return last


def _finalize(db, run: Run, final_state: dict) -> dict:
    """Mark a run completed or paused based on the graph's returned state."""
    # Mid-flight cancellation observed by _drive_graph — reject any approvals the graph
    # created BEFORE the cancel landed, mark terminal, record the event. We do this before
    # the __interrupt__ check because a cancellation observation always wins over a pause.
    if final_state.get("__cancelled__"):
        from vapt_persistence.models import Approval
        for appr in db.query(Approval).filter(
            Approval.run_id == run.id, Approval.state == "pending"
        ).all():
            appr.state = "rejected"
        run.status = "cancelled"
        run.phase = "cancelled"
        db.add(RunEvent(run_id=run.id, seq=_next_seq(db, run.id),
                        kind="run.cancelled",
                        payload={"reason": "operator cancelled mid-run"}))
        return {"status": "cancelled", "run_id": run.id}
    if "__interrupt__" in final_state:
        run.status = "awaiting_approval"
        run.phase = final_state.get("phase", "scan")
        db.add(RunEvent(run_id=run.id, seq=_next_seq(db, run.id),
                        kind="run.paused", payload={"reason": "approval_required"}))
        return {"status": "awaiting_approval", "run_id": run.id}

    run.phase = final_state.get("phase", "report")
    run.status = "completed"
    db.add(RunEvent(
        run_id=run.id, seq=_next_seq(db, run.id), kind="run.completed",
        payload={
            "candidates": len(final_state.get("candidate_finding_refs", [])),
            "confirmed": len(final_state.get("validated_finding_refs", [])),
        },
    ))
    return {"status": "completed", "run_id": run.id,
            "candidates": len(final_state.get("candidate_finding_refs", [])),
            "confirmed": len(final_state.get("validated_finding_refs", []))}


def _latest_completed_run(db, engagement_id: str, exclude_id: str | None = None):
    q = db.query(Run).filter(Run.engagement_id == engagement_id, Run.status == "completed")
    if exclude_id:
        q = q.filter(Run.id != exclude_id)
    return q.order_by(Run.created_at.desc()).first()


def enqueue_run(db, engagement_id: str, *, retest_of: str | None = None) -> Run:
    """Create a queued Run + its transactional-outbox start intent (the relay dispatches
    it). Shared by the scheduler tick and the retest endpoint."""
    run = Run(
        engagement_id=engagement_id, thread_id=str(uuid.uuid4()),
        status="queued", phase="intake", retest_of=retest_of,
    )
    db.add(run)
    db.flush()
    db.add(RunEvent(run_id=run.id, seq=1, kind="run.created",
                    payload={"scheduled": retest_of is None, "retest_of": retest_of}))
    db.add(Outbox(run_id=run.id, topic="run.start", payload={"run_id": run.id}))
    return run


@celery_app.task(name="schedules.tick")
def tick_schedules() -> dict:
    """Beat tick: fire every enabled schedule whose next_fire_at is due, creating a run
    (linked as a retest of the engagement's latest completed run) and advancing the
    schedule. Interval-based for the beta; cron is kept for display/future."""
    _ensure_engine()
    now = datetime.now(UTC)
    fired = 0
    with session_scope() as db:
        due = db.query(Schedule).filter(
            Schedule.enabled.is_(True),
            Schedule.interval_minutes.isnot(None),
            Schedule.next_fire_at.isnot(None),
            Schedule.next_fire_at <= now,
        ).all()
        for sch in due:
            prior = _latest_completed_run(db, sch.engagement_id)
            enqueue_run(db, sch.engagement_id, retest_of=(prior.id if prior else None))
            sch.last_fired_at = now
            sch.next_fire_at = now + timedelta(minutes=int(sch.interval_minutes or 60))
            fired += 1
    return {"fired": fired}


@celery_app.task(name="outbox.drain")
def drain_outbox() -> dict:
    """Periodic transactional-outbox relay: dispatch undelivered rows into Celery.
    Scheduled by Celery beat (see celery_app.beat_schedule)."""
    _ensure_engine()
    with session_scope() as db:
        n = dispatch_pending(db, celery_dispatcher)
    return {"dispatched": n}


_TERMINAL = ("completed", "cancelled", "failed")


def _lock_run(db, run_id: str) -> Run | None:
    """Fetch the run FOR UPDATE so two workers can't drive the same run concurrently
    (which raced on the run-event sequence → uq_run_event_seq duplicates). On MariaDB this
    serializes start/resume per run; on SQLite (dev/tests) it is a harmless no-op since
    writes are already serialized."""
    return db.query(Run).filter(Run.id == run_id).with_for_update().first()


@celery_app.task(name="runs.start", bind=True, max_retries=3)
def start_run(self, run_id: str) -> dict:
    _ensure_engine()
    with session_scope() as db:
        run = _lock_run(db, run_id)
        if run is None:
            return {"status": "missing", "run_id": run_id}
        # Idempotent: a duplicate start for a run that already ran (or is past intake) is a
        # no-op rather than a second graph invocation.
        if run.status in _TERMINAL or run.status == "running":
            return {"status": f"noop_{run.status}", "run_id": run_id}
        eng = db.get(Engagement, run.engagement_id)

        run.status = "running"
        db.add(RunEvent(run_id=run.id, seq=_next_seq(db, run.id), kind="run.started", payload={}))

        graph, target = _graph_for_run(db, run, eng)
        if graph is not None:
            config = {"configurable": {"thread_id": run.thread_id}}
            initial = {
                "schema_version": 1, "engagement_id": run.engagement_id, "run_id": run.id,
                "thread_id": run.thread_id, "scope_ref": target, "phase": "intake",
                "budget_remaining": 100, "cancellation_requested": run.cancellation_requested,
            }
            final_state = _drive_graph(graph, initial, config, db)
            return _finalize(db, run, final_state)

        # Fallback: minimal Week-1 graph for any other target type.
        graph = build_graph(tool_runner=make_tool_runner(run.id))
        config = {"configurable": {"thread_id": run.thread_id}}
        initial = {
            "schema_version": 1, "engagement_id": run.engagement_id, "run_id": run.id,
            "thread_id": run.thread_id, "scope_ref": "example.com", "phase": "intake",
            "budget_remaining": 100, "cancellation_requested": run.cancellation_requested,
        }
        final_state = graph.invoke(initial, config)
        run.phase = final_state.get("phase", "report")
        run.status = "completed"
        db.add(RunEvent(
            run_id=run.id, seq=_next_seq(db, run.id), kind="run.completed",
            payload={"phase": run.phase},
        ))
        return {"status": "completed", "run_id": run.id, "phase": run.phase}


@celery_app.task(name="runs.resume", bind=True, max_retries=3)
def resume_run(self, run_id: str, decision: str = "approve") -> dict:
    """Resume a run paused for approval. `decision` is the human verdict
    ('approve' | 'approve_batch' | 'reject'). Marks the pending approval(s) decided
    and resumes the graph on the same thread via Command(resume=...)."""
    from langgraph.types import Command

    _ensure_engine()
    with session_scope() as db:
        run = _lock_run(db, run_id)      # serialize: one resume per run at a time
        if run is None:
            return {"status": "missing", "run_id": run_id}
        eng = db.get(Engagement, run.engagement_id)
        if not (eng and eng.target_type in ("web", "network", "source")):
            return {"status": "not_resumable", "run_id": run_id}
        if run.status in _TERMINAL:
            return {"status": f"noop_{run.status}", "run_id": run_id}

        graph, _target = _graph_for_run(db, run, eng)
        config = {"configurable": {"thread_id": run.thread_id}}

        # Only resume if the graph is actually paused at an interrupt. A stale or duplicate
        # resume (e.g. an approval decided after the run already finished, or two resume
        # messages racing) finds no pending work and is a no-op — this is what prevents the
        # graph from being re-invoked to completion twice and colliding on the event seq.
        try:
            snap = graph.get_state(config)
            has_pending = bool(getattr(snap, "next", None))
        except Exception:
            has_pending = True   # can't tell → fall through and let invoke decide
        if not has_pending:
            return {"status": "noop_no_interrupt", "run_id": run_id}

        # The approval decision is recorded authoritatively by the API decide endpoint:
        # it sets Approval.state and logs approval.decided (with the approval_id + reviewer)
        # in the same transaction that enqueues this resume. resume_run must NOT also flip
        # approvals here — the old bulk "mark every pending approval approved" (a) double-
        # logged the decision and (b) could approve an unrelated action on a duplicate
        # resume. The graph nodes read the recorded per-action decision via
        # phases.prior_decision, so here we only drive the graph forward.
        run.status = "running"
        final_state = _drive_graph(graph, Command(resume={"decision": decision}), config, db)
        return _finalize(db, run, final_state)
