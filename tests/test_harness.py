"""Governed harness: allow -> execute, deny -> blocked, require_approval -> pending
(no execution), then execute_approved -> executed. Ledger records every step.
"""
from __future__ import annotations

import pytest
from sqlalchemy import select
from vapt_domain.enums import AgentRole, PolicyClass, PolicyDecision, TestingMode
from vapt_harness import ActionContext, GovernedHarness
from vapt_persistence import Base, init_engine
from vapt_persistence.models import (
    Approval,
    Engagement,
    PolicyDecisionRecord,
    Project,
    Run,
    RunEvent,
    ToolActionRecord,
)
from vapt_tools import REGISTRY


@pytest.fixture()
def db(tmp_path):
    import vapt_persistence.db as dbmod
    from vapt_persistence import SessionLocal  # noqa: F401

    init_engine(f"sqlite:///{tmp_path}/h.db")
    Base.metadata.create_all(dbmod.get_engine())
    s = dbmod.SessionLocal()
    # seed a project/engagement/run so FKs resolve
    p = Project(name="P")
    s.add(p)
    s.flush()
    e = Engagement(project_id=p.id, name="E", testing_mode="black_box", target_type="web")
    s.add(e)
    s.flush()
    r = Run(engagement_id=e.id, thread_id="t1", status="running")
    s.add(r)
    s.flush()
    s.commit()
    yield s, r.id
    s.close()


def _ctx(run_id, **kw):
    base = dict(
        run_id=run_id,
        task_id="task1",
        agent_role=AgentRole.RECON,
        testing_mode=TestingMode.BLACK_BOX,
        tool_id="dns_resolve",
        profile_id="default",
        target_ref="example.com",
        args={"target": "example.com"},
        allowed_action_classes=[PolicyClass.P0_PASSIVE, PolicyClass.P1_LOW_IMPACT],
        scope_domains=["example.com"],
        scope_ip_cidrs=[],
    )
    base.update(kw)
    return ActionContext(**base)


def test_allow_p0_executes(db):
    s, run_id = db
    h = GovernedHarness(REGISTRY)
    out = h.run_action(s, _ctx(run_id))
    s.commit()
    assert out.decision == PolicyDecision.ALLOW
    assert out.executed is True
    # ledger: action executed + events present
    action = s.execute(select(ToolActionRecord)).scalars().one()
    assert action.state == "executed"
    kinds = {e.kind for e in s.execute(select(RunEvent)).scalars().all()}
    assert {"action.proposed", "action.executing", "action.executed"} <= kinds


def test_live_progress_published_and_timed(db):
    """A tool announces its start (tool + target + started_at), published immediately via
    the commit hook so the run page shows it live, and records elapsed_seconds on finish —
    all without any wall-clock limit that could cut a legitimately long scan."""
    s, run_id = db
    commits = {"n": 0}
    h = GovernedHarness(REGISTRY, progress_commit=lambda: commits.__setitem__("n", commits["n"] + 1))
    out = h.run_action(s, _ctx(run_id))
    s.commit()
    assert out.executed is True
    assert commits["n"] >= 2                    # published at start AND at finish

    events = {e.kind: (e.payload or {}) for e in s.execute(select(RunEvent)).scalars().all()}
    assert events["action.executing"]["tool"] == "dns_resolve"
    assert events["action.executing"]["started_at"]                 # timestamp for "running since…"
    assert "elapsed_seconds" in events["action.executed"]           # duration for "took Ns"


def test_progress_commit_failure_does_not_abort(db):
    """A failing commit hook must never break a running action — progress is best-effort."""
    s, run_id = db
    def _boom():
        raise RuntimeError("reader connection dropped")
    h = GovernedHarness(REGISTRY, progress_commit=_boom)
    out = h.run_action(s, _ctx(run_id))         # must not raise
    s.commit()
    assert out.executed is True


def test_out_of_scope_denied(db):
    s, run_id = db
    h = GovernedHarness(REGISTRY)
    out = h.run_action(s, _ctx(run_id, target_ref="evil.com", args={"target": "evil.com"}))
    s.commit()
    assert out.decision == PolicyDecision.DENY
    assert out.executed is False
    action = s.execute(select(ToolActionRecord)).scalars().one()
    assert action.state == "denied"


def test_wrong_agent_blocked(db):
    s, run_id = db
    h = GovernedHarness(REGISTRY)
    # http_probe is allowed for RECON/SCAN, not VALIDATE
    out = h.run_action(
        s, _ctx(run_id, agent_role=AgentRole.REPORTING, tool_id="http_probe")
    )
    s.commit()
    assert out.decision == PolicyDecision.DENY
    assert out.executed is False


def test_require_approval_then_execute_approved(db):
    s, run_id = db
    h = GovernedHarness(REGISTRY)
    # http_probe is P1; without a signed profile -> require approval
    ctx = _ctx(run_id, tool_id="http_probe", agent_role=AgentRole.RECON)
    out = h.run_action(s, ctx)
    s.commit()
    assert out.decision == PolicyDecision.REQUIRE_APPROVAL
    assert out.executed is False
    assert out.approval_id is not None
    # action still pending, not executed
    action = s.execute(select(ToolActionRecord)).scalars().one()
    assert action.state == "proposed"
    appr = s.get(Approval, out.approval_id)
    assert appr.state == "pending"

    # Approve out-of-band, then execute_approved runs it.
    appr.state = "approved"
    s.commit()
    out2 = h.execute_approved(s, ctx)
    s.commit()
    assert out2.executed is True
    pol = s.execute(select(PolicyDecisionRecord)).scalars().all()
    assert any(p.decision == "require_approval" for p in pol)


def test_signed_profile_allows_p1(db):
    s, run_id = db
    h = GovernedHarness(REGISTRY)
    out = h.run_action(
        s, _ctx(run_id, tool_id="http_probe", agent_role=AgentRole.RECON, signed_profile=True)
    )
    s.commit()
    assert out.decision == PolicyDecision.ALLOW
    assert out.executed is True


def test_cancelled_run_blocks_new_actions(db):
    """A run flagged `cancellation_requested=True` must not have new approvals or actions
    created on it mid-flight — otherwise an in-flight tool subprocess finishing after the
    operator hits Cancel would drop a fresh approval into their queue.
    Regression for: `cancel sets flag -> graph proposes next action -> approval appears`."""
    s, run_id = db
    r = s.get(Run, run_id)
    r.cancellation_requested = True
    r.status = "cancelled"
    s.commit()

    h = GovernedHarness(REGISTRY)
    out = h.run_action(s, _ctx(run_id))
    s.commit()

    assert out.decision == PolicyDecision.DENY
    assert out.executed is False
    assert "cancelled" in (out.reason or "").lower()
    # No approval was created
    assert s.execute(select(Approval).filter_by(run_id=run_id)).first() is None
    # Ledger records the cancellation path
    kinds = {e.kind for e in s.execute(select(RunEvent).filter_by(run_id=run_id)).scalars().all()}
    assert "action.cancelled" in kinds


def test_auto_approve_run_bypasses_human_gate(db, monkeypatch):
    """When Run.auto_approve=True, an action that would normally stop for human approval
    must instead be auto-approved. Scope + policy checks still apply.
    Regression for the operator complaint "15 web_param_probe approvals per run".

    Uses http_probe (P1) without signed_profile → requires approval. The broker is
    stubbed so the test doesn't actually hit the network — we only care that the
    harness flipped the approval to 'approved' and recorded the decision event."""
    s, run_id = db
    r = s.get(Run, run_id)
    r.auto_approve = True
    s.commit()

    from datetime import UTC, datetime
    from vapt_domain.schemas import ToolResult

    class _OkBroker:
        def execute(self, tool_id, args):
            now = datetime.now(UTC)
            return ToolResult(outcome="ok", exit_code=0, started_at=now, finished_at=now,
                              tool_version="stub", observations=[{"stdout": "ok"}])

    h = GovernedHarness(REGISTRY, broker=_OkBroker())
    out = h.run_action(
        s, _ctx(run_id, tool_id="http_probe", agent_role=AgentRole.RECON),
    )
    s.commit()

    # Approval record created and auto-approved — no human gate hit
    apprs = s.execute(select(Approval).filter_by(run_id=run_id)).scalars().all()
    assert len(apprs) == 1, f"expected 1 approval, got {len(apprs)}"
    assert apprs[0].state == "approved"
    # Ledger shows the auto-decision
    kinds = [e.kind for e in s.execute(select(RunEvent).filter_by(run_id=run_id)).scalars().all()]
    assert "approval.requested" in kinds
    assert "approval.decided" in kinds
    # The action actually executed (auto-approve → _execute)
    assert out.executed is True


def test_cancelled_run_blocks_require_approval(db):
    """Same guard but on the always-escalate path used by ATTACK agents — a cancel in flight
    must suppress the forced-approval creation too."""
    s, run_id = db
    r = s.get(Run, run_id)
    r.cancellation_requested = True
    s.commit()

    h = GovernedHarness(REGISTRY)
    out = h.require_approval(
        s,
        _ctx(run_id, tool_id="burp_request", agent_role=AgentRole.ATTACK,
             args={"target": "example.com", "scheme": "https"}),
        reason="policy: attack escalates",
    )
    s.commit()
    assert out.decision == PolicyDecision.DENY
    assert s.execute(select(Approval).filter_by(run_id=run_id)).first() is None
