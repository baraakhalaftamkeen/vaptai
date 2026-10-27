"""Watchdog — sweeps orphaned `tool_actions` rows on worker boot.

Regression test for the DineHub 2026-10-23 and -24 UX bug where `csp_check`
appeared "running" for 20+ minutes because the matching `action.executed`
ledger write never landed (worker restarted mid-task, or seq-race lost all
retries). After the watchdog, orphaned rows are swept on next worker boot
and the UI shows "ran but did not complete" instead of pretending they're
still live.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from vapt_persistence import Base, init_engine
import vapt_persistence.db as dbmod
from vapt_persistence.models import (
    Engagement, Project, Run, RunEvent, ToolActionRecord,
)
from vapt_orch.watchdog import cleanup_orphaned_actions


@pytest.fixture()
def db(tmp_path):
    init_engine(f"sqlite:///{tmp_path}/n.db")
    Base.metadata.create_all(dbmod.get_engine())
    s = dbmod.SessionLocal()
    p = Project(name="P"); s.add(p); s.flush()
    e = Engagement(project_id=p.id, name="L", testing_mode="black_box",
                   target_type="web"); s.add(e); s.flush()
    r = Run(engagement_id=e.id, thread_id="t", status="running"); s.add(r); s.flush()
    s.commit()
    yield s, r.id
    s.close()


def _mk_action(sess, run_id: str, *, state: str, age_minutes: int,
               digest: str = "deadbeef") -> ToolActionRecord:
    rec = ToolActionRecord(
        run_id=run_id, tool_id="csp_check", profile_id="scan",
        args={"url": "http://x"}, target_ref="x",
        action_digest=digest, idempotency_key=f"k-{digest}",
        policy_class="p1_low_impact", state=state,
    )
    sess.add(rec); sess.flush()
    # SQLAlchemy populates created_at via server-default; we override to age the row.
    rec.created_at = datetime.now(UTC) - timedelta(minutes=age_minutes)
    sess.commit()
    return rec


def test_sweeps_stale_executing_row(db):
    s, run_id = db
    _mk_action(s, run_id, state="executing", age_minutes=60, digest="stale1")
    swept = cleanup_orphaned_actions()
    assert swept == 1
    r = s.query(ToolActionRecord).filter_by(action_digest="stale1").one()
    assert r.state == "failed"
    # And the synthetic ledger event landed, so the report pipeline sees it.
    events = s.execute(
        select(RunEvent).where(RunEvent.run_id == run_id,
                               RunEvent.kind == "action.executed")
    ).scalars().all()
    assert any(ev.payload.get("digest") == "stale1"
               and ev.payload.get("outcome") == "failed"
               and ev.payload.get("note") == "worker_restart_orphan"
               for ev in events)


def test_sweeps_stale_proposed_row(db):
    s, run_id = db
    _mk_action(s, run_id, state="proposed", age_minutes=60, digest="prop1")
    swept = cleanup_orphaned_actions()
    assert swept == 1
    assert s.query(ToolActionRecord).filter_by(action_digest="prop1").one().state == "failed"


def test_sweeps_stale_authorized_row(db):
    """Regression for the DineHub 2026-10-24 observation: 5 csp_check rows
    wedged in `authorized` state for days. Approval completed but the broker
    call never fired. The watchdog must cover `authorized` too, not just
    `executing`/`proposed`, or these rows live forever."""
    s, run_id = db
    _mk_action(s, run_id, state="authorized", age_minutes=60, digest="auth1")
    swept = cleanup_orphaned_actions()
    assert swept == 1
    assert s.query(ToolActionRecord).filter_by(action_digest="auth1").one().state == "failed"


def test_leaves_fresh_executing_row_alone(db):
    """A row that's only 2 minutes old could still be running legitimately —
    the longest tool timeout in the registry is wapiti @ 420s + startup.
    Threshold is 15 min; fresh rows stay untouched."""
    s, run_id = db
    _mk_action(s, run_id, state="executing", age_minutes=2, digest="fresh1")
    swept = cleanup_orphaned_actions()
    assert swept == 0
    assert s.query(ToolActionRecord).filter_by(action_digest="fresh1").one().state == "executing"


def test_leaves_terminal_rows_alone(db):
    """`executed`, `failed`, `denied` rows are terminal — the watchdog must
    never touch them even if they're ancient, because touching one would
    double-write its ledger `action.executed` event (which is what the
    original seq-race fix was all about — don't duplicate ledger writes)."""
    s, run_id = db
    _mk_action(s, run_id, state="executed", age_minutes=120, digest="done1")
    _mk_action(s, run_id, state="failed", age_minutes=120, digest="done2")
    swept = cleanup_orphaned_actions()
    assert swept == 0
    assert s.query(ToolActionRecord).filter_by(action_digest="done1").one().state == "executed"
    assert s.query(ToolActionRecord).filter_by(action_digest="done2").one().state == "failed"


def test_sweeps_multiple_rows_in_one_pass(db):
    s, run_id = db
    _mk_action(s, run_id, state="executing", age_minutes=60, digest="s1")
    _mk_action(s, run_id, state="executing", age_minutes=45, digest="s2")
    _mk_action(s, run_id, state="proposed", age_minutes=30, digest="s3")
    _mk_action(s, run_id, state="executing", age_minutes=1, digest="fresh")
    swept = cleanup_orphaned_actions()
    assert swept == 3
    final = {r.action_digest: r.state
             for r in s.query(ToolActionRecord).all()}
    assert final == {"s1": "failed", "s2": "failed", "s3": "failed",
                     "fresh": "executing"}


def test_cleanup_is_idempotent(db):
    """Called twice back-to-back, the second call finds nothing to do and
    emits no new ledger events. Protects against double-sweep bugs if a
    cron ever calls this alongside the worker-boot handler."""
    s, run_id = db
    _mk_action(s, run_id, state="executing", age_minutes=60, digest="once")
    assert cleanup_orphaned_actions() == 1
    assert cleanup_orphaned_actions() == 0
    # Exactly ONE synthetic ledger event, not two.
    hits = [
        ev for ev in s.execute(
            select(RunEvent).where(RunEvent.run_id == run_id,
                                   RunEvent.kind == "action.executed")
        ).scalars().all()
        if ev.payload.get("digest") == "once"
    ]
    assert len(hits) == 1
