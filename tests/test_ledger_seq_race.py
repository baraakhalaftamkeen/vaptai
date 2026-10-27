"""ledger.record_event retries on seq collision (uq_run_event_seq).

Regression test for the DineHub 2026-10-23 10:43 failure where plan.proposed
collided at seq=4 under a Celery task retry. Before the fix, the IntegrityError
propagated out of record_event and killed the runs.start task with no recovery.
After the fix, record_event uses a SAVEPOINT per attempt and retries up to
_RECORD_EVENT_MAX_RETRIES times, bumping the seq each time.
"""
from __future__ import annotations

import pytest

from vapt_persistence import Base, init_engine, ledger
import vapt_persistence.db as dbmod
from vapt_persistence.models import Engagement, Project, Run, RunEvent


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


def test_record_event_assigns_monotonic_seq(db):
    s, run_id = db
    ev1 = ledger.record_event(s, run_id, "a")
    ev2 = ledger.record_event(s, run_id, "b")
    ev3 = ledger.record_event(s, run_id, "c")
    assert (ev1.seq, ev2.seq, ev3.seq) == (1, 2, 3)


def test_record_event_retries_on_seq_collision(db, monkeypatch):
    s, run_id = db
    # Pre-insert seq=1,2 so the first retry's "max(seq)+1 = 3" is the real next slot.
    ledger.record_event(s, run_id, "a")  # seq=1
    ledger.record_event(s, run_id, "b")  # seq=2

    # Force a collision on the first attempt by making next_event_seq return 2
    # (already taken) the first time, then normal behavior for retries.
    original = ledger.next_event_seq
    seq_sequence = iter([2])  # one bad value, then let the real function take over

    def _flaky(db_, rid):
        try:
            return next(seq_sequence)
        except StopIteration:
            return original(db_, rid)

    monkeypatch.setattr(ledger, "next_event_seq", _flaky)

    # record_event's first attempt should collide (seq=2 is taken), SAVEPOINT rollback,
    # then retry with next_event_seq producing seq=3, which succeeds.
    ev = ledger.record_event(s, run_id, "retried")
    assert ev.seq == 3

    # And the row IS persisted — not left in a half-written SAVEPOINT state.
    rows = s.query(RunEvent).filter(RunEvent.run_id == run_id).order_by(RunEvent.seq).all()
    assert [r.seq for r in rows] == [1, 2, 3]
    assert [r.kind for r in rows] == ["a", "b", "retried"]


def test_record_event_raises_after_max_retries_exhausted(db, monkeypatch):
    s, run_id = db
    ledger.record_event(s, run_id, "a")  # seq=1

    # Force EVERY attempt to collide. record_event should exhaust its retries and
    # re-raise so a genuine bug (not a transient race) surfaces instead of being
    # silently swallowed.
    monkeypatch.setattr(ledger, "next_event_seq", lambda db_, rid: 1)

    from sqlalchemy.exc import IntegrityError
    with pytest.raises(IntegrityError):
        ledger.record_event(s, run_id, "doomed")


def test_outer_transaction_survives_collision(db, monkeypatch):
    """A collision rolls back only the SAVEPOINT, not the caller's outer transaction.
    After a successful record_event (with internal retry), prior pending work in
    the same session must still be committable."""
    s, run_id = db
    # Add a Project in the outer tx (not committed yet) alongside the retry path.
    from vapt_persistence.models import Project as _P
    pending = _P(name="pending-work"); s.add(pending)

    original = ledger.next_event_seq
    seq_sequence = iter([1])  # collide once (seq=1 is taken from the fixture's events? no,
                              # fixture only inserts Project/Engagement/Run, no RunEvent)

    # Pre-insert seq=1 to force a collision on first attempt.
    ledger.record_event(s, run_id, "a")  # now seq=1 is taken

    def _flaky(db_, rid):
        try:
            return next(seq_sequence)
        except StopIteration:
            return original(db_, rid)

    monkeypatch.setattr(ledger, "next_event_seq", _flaky)
    ledger.record_event(s, run_id, "survives")  # collides at 1, retries → 2

    # The caller can still commit the outer transaction with its pending Project.
    s.commit()
    assert s.query(_P).filter(_P.name == "pending-work").count() == 1
