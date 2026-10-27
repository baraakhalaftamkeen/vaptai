"""Regression for the uq_run_event_seq collision: with an autoflush=False session, a
run event added by the task layer (not yet flushed) must still be counted when the graph
computes the next seq — otherwise two events race to the same seq and the batched insert
fails on commit."""
from __future__ import annotations

import pytest

from vapt_persistence import Base, init_engine, ledger
import vapt_persistence.db as dbmod
from vapt_persistence.models import Engagement, Project, Run, RunEvent
from vapt_orch.tasks import _next_seq


@pytest.fixture()
def db(tmp_path):
    init_engine(f"sqlite:///{tmp_path}/ev.db")
    Base.metadata.create_all(dbmod.get_engine())
    s = dbmod.SessionLocal()
    p = Project(name="P"); s.add(p); s.flush()
    e = Engagement(project_id=p.id, name="Lab", testing_mode="black_box", target_type="web")
    s.add(e); s.flush()
    r = Run(engagement_id=e.id, thread_id="t", status="queued"); s.add(r); s.flush()
    # run.created committed first, like the API create path.
    s.add(RunEvent(run_id=r.id, seq=1, kind="run.created", payload={}))
    s.commit()
    yield s, r.id
    s.close()


def test_mixed_manual_and_ledger_events_do_not_collide(db):
    s, run_id = db

    # Task layer adds run.started WITHOUT flushing (mirrors tasks.start_run).
    s.add(RunEvent(run_id=run_id, seq=_next_seq(s, run_id), kind="run.started", payload={}))

    # Graph then records several events via the ledger (flushes each).
    ledger.record_event(s, run_id, "phase.intake")
    ledger.record_event(s, run_id, "phase.scan")

    # Task layer finalizes with another manual add.
    s.add(RunEvent(run_id=run_id, seq=_next_seq(s, run_id), kind="run.completed", payload={}))

    s.commit()  # must not raise IntegrityError on uq_run_event_seq

    # run.created, run.started, phase.intake, phase.scan, run.completed
    seqs = sorted(e.seq for e in s.query(RunEvent).filter(RunEvent.run_id == run_id).all())
    assert seqs == [1, 2, 3, 4, 5]       # contiguous and unique — no collision
    assert len(seqs) == len(set(seqs))
