"""Transactional-outbox relay: pending rows are dispatched oldest-first and marked
delivered; topics map to the right task call; an unknown topic is skipped (left
undelivered) instead of blocking the queue."""
from __future__ import annotations

import pytest
import vapt_persistence.db as dbmod
from vapt_orch.relay import dispatch_pending
from vapt_persistence import Base, init_engine
from vapt_persistence.models import Engagement, Outbox, Project, Run


@pytest.fixture()
def db(tmp_path):
    init_engine(f"sqlite:///{tmp_path}/r.db")
    Base.metadata.create_all(dbmod.get_engine())
    s = dbmod.SessionLocal()
    p = Project(name="P"); s.add(p); s.flush()
    e = Engagement(project_id=p.id, name="Lab", testing_mode="black_box", target_type="web")
    s.add(e); s.flush()
    r = Run(engagement_id=e.id, thread_id="t", status="queued"); s.add(r); s.flush()
    s.commit()
    yield s, r.id
    s.close()


def test_dispatch_maps_topics_and_marks_delivered(db):
    s, run_id = db
    s.add(Outbox(run_id=run_id, topic="run.start", payload={"run_id": run_id}))
    s.add(Outbox(run_id=run_id, topic="run.resume", payload={"run_id": run_id, "decision": "approve"}))
    s.commit()

    calls = []
    n = dispatch_pending(s, lambda topic, payload: calls.append((topic, payload)))
    s.commit()

    assert n == 2
    assert ("run.start", {"run_id": run_id}) in calls
    assert ("run.resume", {"run_id": run_id, "decision": "approve"}) in calls
    # All delivered now; a second drain does nothing.
    assert all(o.delivered for o in s.query(Outbox).all())
    assert dispatch_pending(s, lambda t, p: calls.append((t, p))) == 0


def test_bad_topic_is_skipped_not_blocking(db):
    s, run_id = db
    s.add(Outbox(run_id=run_id, topic="poison", payload={}))
    s.add(Outbox(run_id=run_id, topic="run.start", payload={"run_id": run_id}))
    s.commit()

    def dispatcher(topic, payload):
        if topic == "poison":
            raise ValueError("unknown topic")

    n = dispatch_pending(s, dispatcher)
    s.commit()
    # The good row was delivered; the poison row remains for later inspection.
    assert n == 1
    by_topic = {o.topic: o.delivered for o in s.query(Outbox).all()}
    assert by_topic["run.start"] is True
    assert by_topic["poison"] is False
