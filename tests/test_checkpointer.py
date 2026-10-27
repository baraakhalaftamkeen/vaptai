"""Durable SQLAlchemy checkpointer: a direct put/get round-trip, and proof that a
paused graph resumes after the checkpointer (and the in-process graph) is rebuilt —
i.e. the pause survived in the database, not in memory. This is the Week 1-3 spike.
"""
from __future__ import annotations

from typing import TypedDict

import pytest
import vapt_persistence.db as dbmod
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, interrupt
from vapt_orch.graph.checkpointer import SqlAlchemyCheckpointer
from vapt_persistence import Base, init_engine
from vapt_persistence.models import GraphCheckpoint


@pytest.fixture()
def factory(tmp_path):
    init_engine(f"sqlite:///{tmp_path}/ck.db")
    Base.metadata.create_all(dbmod.get_engine())
    return lambda: dbmod.SessionLocal()


class MiniState(TypedDict, total=False):
    value: str
    answer: str


def _build(checkpointer):
    def start(state: MiniState) -> dict:
        return {"value": "started"}

    def gate(state: MiniState) -> dict:
        verdict = interrupt({"question": "approve?"})
        return {"answer": verdict}

    g = StateGraph(MiniState)
    g.add_node("start", start)
    g.add_node("gate", gate)
    g.add_edge(START, "start")
    g.add_edge("start", "gate")
    g.add_edge("gate", END)
    return g.compile(checkpointer=checkpointer)


def test_checkpointer_direct_roundtrip(factory):
    cp = SqlAlchemyCheckpointer(factory)
    graph = _build(cp)
    cfg = {"configurable": {"thread_id": "rt-1"}}
    out = graph.invoke({"value": "x"}, cfg)
    assert "__interrupt__" in out                     # paused at the gate

    # A checkpoint row exists, and get_tuple reconstructs the paused state.
    with factory() as s:
        assert s.query(GraphCheckpoint).filter_by(thread_id="rt-1").count() >= 1
    tup = cp.get_tuple(cfg)
    assert tup is not None
    assert tup.checkpoint["channel_values"].get("value") == "started"


def test_pause_survives_checkpointer_rebuild(factory):
    # Graph + checkpointer #1: run until it pauses, then throw both away.
    cp1 = SqlAlchemyCheckpointer(factory)
    cfg = {"configurable": {"thread_id": "resume-1"}}
    out = _build(cp1).invoke({"value": "x"}, cfg)
    assert "__interrupt__" in out

    # Fresh checkpointer + fresh compiled graph (simulates a worker restart). State
    # must come entirely from the database.
    cp2 = SqlAlchemyCheckpointer(factory)
    resumed = _build(cp2).invoke(Command(resume="yes"), cfg)
    assert resumed.get("answer") == "yes"
    assert "__interrupt__" not in resumed
