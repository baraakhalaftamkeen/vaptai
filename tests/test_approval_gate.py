"""Week 2 exit gate on the graph: allow executes; require_approval pauses (interrupt),
approve resumes and executes, reject blocks and records a coverage gap.
"""
from __future__ import annotations

from langgraph.checkpoint.memory import MemorySaver
from langgraph.types import Command
from vapt_orch.graph.approval_gate import build_approval_graph


def _executed_flag():
    calls = {"n": 0}

    def execute(state):
        calls["n"] += 1
        return {"evidence_refs": ["evidence:x"], "log": []}

    return calls, execute


def test_allow_executes_without_pause():
    calls, execute = _executed_flag()
    g = build_approval_graph(decide_action=lambda s: "allow", execute=execute)
    out = g.invoke({"run_id": "r1", "pending_tool": "http_probe"}, {"configurable": {"thread_id": "r1"}})
    assert calls["n"] == 1
    assert out["phase"] == "report"
    assert "__interrupt__" not in out


def test_require_approval_pauses_then_approve_resumes():
    calls, execute = _executed_flag()
    cp = MemorySaver()
    g = build_approval_graph(decide_action=lambda s: "require_approval", execute=execute, checkpointer=cp)
    cfg = {"configurable": {"thread_id": "r2"}}
    paused = g.invoke({"run_id": "r2", "pending_tool": "nuclei"}, cfg)
    # Paused: interrupt surfaced, nothing executed yet.
    assert "__interrupt__" in paused
    assert calls["n"] == 0
    # Resume with an approval.
    out = g.invoke(Command(resume={"decision": "approve"}), cfg)
    assert calls["n"] == 1
    assert out["phase"] == "report"


def test_reject_blocks_and_records_gap():
    calls, execute = _executed_flag()
    cp = MemorySaver()
    g = build_approval_graph(decide_action=lambda s: "require_approval", execute=execute, checkpointer=cp)
    cfg = {"configurable": {"thread_id": "r3"}}
    g.invoke({"run_id": "r3", "pending_tool": "sqlmap"}, cfg)
    out = g.invoke(Command(resume={"decision": "reject"}), cfg)
    assert calls["n"] == 0  # never executed
    assert any("rejected" in gap for gap in out.get("coverage_gaps", []))


def test_deny_blocks_without_pause():
    calls, execute = _executed_flag()
    g = build_approval_graph(decide_action=lambda s: "deny", execute=execute)
    out = g.invoke({"run_id": "r4", "pending_tool": "masscan"}, {"configurable": {"thread_id": "r4"}})
    assert calls["n"] == 0
    assert any("denied" in gap for gap in out.get("coverage_gaps", []))
