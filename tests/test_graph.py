from vapt_orch.graph.workflow import build_graph


def test_graph_runs_one_tool_and_reaches_report():
    calls = []

    def fake_runner(tool_id, args):
        calls.append((tool_id, args))
        return {"outcome": "ok", "evidence_ref": "evidence:test-1"}

    graph = build_graph(tool_runner=fake_runner)
    state = graph.invoke(
        {"schema_version": 1, "run_id": "r1", "thread_id": "t1", "scope_ref": "example.com"},
        {"configurable": {"thread_id": "t1"}},
    )
    assert state["phase"] == "report"
    assert calls == [("dns_resolve", {"target": "example.com"})]
    assert "evidence:test-1" in state["evidence_refs"]


def test_graph_observes_cancellation():
    graph = build_graph(tool_runner=lambda *_: {"outcome": "ok"})
    state = graph.invoke(
        {"run_id": "r2", "thread_id": "t2", "cancellation_requested": True},
        {"configurable": {"thread_id": "t2"}},
    )
    assert state["phase"] == "cancelled"
