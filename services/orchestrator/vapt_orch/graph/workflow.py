"""LangGraph orchestrator skeleton (plan §6).

Week 1 exit gate: a scoped run persists a task, executes one safe tool and completes
one model call. This graph wires: intake -> plan -> recon(one P0 tool) -> END, with a
checkpointer so runs can pause/resume. Richer agents (scan/validate/...) attach here
in later weeks. The orchestrator controls routing; model text never changes transitions.
"""
from __future__ import annotations

from collections.abc import Callable

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph

from .state import EngagementState


def _intake_node(state: EngagementState) -> dict:
    return {"phase": "planning", "log": [f"intake: run {state.get('run_id')} accepted"]}


def _plan_node(state: EngagementState) -> dict:
    # A single bounded task is enough for the Week 1 gate.
    return {
        "phase": "recon",
        "task_refs": ["task:recon-dns-1"],
        "log": ["plan: created 1 recon task"],
    }


def build_recon_node(tool_runner: Callable[[str, dict], dict] | None = None) -> Callable:
    """Recon node runs exactly one safe (P0) tool via an injected runner.

    tool_runner is injected so tests can run without tool binaries, and so the real
    broker (with policy + ledger) is the only thing that actually executes tools.
    """

    def _recon_node(state: EngagementState) -> dict:
        if state.get("cancellation_requested"):
            return {"phase": "cancelled", "log": ["recon: cancellation observed"]}
        evidence: list[str] = []
        log = ["recon: running one P0 tool (dns_resolve)"]
        if tool_runner is not None:
            result = tool_runner("dns_resolve", {"target": state.get("scope_ref", "example.com")})
            evidence.append(result.get("evidence_ref", "evidence:dns-1"))
            log.append(f"recon: tool outcome={result.get('outcome')}")
        return {"phase": "report", "evidence_refs": evidence, "log": log}

    return _recon_node


def build_graph(tool_runner: Callable[[str, dict], dict] | None = None, checkpointer=None):
    graph = StateGraph(EngagementState)
    graph.add_node("intake", _intake_node)
    graph.add_node("plan", _plan_node)
    graph.add_node("recon", build_recon_node(tool_runner))
    graph.add_edge(START, "intake")
    graph.add_edge("intake", "plan")
    graph.add_edge("plan", "recon")
    graph.add_edge("recon", END)
    return graph.compile(checkpointer=checkpointer or MemorySaver())
