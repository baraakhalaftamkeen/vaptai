"""Approval-gated workflow (plan §6 §8, Week 2 exit gate).

Demonstrates the controlled-execution contract on the graph:
  allow        -> the action executes
  require_appr -> the graph INTERRUPTS (pauses); an approval decision resumes it
  reject       -> execution is blocked and a coverage gap is recorded

Uses LangGraph interrupt()/Command(resume=...) with a checkpointer so a paused run
survives and resumes on the same thread [plan S1]. A durable MariaDB checkpointer is
the documented Week 1-3 spike; MemorySaver is the in-process default here.
"""
from __future__ import annotations

from collections.abc import Callable

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import interrupt

from .state import EngagementState


def build_approval_graph(
    *,
    decide_action: Callable[[EngagementState], str],
    execute: Callable[[EngagementState], dict],
    checkpointer=None,
):
    """Build a graph whose single 'gate' node enforces the approval contract.

    decide_action(state) -> "allow" | "require_approval" | "deny"  (deterministic policy)
    execute(state)       -> dict patch merged into state after an approved/allowed action
    """

    def gate(state: EngagementState) -> dict:
        decision = decide_action(state)
        if decision == "deny":
            return {
                "phase": "report",
                "coverage_gaps": [f"denied: {state.get('pending_tool', 'action')}"],
                "log": ["gate: policy denied action"],
            }
        if decision == "require_approval":
            # Pause here. The resumed value carries the human decision.
            verdict = interrupt(
                {
                    "kind": "approval_required",
                    "tool": state.get("pending_tool"),
                    "target": state.get("scope_ref"),
                }
            )
            decision_value = (verdict or {}).get("decision", "reject")
            if decision_value not in ("approve", "approve_batch"):
                return {
                    "phase": "report",
                    "coverage_gaps": [f"rejected: {state.get('pending_tool', 'action')}"],
                    "log": ["gate: approval rejected -> blocked"],
                }
            # fall through to execution

        patch = execute(state)
        patch.setdefault("phase", "report")
        patch.setdefault("log", []).append("gate: action executed")
        return patch

    graph = StateGraph(EngagementState)
    graph.add_node("gate", gate)
    graph.add_edge(START, "gate")
    graph.add_edge("gate", END)
    return graph.compile(checkpointer=checkpointer or MemorySaver())
