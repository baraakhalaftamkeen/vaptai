"""Shared, bounded EngagementState (plan §6).

Stores identifiers and compact summaries only — never raw captures or secrets.
Reducers append by stable IDs so queue retries / graph replay don't duplicate.
"""
from __future__ import annotations

import operator
from typing import Annotated, TypedDict


def _merge_unique(left: list, right: list) -> list:
    seen = list(left)
    for item in right:
        if item not in seen:
            seen.append(item)
    return seen


class EngagementState(TypedDict, total=False):
    schema_version: int
    engagement_id: str
    run_id: str
    thread_id: str
    project_id: str

    scope_ref: str
    scope_version: int
    testing_mode: str
    target_type: str

    policy_version: str
    budget_remaining: int
    deadline: str | None

    phase: str
    # The planning agent's proposed, policy-ungated scan plan (last-write-wins).
    # Each item: {"tool_id": str, "args": dict, "rationale": str, "source": str}
    plan: list[dict]
    plan_source: str                 # "model" | "fallback"
    # The action currently awaiting human approval (surfaced on interrupt).
    pending_action: dict
    # Scan is a self-looping node: one planned action per visit, so at most one
    # interrupt() per visit and resume values never drift (see engagement.py).
    scan_idx: int
    scan_iters: int
    # Attack is also a self-looping node (one gated PoC per visit).
    attack_idx: int
    attack_iters: int
    # Webvuln is a self-looping node (one gated active web-vuln scan per visit).
    webvuln_idx: int
    webvuln_iters: int
    task_refs: Annotated[list[str], _merge_unique]
    proposed_asset_refs: Annotated[list[str], _merge_unique]
    approved_asset_refs: Annotated[list[str], _merge_unique]
    candidate_finding_refs: Annotated[list[str], _merge_unique]
    validated_finding_refs: Annotated[list[str], _merge_unique]
    evidence_refs: Annotated[list[str], _merge_unique]
    pending_action_refs: Annotated[list[str], _merge_unique]
    approval_refs: Annotated[list[str], _merge_unique]
    coverage_gaps: Annotated[list[str], operator.add]
    error_refs: Annotated[list[str], operator.add]

    cancellation_requested: bool
    report_ref: str | None
    # Drafted narrative carried between the remediate and report nodes (bounded summaries,
    # not raw captures or secrets) so the report node can assemble both.
    remediation_text: str
    report_summary: str
    log: Annotated[list[str], operator.add]
