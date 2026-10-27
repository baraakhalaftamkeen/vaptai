"""Web & network assessment pipeline: recon -> scan -> validate (plan §5, §6).

This is the sequential library path. It now delegates each phase to the shared helpers
in `phases`, so the graph nodes and this function run identical recon/scan/validate
logic through the GovernedHarness. A candidate is a scanner observation; only the
validate step marks something confirmed — AI/scanner output alone never confirms.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy.orm import Session
from vapt_harness import GovernedHarness
from vapt_persistence import ledger

from . import phases
from .runscope import RunScope

__all__ = ["RunScope", "PipelineResult", "run_web_network_pipeline"]


@dataclass
class PipelineResult:
    asset_refs: list[str] = field(default_factory=list)
    candidate_finding_ids: list[str] = field(default_factory=list)
    confirmed_finding_ids: list[str] = field(default_factory=list)
    approvals_requested: list[str] = field(default_factory=list)
    coverage_gaps: list[str] = field(default_factory=list)


def run_web_network_pipeline(
    db: Session,
    scope: RunScope,
    harness: GovernedHarness,
    scan_tools: list[tuple[str, dict]] | None = None,
) -> PipelineResult:
    """Drive one run through recon -> scan -> validate. Returns what was produced.

    scan_tools lets the caller choose the adapter set + args; defaults to a bounded
    black/gray-box web+network set. On an action that needs approval, the sequential
    path records the approval id and moves on (the graph path pauses instead)."""
    result = PipelineResult()
    scan_tools = scan_tools or phases.DEFAULT_SCAN_TOOLS

    # --- Recon ---
    result.asset_refs = phases.recon_phase(db, scope, harness)

    # --- Scan ---
    ledger.record_event(db, scope.run_id, "phase.scan", {})
    for i, (tool_id, args) in enumerate(scan_tools):
        step = phases.scan_action(
            db, scope, harness, tool_id=tool_id, args=args, task_id=f"scan-{i}"
        )
        if step.outcome.approval_id:
            result.approvals_requested.append(step.outcome.approval_id)
            continue  # paused for approval; a later resume re-runs this action
        if not step.outcome.executed:
            result.coverage_gaps.append(f"{tool_id}: {step.outcome.reason}")
            continue
        result.candidate_finding_ids.extend(step.candidate_ids)

    # --- Validate ---
    ledger.record_event(db, scope.run_id, "phase.validate", {})
    for fid in result.candidate_finding_ids:
        if phases.validate_candidate(db, scope, harness, fid):
            result.confirmed_finding_ids.append(fid)

    ledger.record_event(
        db, scope.run_id, "phase.report",
        {"candidates": len(result.candidate_finding_ids),
         "confirmed": len(result.confirmed_finding_ids)},
    )
    return result
