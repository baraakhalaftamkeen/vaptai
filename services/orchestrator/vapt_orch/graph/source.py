"""White-box source engagement graph (plan §5, BAR-27).

    START → intake → analyze → validate → remediate → report → END

The ANALYZE node runs the static-analysis adapters (semgrep, gitleaks, dependency
audit) against the engagement's uploaded source bundle through the GovernedHarness —
so policy, the ledger and (for P1 dep-audit without a signed profile) approval gating
apply exactly as they do for network scans. It is self-looping (one analyzer per visit)
so a gated analyzer pauses the whole graph via interrupt(), re-entrant via the ledger.

VALIDATE is evidence-anchored: a static finding is confirmed only if the file it points
at actually exists in the bundle — candidate vs confirmed holds for SAST too. REMEDIATE
and REPORT draft via the gateway (counts-only audit) and degrade offline.
"""
from __future__ import annotations

from langgraph.graph import END, START, StateGraph
from langgraph.types import interrupt
from sqlalchemy.orm import Session
from vapt_agents import phases
from vapt_agents.manifests import REMEDIATION, REPORTING, SCAN, VALIDATE, ManifestGuard
from vapt_agents.report import build_and_store as build_report
from vapt_agents.report import findings_brief
from vapt_agents.runscope import RunScope
from vapt_harness import GovernedHarness
from vapt_persistence import ledger

from .drafting import draft_and_audit
from .state import EngagementState

_GROUNDED_SYSTEM = (
    "You write factual security-assessment prose. Base everything strictly on the "
    "findings you are given. Never invent vulnerabilities, CVEs, files, software "
    "versions, or hosts that are not explicitly listed. Be concise."
)


def build_source_graph(
    *,
    db: Session,
    scope: RunScope,
    harness: GovernedHarness,
    bundle_path: str | None,
    gateway=None,
    checkpointer=None,
    record_model_calls: bool = True,
):
    """Compile a source-analysis graph bound to one run. `bundle_path` is the extracted
    source directory (platform-supplied, never model-supplied)."""

    tools = list(phases.DEFAULT_SOURCE_TOOLS)

    def intake(state: EngagementState) -> dict:
        ledger.record_event(db, scope.run_id, "phase.intake",
                            {"run_id": scope.run_id, "bundle": bool(bundle_path)})
        if not bundle_path:
            # No source uploaded: nothing to analyze. Record a gap and finish cleanly.
            ledger.record_event(db, scope.run_id, "phase.analyze", {"skipped": "no source bundle"})
            return {"phase": "report", "coverage_gaps": ["source: no bundle uploaded"],
                    "log": ["intake: no source bundle; nothing to analyze"]}
        return {"phase": "analyze", "log": [f"intake: run {scope.run_id} accepted"]}

    # -- analyze (self-looping: ONE analyzer per visit) ----------------------
    def analyze(state: EngagementState) -> dict:
        if state.get("cancellation_requested"):
            return {"phase": "cancelled", "log": ["analyze: cancellation observed"]}

        idx = int(state.get("scan_idx", 0))
        iters = int(state.get("scan_iters", 0)) + 1
        if idx == 0 and iters == 1:
            ledger.record_event(db, scope.run_id, "phase.analyze", {"tools": len(tools)})

        if idx >= len(tools) or iters > SCAN.max_iterations:
            return {"phase": "validate", "scan_iters": iters,
                    "candidate_finding_refs": phases.candidate_ids_for_run(db, scope.run_id),
                    "log": ["analyze: complete"]}

        tool_id = tools[idx]
        args = {"path": bundle_path}
        task_id = f"analyze-{idx}"
        base = {"phase": "analyze", "scan_idx": idx + 1, "scan_iters": iters}

        if phases.already_executed(db, scope, task_id=task_id, tool_id=tool_id, args=args):
            return {**base, "log": [f"analyze: {tool_id} already done; skipping"]}

        step = phases.scan_action(db, scope, harness, tool_id=tool_id, args=args, task_id=task_id)

        if step.outcome.approval_id:
            verdict = interrupt({
                "kind": "approval_required", "tool": tool_id, "target": "source bundle",
                "approval_id": step.outcome.approval_id,
                "action_digest": step.outcome.action_digest, "reason": step.outcome.reason,
            })
            decision = (verdict or {}).get("decision", "reject")
            if decision in ("approve", "approve_batch"):
                phases.execute_scan_after_approval(
                    db, scope, harness, tool_id=tool_id, args=args, task_id=task_id)
                return {**base, "log": [f"analyze: {tool_id} approved and executed"]}
            return {**base, "coverage_gaps": [f"{tool_id}: approval {decision}"],
                    "log": [f"analyze: {tool_id} not approved ({decision})"]}

        if not step.outcome.executed:
            return {**base, "coverage_gaps": [f"{tool_id}: {step.outcome.reason}"],
                    "log": [f"analyze: {tool_id} not executed ({step.outcome.reason})"]}
        return {**base, "log": [f"analyze: {tool_id} executed ({len(step.candidate_ids)} finding(s))"]}

    def _analyze_router(state: EngagementState) -> str:
        return "validate" if state.get("phase") == "validate" else "analyze"

    # -- validate (evidence-anchored) ----------------------------------------
    def validate(state: EngagementState) -> dict:
        guard = ManifestGuard(VALIDATE)
        for fid in phases.candidate_ids_for_run(db, scope.run_id):
            try:
                guard.step()
            except Exception:
                break
            phases.validate_source_candidate(db, fid, bundle_path or "")
        confirmed = phases.confirmed_ids_for_run(db, scope.run_id)
        return {"phase": "remediate", "validated_finding_refs": confirmed,
                "log": [f"validate: {len(confirmed)} confirmed (location verified)"]}

    def remediate(state: EngagementState) -> dict:
        confirmed = phases.confirmed_ids_for_run(db, scope.run_id)
        brief = findings_brief(db, scope.run_id)
        text, used, diag = draft_and_audit(
            db=db, run_id=scope.run_id, gateway=gateway, manifest=REMEDIATION,
            record_model_calls=record_model_calls,
            messages=[
                {"role": "system", "content": _GROUNDED_SYSTEM},
                {"role": "user", "content": (
                    f"The ONLY source findings are:\n{brief or '(none)'}\n\n"
                    "Draft short, prioritized remediation guidance addressing ONLY these "
                    "findings (no code dumps). Do not invent issues, CVEs, files or versions "
                    "that are not listed. If the list is empty or only informational, say no "
                    "confirmed issues requiring remediation were found."
                )},
            ],
        )
        ledger.record_event(db, scope.run_id, "remediation.drafted",
                            {"confirmed": len(confirmed),
                             "source": "model" if used else "deterministic",
                             **diag})
        return {"phase": "report", "remediation_text": text,
                "log": [f"remediate: guidance for {len(confirmed)} finding(s) "
                        f"({'model' if used else 'deterministic'})"]}

    def report(state: EngagementState) -> dict:
        candidates = phases.candidate_ids_for_run(db, scope.run_id)
        confirmed = phases.confirmed_ids_for_run(db, scope.run_id)
        brief = findings_brief(db, scope.run_id)
        summary, used, diag = draft_and_audit(
            db=db, run_id=scope.run_id, gateway=gateway, manifest=REPORTING,
            record_model_calls=record_model_calls,
            messages=[
                {"role": "system", "content": _GROUNDED_SYSTEM},
                {"role": "user", "content": (
                    f"Source assessment: {len(candidates)} candidate and {len(confirmed)} confirmed "
                    f"finding(s). The ONLY findings are:\n{brief or '(none)'}\n\n"
                    "Write a 3-4 sentence executive summary describing ONLY what is listed. "
                    "Do not invent findings, CVEs, files or versions. If nothing of note was "
                    "confirmed, say the assessment found no confirmed issues."
                )},
            ],
        )
        report = build_report(db, scope.run_id, summary=summary,
                              remediation=state.get("remediation_text", ""),
                              title="White-box source assessment")
        ledger.record_event(db, scope.run_id, "report.generated",
                            {"report_id": report.id, "candidates": len(candidates),
                             "confirmed": len(confirmed),
                             "summary": "model" if used else "deterministic",
                             **diag})
        return {"phase": "report", "report_ref": report.id,
                "log": [f"report: generated ({'model' if used else 'deterministic'} summary)"]}

    graph = StateGraph(EngagementState)
    graph.add_node("intake", intake)
    graph.add_node("analyze", analyze)
    graph.add_node("validate", validate)
    graph.add_node("remediate", remediate)
    graph.add_node("report", report)

    graph.add_edge(START, "intake")
    # Intake routes to analyze, or straight to report when there is no bundle.
    graph.add_conditional_edges(
        "intake", lambda s: "report" if s.get("phase") == "report" else "analyze",
        {"analyze": "analyze", "report": "report"},
    )
    graph.add_conditional_edges("analyze", _analyze_router, {"analyze": "analyze", "validate": "validate"})
    graph.add_edge("validate", "remediate")
    graph.add_edge("remediate", "report")
    graph.add_edge("report", END)

    return graph.compile(checkpointer=checkpointer)
