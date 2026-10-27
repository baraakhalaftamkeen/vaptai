"""Shared helper: call the gateway under an agent manifest for a text draft and audit
the call (counts only; never prompt/output text). Degrades to ("", False) offline so a
run without an LLM still completes. Used by the remediation/reporting nodes in both the
web/network and source graphs."""
from __future__ import annotations

from vapt_agents.manifests import AgentManifest
from vapt_persistence import ledger


def draft_and_audit(
    *, db, run_id: str, gateway, manifest: AgentManifest, messages: list[dict],
    record_model_calls: bool = True,
) -> tuple[str, bool, dict]:
    """Returns (text, used_model, diag). The `diag` dict carries finish_reason / error so
    the caller's ledger event can SAY why the deterministic fallback kicked in, instead of
    silently hiding that information in an unreadable audit row."""
    if gateway is None:
        return "", False, {"reason": "no_gateway"}
    if not manifest.model_profile:
        return "", False, {"reason": "no_profile"}
    resp = gateway.invoke(manifest.model_profile, messages)
    if record_model_calls:
        ledger.record_model_call(
            db, run_id=run_id, profile_id=resp.profile_id, provider=resp.provider,
            model_id=resp.model_id, finish_reason=resp.finish_reason, usage=resp.usage,
            latency_ms=resp.latency_ms, trace_id=resp.trace_id,
            agent_id=manifest.agent_id, prompt_version=manifest.prompt_version,
            error=resp.error,
        )
    diag = {"finish_reason": resp.finish_reason, "profile": resp.profile_id,
            "model": resp.model_id, "latency_ms": resp.latency_ms}
    if resp.error:
        diag["error"] = str(resp.error)[:300]
    if resp.error or not resp.text:
        return "", False, diag
    return resp.text, True, diag
