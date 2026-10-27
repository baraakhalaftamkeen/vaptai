"""Glue the broker into a tool_runner the graph can call.

The runner is the only path from an agent node to real tool execution; in later weeks
it also consults the policy engine + records the ledger entry before brokering.
"""
from __future__ import annotations

from vapt_tools import REGISTRY, ToolBroker, action_digest, idempotency_key

_broker = ToolBroker(REGISTRY)


def make_tool_runner(run_id: str):
    def _run(tool_id: str, args: dict) -> dict:
        digest = action_digest(tool_id, "default", str(args.get("target", "")), args)
        key = idempotency_key(run_id, f"{tool_id}", digest)
        result = _broker.execute(tool_id, args)
        return {
            "outcome": result.outcome,
            "evidence_ref": f"evidence:{key[:12]}",
            "action_digest": digest,
            "idempotency_key": key,
        }

    return _run
