"""Approved PoC playbooks (plan §5, §8, BAR-30).

A playbook is a NAMED, bounded proof-of-concept the attack agent may run against a
confirmed finding — never a free-form exploit. Each maps to exactly one registry tool
(argv-only, no shell), and every PoC action is still forced through human approval by
the ATTACK manifest regardless of its policy class. Playbooks are the only exploitation
the platform will perform, and only when the engagement explicitly opts in.

Keep this list tight and reviewed: adding a playbook is a deliberate expansion of what
the attack agent can even propose."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Playbook:
    id: str
    title: str
    description: str
    tool_id: str          # a registry tool allowed for the ATTACK agent


PLAYBOOKS: dict[str, Playbook] = {
    "http_evidence": Playbook(
        id="http_evidence",
        title="HTTP evidence capture",
        description="Issue one approved request via the Burp MCP proxy and capture the "
                    "response as evidence. Read/request only — no modification.",
        tool_id="burp_request",
    ),
    "screenshot": Playbook(
        id="screenshot",
        title="Screenshot capture",
        description="Capture a screenshot of the confirmed issue as visual PoC evidence "
                    "(V1 poc_screenshot). Bounded, single-shot.",
        tool_id="poc_screenshot",
    ),
}

DEFAULT_PLAYBOOK = "http_evidence"


def get_playbook(playbook_id: str | None) -> Playbook:
    """Resolve a playbook id to its definition, falling back to the default when unset
    or unknown (the model/engagement can never invent a playbook or its tool)."""
    return PLAYBOOKS.get(playbook_id or DEFAULT_PLAYBOOK, PLAYBOOKS[DEFAULT_PLAYBOOK])
