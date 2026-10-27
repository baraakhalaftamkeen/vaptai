"""The bounded description of what a single run may touch.

Factored into its own module so both the sequential pipeline and the graph nodes can
import it without a circular dependency (phases <-> web_network)."""
from __future__ import annotations

from dataclasses import dataclass

from vapt_domain.enums import PolicyClass, TestingMode


@dataclass
class RunScope:
    run_id: str
    testing_mode: TestingMode
    target: str
    domains: list[str]
    ip_cidrs: list[str]
    allowed_action_classes: list[PolicyClass]
    signed_profile: bool = True  # lab engagements sign a profile that pre-approves P1
    # Port scope carried to the nmap -p argument ("80,443,8080" or "1-65535"). Empty
    # means the scan uses its default service set. Validated at intake (ScopeInput).
    allowed_ports: str = ""
    # Opt-in exploitation: the attack agent runs PoC playbooks ONLY when this is set,
    # and even then every PoC action is forced through human approval. Off by default.
    allow_exploitation: bool = False
    # Which named PoC playbook the attack agent runs (see vapt_agents.playbooks).
    poc_playbook: str = "http_evidence"
    # Optional workspace-relative path to an exported .nessus file to import as external
    # authenticated-scanner intel (None = none supplied). Tenable.sc live intel is separate
    # and gated on the VAPT_TENABLE_* env vars, not this field.
    nessus_path: str | None = None
