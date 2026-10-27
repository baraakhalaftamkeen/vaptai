"""Deterministic, deny-by-default policy engine (plan §7).

This is ordinary application code, never a model prompt. It classifies an action by
its resolved profile/arguments and context — not by tool name alone — and returns
allow / require_approval / deny. A model can never widen this decision.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from vapt_domain.enums import PolicyClass, PolicyDecision, TestingMode


@dataclass
class PolicyInput:
    policy_class: PolicyClass
    tool_id: str
    profile_id: str
    target_ref: str
    testing_mode: TestingMode
    allowed_action_classes: list[PolicyClass]
    in_scope: bool
    resolved_addresses: list[str] = field(default_factory=list)
    signed_profile: bool = False       # engagement profile pre-approves P1
    policy_version: str = "v1"


@dataclass
class PolicyResult:
    decision: PolicyDecision
    reason: str
    policy_version: str = "v1"


# Addresses that must never be reachable regardless of scope wording.
_FORBIDDEN_ADDRESS_MARKERS = ("169.254.169.254", "metadata.google", "metadata.")


class PolicyEngine:
    def evaluate(self, pi: PolicyInput) -> PolicyResult:
        # 1. Scope is absolute. Out of scope -> deny, no approval path.
        if not pi.in_scope:
            return PolicyResult(PolicyDecision.DENY, "target not in approved scope", pi.policy_version)

        # 2. Cloud metadata / management endpoints are always denied.
        for addr in pi.resolved_addresses:
            if any(marker in addr for marker in _FORBIDDEN_ADDRESS_MARKERS):
                return PolicyResult(
                    PolicyDecision.DENY, f"forbidden address {addr}", pi.policy_version
                )

        # 3. P3 is excluded in beta; no ordinary approval bypass.
        if pi.policy_class == PolicyClass.P3_EXCLUDED:
            return PolicyResult(
                PolicyDecision.DENY, "P3 excluded action class", pi.policy_version
            )

        # 4. The class must be permitted by the signed engagement scope.
        if pi.policy_class not in pi.allowed_action_classes:
            # P2 can still be requested via explicit approval even if not pre-allowed.
            if pi.policy_class == PolicyClass.P2_INTRUSIVE:
                return PolicyResult(
                    PolicyDecision.REQUIRE_APPROVAL,
                    "P2 intrusive action requires explicit approval",
                    pi.policy_version,
                )
            return PolicyResult(
                PolicyDecision.DENY,
                f"action class {pi.policy_class.value} not permitted by scope",
                pi.policy_version,
            )

        # 5. Decide by class.
        if pi.policy_class == PolicyClass.P0_PASSIVE:
            return PolicyResult(PolicyDecision.ALLOW, "passive/local read", pi.policy_version)

        if pi.policy_class == PolicyClass.P1_LOW_IMPACT:
            if pi.signed_profile:
                return PolicyResult(
                    PolicyDecision.ALLOW, "P1 within signed engagement profile", pi.policy_version
                )
            return PolicyResult(
                PolicyDecision.REQUIRE_APPROVAL,
                "P1 without signed profile requires approval",
                pi.policy_version,
            )

        # P2 intrusive always needs approval. White-box mode does NOT bypass this.
        return PolicyResult(
            PolicyDecision.REQUIRE_APPROVAL, "P2 intrusive validation", pi.policy_version
        )
