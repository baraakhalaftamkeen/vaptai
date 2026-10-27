"""Enumerations shared across the platform.

These encode the invariants from the V2 plan: engagement modes, the deny-by-default
policy classes (P0-P3), run lifecycle, and the separation of a candidate finding
from an independently validated one.
"""
from __future__ import annotations

from enum import StrEnum


class Role(StrEnum):
    """Project-level RBAC roles."""

    ADMIN = "admin"
    LEAD = "lead"           # product owner / lead pentester; can approve high-risk
    ANALYST = "analyst"     # runs engagements
    REVIEWER = "reviewer"   # approves / signs off reports
    VIEWER = "viewer"       # read-only


class TestingMode(StrEnum):
    BLACK_BOX = "black_box"
    GRAY_BOX = "gray_box"
    WHITE_BOX = "white_box"


class TargetType(StrEnum):
    WEB = "web"
    NETWORK = "network"
    SOURCE = "source"        # white-box source bundle


class RunStatus(StrEnum):
    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    PAUSED = "paused"            # interrupted, waiting on approval
    AWAITING_APPROVAL = "awaiting_approval"
    CANCELLING = "cancelling"
    CANCELLED = "cancelled"
    COMPLETED = "completed"
    FAILED = "failed"


class PolicyClass(StrEnum):
    """Action risk classes. Classified by profile/arguments, never by tool name alone."""

    P0_PASSIVE = "p0_passive"          # passive / local read -> auto-allow in data rules
    P1_LOW_IMPACT = "p1_low_impact"    # bounded active -> auto-allow within signed profile
    P2_INTRUSIVE = "p2_intrusive"      # intrusive validation -> explicit approval
    P3_EXCLUDED = "p3_excluded"        # excluded in beta -> deny, no ordinary bypass


class PolicyDecision(StrEnum):
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"


class ApprovalState(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    APPROVED_BATCH = "approved_batch"
    REJECTED = "rejected"
    EXPIRED = "expired"
    CHANGES_REQUESTED = "changes_requested"


class FindingStatus(StrEnum):
    CANDIDATE = "candidate"          # scanner observation, not yet validated
    CONFIRMED = "confirmed"          # independently validated
    FALSE_POSITIVE = "false_positive"
    INCONCLUSIVE = "inconclusive"
    UNVERIFIED_LEGACY = "unverified_legacy"  # imported V1 AI-only finding


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AgentRole(StrEnum):
    """The seven specialized agent roles."""

    PLANNING = "planning"
    RECON = "recon"
    SCAN = "scan"
    VALIDATE = "validate"
    ATTACK = "attack"              # narrow approved PoC playbooks only
    REMEDIATION = "remediation"
    REPORTING = "reporting"
