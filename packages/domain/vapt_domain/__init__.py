"""VAPT-AI V2 shared domain models and enums.

Pure Pydantic / enum definitions with no framework or DB coupling, so they can be
imported by the API, the orchestrator and the workers alike.
"""
from .enums import (
    AgentRole,
    ApprovalState,
    FindingStatus,
    PolicyClass,
    PolicyDecision,
    Role,
    RunStatus,
    Severity,
    TargetType,
    TestingMode,
)
from .schemas import (
    ApprovalOut,
    EngagementCreate,
    EngagementOut,
    FindingOut,
    RunCreate,
    RunOut,
    ScopeInput,
    ToolAction,
    ToolResult,
)

__all__ = [
    "Role",
    "TestingMode",
    "TargetType",
    "RunStatus",
    "PolicyClass",
    "PolicyDecision",
    "ApprovalState",
    "FindingStatus",
    "Severity",
    "AgentRole",
    "ScopeInput",
    "EngagementCreate",
    "EngagementOut",
    "RunCreate",
    "RunOut",
    "FindingOut",
    "ApprovalOut",
    "ToolAction",
    "ToolResult",
]
