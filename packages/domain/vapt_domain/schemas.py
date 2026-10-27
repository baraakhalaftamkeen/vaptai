"""API-facing Pydantic contracts.

Kept deliberately small for the Week 1 foundation; richer finding / evidence
contracts arrive with the web+network pipeline (Week 3).
"""
from __future__ import annotations

import re
from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field, field_validator

# A port spec: single ports and single-hyphen ranges, comma-separated
# (e.g. "80,443,8000-8100" or "1-65535"). Mirrors the nmap adapter's own validator.
_PORT_SPEC_RE = re.compile(r"\d{1,5}(?:-\d{1,5})?(?:,\d{1,5}(?:-\d{1,5})?)*")

from .enums import (
    ApprovalState,
    FindingStatus,
    PolicyClass,
    RunStatus,
    Severity,
    TargetType,
    TestingMode,
)


# --------------------------------------------------------------------------- #
# Scope & engagement
# --------------------------------------------------------------------------- #
class ScopeInput(BaseModel):
    """Authorization boundary supplied at intake.

    A wildcard domain does NOT imply permission to scan every hosting/CDN address;
    new assets stay proposed until scope membership is established.
    """

    domains: list[str] = Field(default_factory=list)
    ip_cidrs: list[str] = Field(default_factory=list)
    url_paths: list[str] = Field(default_factory=list)
    exclusions: list[str] = Field(default_factory=list)
    # Port scope as a spec string ("80,443,8080" or "1-65535"), carried straight to the
    # nmap -p argument so the declared scope actually bounds the scan. Accepts a legacy
    # list[int] too (coerced to a spec); empty means "use the scanner's default set".
    allowed_ports: str = ""
    permitted_identities: list[str] = Field(default_factory=list)
    allowed_action_classes: list[PolicyClass] = Field(
        default_factory=lambda: [PolicyClass.P0_PASSIVE, PolicyClass.P1_LOW_IMPACT]
    )
    data_sensitivity: str = "standard"
    emergency_contact: str | None = None
    notes: str | None = None
    # Opt-in exploitation: the attack agent runs the named PoC playbook, and even then
    # every PoC action is forced through human approval (BAR-30).
    allow_exploitation: bool = False
    poc_playbook: str = "http_evidence"

    @field_validator("allowed_ports", mode="before")
    @classmethod
    def _coerce_ports(cls, v) -> str:
        # Accept a legacy list[int] (join to a spec) or a spec string; normalize to a
        # validated spec. Every individual port must be in 1..65535.
        if v is None:
            return ""
        if isinstance(v, (list, tuple)):
            parts: list[str] = []
            for p in v:
                n = int(p)
                if not 0 < n < 65536:
                    raise ValueError(f"invalid port: {p}")
                parts.append(str(n))
            return ",".join(parts)
        spec = str(v).strip()
        if not spec:
            return ""
        if not _PORT_SPEC_RE.fullmatch(spec):
            raise ValueError(f"invalid port spec: {spec!r}")
        for chunk in spec.split(","):
            for n in chunk.split("-"):
                if not 0 < int(n) < 65536:
                    raise ValueError(f"port out of range: {n}")
        return spec


class EngagementCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    testing_mode: TestingMode
    target_type: TargetType
    scope: ScopeInput


class EngagementOut(BaseModel):
    id: UUID
    project_id: UUID
    name: str
    testing_mode: TestingMode
    target_type: TargetType
    scope_version: int
    created_at: datetime

    model_config = {"from_attributes": True}


# --------------------------------------------------------------------------- #
# Runs
# --------------------------------------------------------------------------- #
class RunCreate(BaseModel):
    engagement_id: UUID
    # Opt-in auto-approve: when true, every approval the harness creates for this run is
    # auto-decided. For lab/testing only — the UI tags such runs with a warning badge.
    auto_approve: bool = False
    # Optional web-login credentials for authenticated scanning. On a NORMAL run these
    # are collected via the webvuln credentials prompt the first time wapiti needs them.
    # On an AUTO-APPROVE run that prompt never fires (approvals bypass the human gate),
    # so the operator must supply creds up-front here. Stored in Redis under the run_id
    # with the same TTL + fail-safe semantics; never persisted to SQL, never in the
    # ledger. Omit if the target has no login flow or you want an unauthenticated scan.
    web_username: str | None = None
    web_password: str | None = None
    # Optional SECOND account for IDOR / authz testing. When both this and the primary
    # web_username are set, the idor_probe tool fires in the webvuln phase: logs in as
    # BOTH accounts, requests ID-bearing URLs as each, and flags cross-tenant access.
    # Only useful on an auto-approve run (or if you also fill the webvuln creds prompt
    # with the primary set).
    web_username_b: str | None = None
    web_password_b: str | None = None
    # Optional THIRD account enabling the recommended admin + 2-user IDOR model:
    #   web_username   (primary) → admin   — unlocks /admin/* for scanning
    #   web_username_b           → user A  — IDOR source (first normal user)
    #   web_username_c           → user B  — IDOR cross-check (second normal user)
    # When present (requires _b too), idor_probe pairs B+C (two users with the same
    # role) instead of A+B (admin+user). The admin-vs-user pairing produces false
    # "legitimate access" positives on admin-only pages; B+C fixes that. If _c is
    # omitted the probe falls back to the legacy A+B behavior.
    web_username_c: str | None = None
    web_password_c: str | None = None


class RunOut(BaseModel):
    id: UUID
    engagement_id: UUID
    status: RunStatus
    phase: str | None = None
    retest_of: UUID | None = None
    auto_approve: bool = False
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


# --------------------------------------------------------------------------- #
# Findings & approvals
# --------------------------------------------------------------------------- #
class FindingOut(BaseModel):
    id: UUID
    run_id: UUID
    title: str
    status: FindingStatus
    severity: Severity
    evidence_ids: list[UUID] = Field(default_factory=list)
    created_at: datetime

    model_config = {"from_attributes": True}


class ApprovalOut(BaseModel):
    id: UUID
    run_id: UUID
    action_digest: str
    policy_class: PolicyClass
    state: ApprovalState
    expires_at: datetime | None = None
    # What the reviewer is actually approving (derived from the proposed action + ledger).
    tool_id: str | None = None
    target: str | None = None
    summary: str | None = None        # one-line "what will run"
    detail: str | None = None         # the tool's own description
    reason: str | None = None         # why approval is required
    # Authenticated web scan (Stage 2): set when a login form was detected, so the UI can
    # offer an optional "log in?" dialog. Only the non-secret login URL is surfaced here;
    # credentials go via the dedicated web-credentials endpoint, never through this schema.
    needs_web_credentials: bool = False
    login_url: str | None = None

    model_config = {"from_attributes": True}


# --------------------------------------------------------------------------- #
# Tool broker contracts
# --------------------------------------------------------------------------- #
class ToolAction(BaseModel):
    """A validated, ready-to-broker action. args are already typed & validated;
    free-form command strings are never accepted."""

    tool_id: str
    profile_id: str
    args: dict = Field(default_factory=dict)
    target_ref: str
    credential_ref: str | None = None
    action_digest: str
    idempotency_key: str


class ToolResult(BaseModel):
    outcome: str                     # ok | failed | unknown
    exit_code: int | None = None
    started_at: datetime
    finished_at: datetime
    tool_version: str | None = None
    observations: list[dict] = Field(default_factory=list)
    artifact_hashes: list[str] = Field(default_factory=list)
    redactions: list[str] = Field(default_factory=list)
