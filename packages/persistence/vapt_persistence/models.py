"""Additive MariaDB schema (plan §10) — Week 1 subset.

Covers identity/projects, engagements/scope/assets, runs/tasks/run_events/outbox,
tool action ledger, policy decisions, approvals, findings, artifacts, model profiles.
Tables not yet exercised by the API are still defined so migrations are complete
and the ledger/approval guarantees have a home from day one.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    CHAR,
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, created_column, pk_column, updated_column


# --------------------------------------------------------------------------- #
# Identity & projects
# --------------------------------------------------------------------------- #
class Project(Base):
    __tablename__ = "projects"

    id: Mapped[str] = pk_column()
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    created_at: Mapped[datetime] = created_column()

    memberships: Mapped[list[Membership]] = relationship(back_populates="project")
    engagements: Mapped[list[Engagement]] = relationship(back_populates="project")


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = pk_column()
    username: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    email: Mapped[str | None] = mapped_column(String(255), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)  # Argon2id
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = created_column()

    memberships: Mapped[list[Membership]] = relationship(back_populates="user")
    sessions: Mapped[list[AuthSession]] = relationship(back_populates="user")


class Membership(Base):
    __tablename__ = "memberships"
    __table_args__ = (UniqueConstraint("project_id", "user_id", name="uq_project_user"),)

    id: Mapped[str] = pk_column()
    project_id: Mapped[str] = mapped_column(CHAR(36), ForeignKey("projects.id"), index=True)
    user_id: Mapped[str] = mapped_column(CHAR(36), ForeignKey("users.id"), index=True)
    role: Mapped[str] = mapped_column(String(20), nullable=False)  # domain.Role

    project: Mapped[Project] = relationship(back_populates="memberships")
    user: Mapped[User] = relationship(back_populates="memberships")


class AuthSession(Base):
    """Server-side revocable session (replaces V1 self-signed tokens)."""

    __tablename__ = "auth_sessions"

    id: Mapped[str] = pk_column()
    user_id: Mapped[str] = mapped_column(CHAR(36), ForeignKey("users.id"), index=True)
    token_hash: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    created_at: Mapped[datetime] = created_column()
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)

    user: Mapped[User] = relationship(back_populates="sessions")


# --------------------------------------------------------------------------- #
# Engagements, scope, assets
# --------------------------------------------------------------------------- #
class Engagement(Base):
    __tablename__ = "engagements"

    id: Mapped[str] = pk_column()
    project_id: Mapped[str] = mapped_column(CHAR(36), ForeignKey("projects.id"), index=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    testing_mode: Mapped[str] = mapped_column(String(20), nullable=False)
    target_type: Mapped[str] = mapped_column(String(20), nullable=False)
    scope_version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = created_column()

    project: Mapped[Project] = relationship(back_populates="engagements")
    scope_versions: Mapped[list[ScopeVersion]] = relationship(back_populates="engagement")
    runs: Mapped[list[Run]] = relationship(back_populates="engagement")


class ScopeVersion(Base):
    __tablename__ = "scope_versions"
    __table_args__ = (UniqueConstraint("engagement_id", "version", name="uq_engagement_scope_ver"),)

    id: Mapped[str] = pk_column()
    engagement_id: Mapped[str] = mapped_column(CHAR(36), ForeignKey("engagements.id"), index=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    scope: Mapped[dict] = mapped_column(JSON, nullable=False)  # ScopeInput serialized
    created_at: Mapped[datetime] = created_column()

    engagement: Mapped[Engagement] = relationship(back_populates="scope_versions")


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[str] = pk_column()
    engagement_id: Mapped[str] = mapped_column(CHAR(36), ForeignKey("engagements.id"), index=True)
    identifier: Mapped[str] = mapped_column(String(500), nullable=False)
    kind: Mapped[str] = mapped_column(String(50), nullable=False)  # domain/ip/url
    approved: Mapped[bool] = mapped_column(Boolean, default=False)  # proposed until established
    created_at: Mapped[datetime] = created_column()


# --------------------------------------------------------------------------- #
# Runs, tasks, events, outbox
# --------------------------------------------------------------------------- #
class Run(Base):
    __tablename__ = "runs"

    id: Mapped[str] = pk_column()
    engagement_id: Mapped[str] = mapped_column(CHAR(36), ForeignKey("engagements.id"), index=True)
    thread_id: Mapped[str] = mapped_column(CHAR(36), nullable=False)  # LangGraph thread
    status: Mapped[str] = mapped_column(String(30), default="pending", index=True)
    phase: Mapped[str | None] = mapped_column(String(50))
    # A retest run links to the prior run it re-checks, so fixes can be compared (BAR-29).
    retest_of: Mapped[str | None] = mapped_column(CHAR(36), ForeignKey("runs.id"), index=True)
    cancellation_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    # Operator-opt-in auto-approve: when true, every approval the harness creates for this
    # run is immediately auto-decided (approved, by="auto-approve"). Audit trail stays
    # intact — approval.decided events still fire, approvals still exist in the DB, policy
    # scope checks still run on the actual action. ONLY for lab/testing targets; a run
    # with auto_approve=True on a production engagement is a self-inflicted wound and the
    # UI tags it with a warning badge.
    auto_approve: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    version: Mapped[int] = mapped_column(Integer, default=1)  # optimistic lock
    created_at: Mapped[datetime] = created_column()
    updated_at: Mapped[datetime] = updated_column()

    engagement: Mapped[Engagement] = relationship(back_populates="runs")
    events: Mapped[list[RunEvent]] = relationship(back_populates="run")
    findings: Mapped[list[Finding]] = relationship(back_populates="run")


class Task(Base):
    __tablename__ = "tasks"

    id: Mapped[str] = pk_column()
    run_id: Mapped[str] = mapped_column(CHAR(36), ForeignKey("runs.id"), index=True)
    agent_role: Mapped[str] = mapped_column(String(30), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(30), default="pending")
    created_at: Mapped[datetime] = created_column()


class RunEvent(Base):
    """Monotonic, replayable run events (back SSE with Last-Event-ID)."""

    __tablename__ = "run_events"
    __table_args__ = (UniqueConstraint("run_id", "seq", name="uq_run_event_seq"),)

    id: Mapped[str] = pk_column()
    run_id: Mapped[str] = mapped_column(CHAR(36), ForeignKey("runs.id"), index=True)
    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    kind: Mapped[str] = mapped_column(String(50), nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = created_column()

    run: Mapped[Run] = relationship(back_populates="events")


class Outbox(Base):
    """Transactional outbox: queue delivery can be retried without creating another run."""

    __tablename__ = "outbox"

    id: Mapped[str] = pk_column()
    run_id: Mapped[str] = mapped_column(CHAR(36), ForeignKey("runs.id"), index=True)
    topic: Mapped[str] = mapped_column(String(100), nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    delivered: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    created_at: Mapped[datetime] = created_column()


# --------------------------------------------------------------------------- #
# Action ledger, leases, policy, approvals
# --------------------------------------------------------------------------- #
class ToolActionRecord(Base):
    __tablename__ = "tool_actions"
    __table_args__ = (UniqueConstraint("idempotency_key", name="uq_tool_action_idem"),)

    id: Mapped[str] = pk_column()
    run_id: Mapped[str] = mapped_column(CHAR(36), ForeignKey("runs.id"), index=True)
    tool_id: Mapped[str] = mapped_column(String(100), nullable=False)
    profile_id: Mapped[str] = mapped_column(String(100), nullable=False)
    args: Mapped[dict] = mapped_column(JSON, default=dict)
    target_ref: Mapped[str] = mapped_column(String(500), nullable=False)
    action_digest: Mapped[str] = mapped_column(String(128), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    policy_class: Mapped[str] = mapped_column(String(20), nullable=False)
    state: Mapped[str] = mapped_column(String(30), default="proposed")  # proposed/authorized/executed
    created_at: Mapped[datetime] = created_column()


class ExecutionLease(Base):
    __tablename__ = "execution_leases"

    id: Mapped[str] = pk_column()
    run_id: Mapped[str] = mapped_column(CHAR(36), ForeignKey("runs.id"), index=True, unique=True)
    holder: Mapped[str] = mapped_column(String(100), nullable=False)
    acquired_at: Mapped[datetime] = created_column()
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class PolicyDecisionRecord(Base):
    __tablename__ = "policy_decisions"

    id: Mapped[str] = pk_column()
    run_id: Mapped[str] = mapped_column(CHAR(36), ForeignKey("runs.id"), index=True)
    action_digest: Mapped[str] = mapped_column(String(128), nullable=False)
    policy_version: Mapped[str] = mapped_column(String(50), nullable=False)
    decision: Mapped[str] = mapped_column(String(30), nullable=False)
    reason: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = created_column()


class Approval(Base):
    __tablename__ = "approvals"

    id: Mapped[str] = pk_column()
    run_id: Mapped[str] = mapped_column(CHAR(36), ForeignKey("runs.id"), index=True)
    action_digest: Mapped[str] = mapped_column(String(128), nullable=False)
    policy_class: Mapped[str] = mapped_column(String(20), nullable=False)
    state: Mapped[str] = mapped_column(String(30), default="pending", index=True)
    requested_by: Mapped[str | None] = mapped_column(CHAR(36))
    decided_by: Mapped[str | None] = mapped_column(CHAR(36))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = created_column()


# --------------------------------------------------------------------------- #
# Findings, artifacts, reports
# --------------------------------------------------------------------------- #
class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = pk_column()
    run_id: Mapped[str] = mapped_column(CHAR(36), ForeignKey("runs.id"), index=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    status: Mapped[str] = mapped_column(String(30), default="candidate")
    severity: Mapped[str] = mapped_column(String(20), default="info")
    description: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = created_column()

    run: Mapped[Run] = relationship(back_populates="findings")
    observations: Mapped[list[FindingObservation]] = relationship(back_populates="finding")


class FindingObservation(Base):
    """Preserve observation vs interpretation; links to raw evidence artifacts."""

    __tablename__ = "finding_observations"

    id: Mapped[str] = pk_column()
    finding_id: Mapped[str] = mapped_column(CHAR(36), ForeignKey("findings.id"), index=True)
    source_tool: Mapped[str] = mapped_column(String(100), nullable=False)
    artifact_id: Mapped[str | None] = mapped_column(CHAR(36))
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = created_column()

    finding: Mapped[Finding] = relationship(back_populates="observations")


class Artifact(Base):
    __tablename__ = "artifacts"

    id: Mapped[str] = pk_column()
    run_id: Mapped[str] = mapped_column(CHAR(36), ForeignKey("runs.id"), index=True)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    mime: Mapped[str] = mapped_column(String(100), nullable=False)
    byte_length: Mapped[int] = mapped_column(Integer, nullable=False)
    producer: Mapped[str] = mapped_column(String(100), nullable=False)
    access_class: Mapped[str] = mapped_column(String(50), default="restricted")
    storage_key: Mapped[str] = mapped_column(String(500), nullable=False)
    created_at: Mapped[datetime] = created_column()


# --------------------------------------------------------------------------- #
# Model profiles & schedules
# --------------------------------------------------------------------------- #
class ModelProfile(Base):
    __tablename__ = "model_profiles"

    id: Mapped[str] = pk_column()
    profile_id: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    provider: Mapped[str] = mapped_column(String(50), nullable=False)
    model_id: Mapped[str] = mapped_column(String(100), nullable=False)
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = created_column()


class Schedule(Base):
    __tablename__ = "schedules"

    id: Mapped[str] = pk_column()
    engagement_id: Mapped[str] = mapped_column(CHAR(36), ForeignKey("engagements.id"), index=True)
    cron: Mapped[str] = mapped_column(String(100), nullable=False, default="")
    # Interval-based scheduling for the beta (cron kept for display/future). The beat
    # tick fires a schedule when now >= next_fire_at, then advances it (BAR-29).
    interval_minutes: Mapped[int | None] = mapped_column(Integer)
    next_fire_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    last_fired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = created_column()


class Report(Base):
    """A generated, evidence-linked assessment report for a run (plan §8, BAR-28).

    Unlike model_calls (counts only), the report IS the deliverable, so its rendered
    HTML, executive summary and remediation guidance are stored. A reviewer signs off a
    draft to mark it final."""

    __tablename__ = "reports"

    id: Mapped[str] = pk_column()
    run_id: Mapped[str] = mapped_column(CHAR(36), ForeignKey("runs.id"), index=True)
    fmt: Mapped[str] = mapped_column(String(10), default="html")
    status: Mapped[str] = mapped_column(String(20), default="draft")   # draft | final
    title: Mapped[str] = mapped_column(String(300), default="Assessment report")
    summary: Mapped[str] = mapped_column(Text, default="")             # executive summary
    remediation: Mapped[str] = mapped_column(Text, default="")        # remediation guidance
    content: Mapped[str] = mapped_column(Text, default="")            # rendered HTML
    stats: Mapped[dict] = mapped_column(JSON, default=dict)           # counts, coverage gaps
    generated_by: Mapped[str] = mapped_column(String(50), default="reporting-agent")
    signed_off_by: Mapped[str | None] = mapped_column(CHAR(36))
    created_at: Mapped[datetime] = created_column()
    updated_at: Mapped[datetime] = updated_column()


class SourceBundle(Base):
    """An uploaded source/repo bundle for a white-box engagement (plan §5, BAR-27).

    The archive is stored once and extracted into a per-bundle directory; static
    analyzers run against `extracted_path`. The bundle, not a network host, is the
    engagement's authorized scope, so source-analysis actions are in scope by workspace."""

    __tablename__ = "source_bundles"

    id: Mapped[str] = pk_column()
    engagement_id: Mapped[str] = mapped_column(CHAR(36), ForeignKey("engagements.id"), index=True)
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    byte_length: Mapped[int] = mapped_column(Integer, nullable=False)
    storage_key: Mapped[str] = mapped_column(String(1000), nullable=False)   # stored archive path
    extracted_path: Mapped[str | None] = mapped_column(String(1000))          # extraction dir
    file_count: Mapped[int] = mapped_column(Integer, default=0)
    uploaded_by: Mapped[str | None] = mapped_column(CHAR(36))
    created_at: Mapped[datetime] = created_column()


class ModelCall(Base):
    """Every gateway invocation, for audit, cost accounting and reproducibility.

    Prompts/outputs are NOT stored verbatim — only counts, the profile, finish reason,
    latency and a trace id. Keeping raw model I/O out of the ledger avoids persisting
    secrets or engagement content on a hosted-profile boundary (plan §9)."""

    __tablename__ = "model_calls"

    id: Mapped[str] = pk_column()
    run_id: Mapped[str | None] = mapped_column(CHAR(36), ForeignKey("runs.id"), index=True)
    profile_id: Mapped[str] = mapped_column(String(100), nullable=False)
    provider: Mapped[str] = mapped_column(String(50), nullable=False)
    model_id: Mapped[str] = mapped_column(String(100), nullable=False)
    agent_id: Mapped[str | None] = mapped_column(String(100))        # which manifest asked
    prompt_version: Mapped[str | None] = mapped_column(String(50))
    data_class: Mapped[str] = mapped_column(String(50), default="standard")
    finish_reason: Mapped[str] = mapped_column(String(30), default="stop")
    prompt_tokens: Mapped[int] = mapped_column(Integer, default=0)
    completion_tokens: Mapped[int] = mapped_column(Integer, default=0)
    total_tokens: Mapped[int] = mapped_column(Integer, default=0)
    latency_ms: Mapped[int] = mapped_column(Integer, default=0)
    trace_id: Mapped[str | None] = mapped_column(String(100))
    error: Mapped[str | None] = mapped_column(Text)                  # redacted before storage
    created_at: Mapped[datetime] = created_column()


# --------------------------------------------------------------------------- #
# Durable LangGraph checkpoint store (plan §6, §8 — the Week 1-3 spike).
# Mirrors LangGraph's InMemorySaver storage model across three tables so a paused
# run survives a worker restart and resumes on the same thread.
# --------------------------------------------------------------------------- #
class GraphCheckpoint(Base):
    __tablename__ = "graph_checkpoints"
    __table_args__ = (
        UniqueConstraint(
            "thread_id", "checkpoint_ns", "checkpoint_id", name="uq_graph_ckpt"
        ),
    )

    id: Mapped[str] = pk_column()
    thread_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    checkpoint_ns: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    checkpoint_id: Mapped[str] = mapped_column(String(64), nullable=False)
    parent_checkpoint_id: Mapped[str | None] = mapped_column(String(64))
    type: Mapped[str] = mapped_column(String(40), nullable=False)       # serde type tag
    checkpoint: Mapped[bytes] = mapped_column(LargeBinary(length=16_000_000), nullable=False)
    metadata_type: Mapped[str] = mapped_column(String(40), nullable=False)
    checkpoint_metadata: Mapped[bytes] = mapped_column(LargeBinary(length=16_000_000), nullable=False)
    created_at: Mapped[datetime] = created_column()


class GraphCheckpointBlob(Base):
    """Per-channel values, keyed by (thread, ns, channel, version) exactly as
    LangGraph's saver stores them so large channel payloads are written once per version."""

    __tablename__ = "graph_checkpoint_blobs"
    __table_args__ = (
        UniqueConstraint(
            "thread_id", "checkpoint_ns", "channel", "version", name="uq_graph_blob"
        ),
    )

    id: Mapped[str] = pk_column()
    thread_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    checkpoint_ns: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    channel: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str] = mapped_column(String(64), nullable=False)
    type: Mapped[str] = mapped_column(String(40), nullable=False)
    blob: Mapped[bytes | None] = mapped_column(LargeBinary(length=16_000_000))


class GraphCheckpointWrite(Base):
    """Pending writes for a checkpoint (interrupts, partial task output), keyed by
    (thread, ns, checkpoint, task, idx) so a resume replays them without duplication."""

    __tablename__ = "graph_checkpoint_writes"
    __table_args__ = (
        UniqueConstraint(
            "thread_id", "checkpoint_ns", "checkpoint_id", "task_id", "idx",
            name="uq_graph_write",
        ),
    )

    id: Mapped[str] = pk_column()
    thread_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    checkpoint_ns: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    checkpoint_id: Mapped[str] = mapped_column(String(64), nullable=False)
    task_id: Mapped[str] = mapped_column(String(64), nullable=False)
    idx: Mapped[int] = mapped_column(Integer, nullable=False)
    channel: Mapped[str] = mapped_column(String(255), nullable=False)
    type: Mapped[str] = mapped_column(String(40), nullable=False)
    blob: Mapped[bytes] = mapped_column(LargeBinary(length=16_000_000), nullable=False)
    task_path: Mapped[str] = mapped_column(String(255), default="")
