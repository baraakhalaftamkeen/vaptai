"""Approval inbox + decision endpoints (plan §8).

An approval binds to a run + action digest + policy version + expiry. Decisions are
bound to authorized reviewers (lead/reviewer/admin). For high-risk (P2) actions the
initiator may not approve their own request. A rejected/expired approval never resumes
execution as approved. Decisions use a transactional compare-and-set on state to
prevent duplicate decisions.
"""
from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session
from vapt_domain.enums import ApprovalState, PolicyClass, Role, RunStatus
from vapt_domain.schemas import ApprovalOut
from vapt_persistence import ledger, web_credentials
from vapt_persistence.models import Approval, Engagement, Outbox, Run, ToolActionRecord

from ..deps import CurrentUser, get_current_user, get_db, require_project_role

router = APIRouter(prefix="/api/v2/approvals", tags=["approvals"])

# PoC/attack tools: approval here authorizes an action AGAINST the target, so the
# reviewer is told plainly.
_POC_TOOLS = {"burp_request", "poc_screenshot"}


def _enrich(db: Session, appr: Approval) -> ApprovalOut:
    """Attach 'what will actually run' to an approval by joining the proposed action
    (ToolActionRecord) on the same action digest, so a reviewer can decide from the card
    itself instead of digging through the ledger."""
    out = ApprovalOut.model_validate(appr)
    rec = db.execute(
        select(ToolActionRecord)
        .where(ToolActionRecord.run_id == appr.run_id,
               ToolActionRecord.action_digest == appr.action_digest)
        .order_by(ToolActionRecord.created_at.desc())
    ).scalars().first()
    if rec is None:
        return out

    args = rec.args or {}
    target = rec.target_ref
    # Compose a readable target URL for HTTP-ish tools.
    if rec.tool_id in _POC_TOOLS or rec.tool_id == "http_probe":
        scheme = str(args.get("scheme") or ("http" if rec.tool_id in _POC_TOOLS else "https"))
        port = args.get("port")
        target = f"{scheme}://{rec.target_ref}" + (f":{port}" if port else "")
    elif args.get("ports"):
        target = f"{rec.target_ref}:{args['ports']}"

    try:
        from vapt_tools import REGISTRY
        detail = REGISTRY.get(rec.tool_id).description
    except Exception:
        detail = None

    out.tool_id = rec.tool_id
    out.target = target
    out.detail = detail
    if rec.tool_id in _POC_TOOLS:
        verb = "Capture a screenshot of" if rec.tool_id == "poc_screenshot" else "Send one read-only request to"
        out.summary = f"{verb} {target} via {rec.tool_id}"
        out.reason = "Proof-of-concept action against the target — always requires human approval."
    else:
        out.summary = f"Run {rec.tool_id} against {target}"
        out.reason = ("Intrusive action — requires approval."
                      if appr.policy_class == PolicyClass.P2_INTRUSIVE.value
                      else "Action is gated for this engagement — requires approval.")
    # Authenticated scanning (Stage 2): an active web scan that discovered a login form can
    # take optional login credentials, so the UI offers a "log in?" dialog. Only the hint and
    # the non-secret login URL are surfaced; credentials go via the web-credentials endpoint.
    #
    # Prompt ONCE per run — subsequent wapiti plan items (one per discovered endpoint) must
    # reuse the credentials the operator already provided. If creds are already in the Redis
    # slot we don't surface `needs_web_credentials`, so the dock just shows a normal approval
    # instead of re-asking for a password.
    if rec.tool_id == "wapiti" and args.get("login_url"):
        if web_credentials.get_web_credentials(appr.run_id) is None:
            out.needs_web_credentials = True
            out.login_url = str(args["login_url"])
    return out


class DecisionRequest(BaseModel):
    decision: str  # approve | approve_batch | reject | request_changes


def _run_and_project(db: Session, run_id: str) -> tuple[Run, str]:
    run = db.get(Run, run_id)
    if run is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "run not found")
    eng = db.get(Engagement, run.engagement_id)
    return run, eng.project_id


@router.get("", response_model=list[ApprovalOut])
def list_approvals(
    run_id: str | None = None,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> list[Approval]:
    stmt = select(Approval).where(Approval.state == ApprovalState.PENDING.value)
    if run_id:
        stmt = stmt.where(Approval.run_id == run_id)
    approvals = db.execute(stmt).scalars().all()
    # Filter to approvals the user can see (project membership), enriching each with what
    # will actually run.
    visible = []
    for a in approvals:
        _, project_id = _run_and_project(db, a.run_id)
        if user.role_in(project_id):
            visible.append(_enrich(db, a))
    return visible


@router.post("/{approval_id}/decision", response_model=ApprovalOut)
def decide(
    approval_id: str,
    body: DecisionRequest,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> Approval:
    appr = db.get(Approval, approval_id)
    if appr is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "approval not found")

    # Lock the run row for the duration of this decision so two decisions on the same run
    # (the dock and the Approvals page both poll + submit) can't race on the run-event
    # sequence (uq_run_event_seq). On MariaDB this serializes; on SQLite it's a no-op.
    run = db.query(Run).filter(Run.id == appr.run_id).with_for_update().first()
    if run is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "run not found")
    eng = db.get(Engagement, run.engagement_id)
    project_id = eng.project_id
    # Only lead/reviewer/admin decide approvals.
    require_project_role(project_id, user, Role.LEAD, Role.REVIEWER)

    # Compare-and-set: only a still-pending approval can be decided. Re-read under the lock.
    db.refresh(appr)
    if appr.state != ApprovalState.PENDING.value:
        raise HTTPException(status.HTTP_409_CONFLICT, f"approval already {appr.state}")

    # Expiry check.
    if appr.expires_at and appr.expires_at.replace(tzinfo=UTC) < datetime.now(UTC):
        appr.state = ApprovalState.EXPIRED.value
        db.commit()
        raise HTTPException(status.HTTP_409_CONFLICT, "approval expired")

    # High-risk (P2): initiator may not approve their own request.
    decision = body.decision.lower()
    if decision in ("approve", "approve_batch") and appr.policy_class == PolicyClass.P2_INTRUSIVE.value:
        if appr.requested_by and appr.requested_by == user.id:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "initiator may not approve their own high-risk request",
            )

    mapping = {
        "approve": ApprovalState.APPROVED,
        "approve_batch": ApprovalState.APPROVED_BATCH,
        "reject": ApprovalState.REJECTED,
        "request_changes": ApprovalState.CHANGES_REQUESTED,
    }
    if decision not in mapping:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"bad decision {decision!r}")

    appr.state = mapping[decision].value
    appr.decided_by = user.id

    ledger.record_event(
        db, appr.run_id,
        "approval.decided",
        {"approval_id": appr.id, "decision": appr.state, "by": user.id, "digest": appr.action_digest},
    )

    # Drive the run forward by resuming its paused graph. Both an approval and a
    # rejection must resume the thread: approve → the action executes; reject → the
    # graph records a coverage gap and continues. The resume intent is written to the
    # transactional outbox in THIS transaction, so it is durable and the relay delivers
    # it to the orchestrator (run.resume → resume_run) at-least-once.
    _TERMINAL = {RunStatus.COMPLETED.value, RunStatus.CANCELLED.value, RunStatus.FAILED.value}
    if decision in ("approve", "approve_batch", "reject") and run.status not in _TERMINAL:
        run.status = RunStatus.QUEUED.value  # queued for the orchestrator to resume
        db.add(Outbox(
            run_id=run.id, topic="run.resume",
            payload={"run_id": run.id, "decision": decision},
        ))
    # request_changes leaves the run paused for the analyst to revise; no resume.

    db.commit()
    db.refresh(appr)
    return _enrich(db, appr)


class WebCredentialsRequest(BaseModel):
    """Credentials for the login-dialog. Fields:
      * username / password     — PRIMARY account (admin recommended; required)
      * username_b / password_b — second account (optional; enables IDOR)
      * username_c / password_c — third account (optional; enables the 3-account
                                  IDOR model where primary=admin + two normal users)

    The three-account layout (admin + 2 normal users) is the preferred shape for
    apps that have real cross-tenant resources (orders, invoices, messages). The
    idor_probe pairs the two normal users (B+C) so admin-vs-user noise doesn't
    inflate the finding count. With only A+B (legacy) the probe falls back to
    admin-vs-user comparison.
    """
    username: str
    password: str
    username_b: str | None = None
    password_b: str | None = None
    username_c: str | None = None
    password_c: str | None = None


@router.post("/{approval_id}/web-credentials", status_code=status.HTTP_204_NO_CONTENT)
def submit_web_credentials(
    approval_id: str,
    body: WebCredentialsRequest,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> None:
    """Attach web-login credentials to a pending authenticated-scan approval so the run can
    log in with them. The credentials go ONLY to the ephemeral Redis slot (short TTL, keyed
    by run) — never to the approval record, the outbox, the checkpoint, or any durable store.
    Call this (optionally) BEFORE approving the scan; skip it to scan unauthenticated. The
    webvuln node consumes the slot at scan time and clears it when the phase ends. Only the
    fact that credentials were provided (not the credentials) is written to the audit ledger."""
    appr = db.get(Approval, approval_id)
    if appr is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "approval not found")
    _, project_id = _run_and_project(db, appr.run_id)
    require_project_role(project_id, user, Role.LEAD, Role.REVIEWER)
    if appr.state != ApprovalState.PENDING.value:
        raise HTTPException(status.HTTP_409_CONFLICT, f"approval already {appr.state}")

    # Confirm this approval really is an authenticated web scan (a login form was detected),
    # so credentials can't be stashed against an unrelated action.
    rec = db.execute(
        select(ToolActionRecord)
        .where(ToolActionRecord.run_id == appr.run_id,
               ToolActionRecord.action_digest == appr.action_digest)
        .order_by(ToolActionRecord.created_at.desc())
    ).scalars().first()
    login_url = (rec.args or {}).get("login_url") if rec else None
    if not (rec and rec.tool_id == "wapiti" and login_url):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "approval is not an authenticated web scan")

    try:
        web_credentials.set_web_credentials(appr.run_id, body.username, body.password)
        provided_b = False
        provided_c = False
        if body.username_b and body.password_b:
            web_credentials.set_web_credentials_b(
                appr.run_id, body.username_b, body.password_b)
            provided_b = True
        if body.username_c and body.password_c and provided_b:
            web_credentials.set_web_credentials_c(
                appr.run_id, body.username_c, body.password_c)
            provided_c = True
    except ValueError as e:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(e))
    except Exception:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                            "credential store unavailable; credentials not saved")

    # Audit WHO provided credentials for which login — never the credentials themselves.
    ledger.record_event(
        db, appr.run_id, "webvuln.credentials_provided",
        {"approval_id": appr.id, "by": user.id, "login_url": str(login_url),
         "accounts": ("A+B+C" if provided_c else ("A+B" if provided_b else "A"))},
    )
    db.commit()
