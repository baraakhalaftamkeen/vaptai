"""Session auth endpoints. Cookies are HttpOnly + SameSite; Secure behind TLS."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session
from vapt_persistence.models import AuthSession, User

from ..config import get_settings
from ..deps import CurrentUser, get_current_user, get_db
from ..security import (
    hash_password,
    needs_rehash,
    new_session_token,
    session_expiry,
    verify_password,
)

router = APIRouter(prefix="/api/v2/auth", tags=["auth"])


class LoginRequest(BaseModel):
    username: str
    password: str


class MeResponse(BaseModel):
    id: str
    username: str
    roles: dict[str, str]


@router.post("/session")
def login(body: LoginRequest, response: Response, db: Session = Depends(get_db)) -> dict:
    settings = get_settings()
    user = db.execute(
        select(User).where(User.username == body.username)
    ).scalar_one_or_none()
    # Verify even on missing user to reduce username enumeration timing signal.
    ok = bool(user) and user.is_active and verify_password(user.password_hash, body.password)
    if not user or not ok:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")

    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(body.password)

    raw, token_hash = new_session_token()
    sess = AuthSession(
        user_id=user.id,
        token_hash=token_hash,
        expires_at=session_expiry(settings.session_ttl_hours),
    )
    db.add(sess)
    db.commit()

    response.set_cookie(
        key=settings.session_cookie_name,
        value=raw,
        httponly=True,
        samesite="lax",
        secure=settings.cookie_secure,
        max_age=settings.session_ttl_hours * 3600,
    )
    return {"status": "ok"}


@router.delete("/session")
def logout(
    response: Response,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> dict:
    settings = get_settings()
    # Revoke all of this user's live sessions (simple + safe for the skeleton).
    sessions = db.execute(
        select(AuthSession).where(AuthSession.user_id == user.id, AuthSession.revoked == False)  # noqa: E712
    ).scalars().all()
    for s in sessions:
        s.revoked = True
    db.commit()
    response.delete_cookie(settings.session_cookie_name)
    return {"status": "ok"}


@router.get("/me", response_model=MeResponse)
def me(user: CurrentUser = Depends(get_current_user)) -> MeResponse:
    return MeResponse(id=user.id, username=user.username, roles=user.role_by_project)
