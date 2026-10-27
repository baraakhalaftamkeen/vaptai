"""Request dependencies: DB session + current authenticated user.

Authorization is owned here (FastAPI), on every data/action endpoint — Next.js only
renders UI and may proxy requests. Sessions are looked up and revocation re-checked
on each request.
"""
from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime

from fastapi import Cookie, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session
from vapt_domain.enums import Role
from vapt_persistence import db as _db
from vapt_persistence.models import AuthSession, Membership, User

from .config import get_settings
from .security import hash_token


def get_db() -> Iterator[Session]:
    if _db.SessionLocal is None:
        raise RuntimeError("engine not initialised")
    db = _db.SessionLocal()
    try:
        yield db
    finally:
        db.close()


class CurrentUser:
    def __init__(self, user: User, role_by_project: dict[str, str]):
        self.id = user.id
        self.username = user.username
        self.user = user
        self.role_by_project = role_by_project

    def role_in(self, project_id: str) -> str | None:
        return self.role_by_project.get(project_id)


def _expire_cookie_headers() -> dict[str, str]:
    """Headers to attach to a 401 so the browser DELETES the stale `vapt_session` cookie.
    Without this, an expired/revoked session leaves the cookie in the browser; the Next.js
    middleware sees "has cookie → not public → render", background pollers hit the API,
    the API 401s, and the user is stuck in a redirect-less loop. Max-Age=0 on the same name
    tells the browser to drop it immediately; on the next request there's no cookie, the
    middleware redirects to /login, done. Attributes match what we set on login so the
    browser matches the right cookie entry."""
    settings = get_settings()
    attrs = [f"{settings.session_cookie_name}=", "Path=/", "Max-Age=0", "HttpOnly", "SameSite=lax"]
    if getattr(settings, "cookie_secure", False):
        attrs.append("Secure")
    return {"Set-Cookie": "; ".join(attrs)}


def get_current_user(
    db: Session = Depends(get_db),
    vapt_session: str | None = Cookie(default=None),
) -> CurrentUser:
    get_settings()
    # cookie name is configurable; FastAPI maps the param name, so also accept header-less
    raw = vapt_session
    if not raw:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "not authenticated")

    token_hash = hash_token(raw)
    sess = db.execute(
        select(AuthSession).where(AuthSession.token_hash == token_hash)
    ).scalar_one_or_none()
    # Cookie IS present but doesn't resolve to a valid session (expired/revoked/wiped DB,
    # or just a leftover from the previous deployment) — clear it so the next request lands
    # on /login instead of looping forever.
    if sess is None or sess.revoked:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid session",
                            headers=_expire_cookie_headers())
    if sess.expires_at.replace(tzinfo=UTC) < datetime.now(UTC):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "session expired",
                            headers=_expire_cookie_headers())

    user = db.get(User, sess.user_id)
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "user inactive",
                            headers=_expire_cookie_headers())

    memberships = db.execute(
        select(Membership).where(Membership.user_id == user.id)
    ).scalars().all()
    role_by_project = {m.project_id: m.role for m in memberships}
    return CurrentUser(user, role_by_project)


def require_project_role(project_id: str, user: CurrentUser, *allowed: Role) -> None:
    role = user.role_in(project_id)
    if role is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "not a project member")
    allowed_values = {r.value for r in allowed} or None
    if allowed_values and role not in allowed_values and role != Role.ADMIN.value:
        raise HTTPException(status.HTTP_403_FORBIDDEN, f"role {role} not permitted")
