"""User administration (plan §8). Admin-only: create portal users, set their role on
the default project, and activate/deactivate them. Passwords are Argon2id-hashed; only
the hash is ever stored. Self-lockout is prevented (an admin can't deactivate or demote
their own account)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session
from vapt_domain.enums import Role
from vapt_persistence.models import Membership, User

from ..deps import CurrentUser, get_current_user, get_db, require_project_role
from ..security import hash_password
from .projects import default_project_id

router = APIRouter(prefix="/api/v2/users", tags=["users"])

_ROLES = {r.value for r in Role}


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=100)
    password: str = Field(min_length=8, max_length=200)
    role: str = "analyst"
    email: str | None = None


class UserUpdate(BaseModel):
    role: str | None = None
    is_active: bool | None = None


class UserOut(BaseModel):
    id: str
    username: str
    email: str | None
    is_active: bool
    role: str | None
    created_at: str


def _require_admin(db: Session, user: CurrentUser) -> str:
    pid = default_project_id(db)
    require_project_role(pid, user, Role.ADMIN)   # ADMIN only (admin also bypasses)
    return pid


def _role_for(db: Session, user_id: str, pid: str) -> str | None:
    m = db.execute(
        select(Membership).where(Membership.user_id == user_id, Membership.project_id == pid)
    ).scalar_one_or_none()
    return m.role if m else None


def _out(db: Session, u: User, pid: str) -> UserOut:
    return UserOut(
        id=u.id, username=u.username, email=u.email, is_active=u.is_active,
        role=_role_for(db, u.id, pid), created_at=u.created_at.isoformat(),
    )


@router.get("", response_model=list[UserOut])
def list_users(
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> list[UserOut]:
    pid = _require_admin(db, user)
    rows = db.execute(select(User).order_by(User.created_at)).scalars().all()
    return [_out(db, u, pid) for u in rows]


@router.post("", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(
    body: UserCreate,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> UserOut:
    pid = _require_admin(db, user)
    if body.role not in _ROLES:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"unknown role {body.role!r}")
    exists = db.execute(select(User).where(User.username == body.username)).scalar_one_or_none()
    if exists is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "username already taken")

    u = User(username=body.username, email=body.email,
             password_hash=hash_password(body.password), is_active=True)
    db.add(u)
    db.flush()
    db.add(Membership(project_id=pid, user_id=u.id, role=body.role))
    db.commit()
    db.refresh(u)
    return _out(db, u, pid)


@router.patch("/{user_id}", response_model=UserOut)
def update_user(
    user_id: str,
    body: UserUpdate,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> UserOut:
    pid = _require_admin(db, user)
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")

    # Guard against self-lockout.
    if target.id == user.id and (body.is_active is False or (body.role and body.role != Role.ADMIN.value)):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "you cannot deactivate or demote your own account")

    if body.role is not None:
        if body.role not in _ROLES:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"unknown role {body.role!r}")
        m = db.execute(
            select(Membership).where(Membership.user_id == target.id, Membership.project_id == pid)
        ).scalar_one_or_none()
        if m is None:
            db.add(Membership(project_id=pid, user_id=target.id, role=body.role))
        else:
            m.role = body.role
    if body.is_active is not None:
        target.is_active = body.is_active
    db.commit()
    db.refresh(target)
    return _out(db, target, pid)
