"""Available PoC playbooks (plan §8, BAR-30). Read-only catalog the engagement form
offers; the attack agent runs only these, and only when the engagement opts in."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from vapt_agents.playbooks import PLAYBOOKS

from ..deps import CurrentUser, get_current_user

router = APIRouter(prefix="/api/v2/playbooks", tags=["playbooks"])


class PlaybookOut(BaseModel):
    id: str
    title: str
    description: str
    tool_id: str


@router.get("", response_model=list[PlaybookOut])
def list_playbooks(user: CurrentUser = Depends(get_current_user)) -> list[PlaybookOut]:
    return [
        PlaybookOut(id=p.id, title=p.title, description=p.description, tool_id=p.tool_id)
        for p in PLAYBOOKS.values()
    ]
