"""CVE threat-intel feed (ported from V1 get_cve_feed). Read-only: recent high/critical
CVEs from NIST NVD for the Overview widget. Cached + offline-safe in the agents layer."""
from __future__ import annotations

import re

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from vapt_agents.cve import cve_feed, is_exploited, lookup_cve

from ..deps import CurrentUser, get_current_user

router = APIRouter(prefix="/api/v2/cve", tags=["cve"])
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


class CveFeedItem(BaseModel):
    id: str
    score: float
    severity: str
    published: str
    description: str


class CveDetail(BaseModel):
    cve_id: str
    cvss: float | None = None
    vector: str = ""
    severity: str = "info"
    description: str = ""
    references: list[str] = []
    exploited: bool = False
    exploit_basis: str = ""


@router.get("/feed", response_model=list[CveFeedItem])
def feed(
    days: int = Query(7, ge=1, le=30),
    min_score: float = Query(7.0, ge=0.0, le=10.0),
    keyword: str = Query("", max_length=80),
    limit: int = Query(15, ge=1, le=50),
    user: CurrentUser = Depends(get_current_user),
) -> list[CveFeedItem]:
    items = cve_feed(days=days, min_score=min_score, keyword=keyword, limit=limit)
    return [CveFeedItem(**it) for it in items]


@router.get("/{cve_id}", response_model=CveDetail)
def lookup(cve_id: str, user: CurrentUser = Depends(get_current_user)) -> CveDetail:
    """Full NVD detail for one CVE + exploitation intel (CISA KEV / NVD exploit refs)."""
    if not _CVE_RE.fullmatch(cve_id):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "expected a CVE id (CVE-YYYY-NNNN)")
    info = lookup_cve(cve_id)
    if not info:
        raise HTTPException(status.HTTP_404_NOT_FOUND,
                            "CVE not found (or NVD unavailable — needs internet access)")
    intel = is_exploited(cve_id, nvd_info=info)
    return CveDetail(
        cve_id=info.get("cve_id", cve_id.upper()),
        cvss=info.get("cvss"),
        vector=info.get("vector", ""),
        severity=info.get("severity", "info"),
        description=info.get("description", ""),
        references=info.get("references", []),
        exploited=bool(intel.get("exploited")),
        exploit_basis=str(intel.get("basis", "")),
    )
