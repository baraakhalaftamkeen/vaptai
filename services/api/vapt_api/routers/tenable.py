"""Tenable.sc vulnerability findings — read-only proxy to the Tenable.sc REST API.

Fetches cumulative vulnerability data from the configured Tenable.sc instance and
returns it as JSON for the portal's Tenable page. Uses the same credentials and API
contract as the `vapt-tenable` CLI shim (VAPT_TENABLE_URL / ACCESS_KEY / SECRET_KEY).
"""
from __future__ import annotations

import json
import ssl
import urllib.request
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel

from ..config import get_settings
from ..deps import CurrentUser, get_current_user

router = APIRouter(prefix="/api/v2/tenable", tags=["tenable"])

_SEV = {"0": "info", "1": "low", "2": "medium", "3": "high", "4": "critical",
        "info": "info", "low": "low", "medium": "medium", "high": "high", "critical": "critical"}

_VULN_COLUMNS = [
    {"name": "ip"}, {"name": "port"}, {"name": "protocol"}, {"name": "pluginName"},
    {"name": "severity"}, {"name": "cve"}, {"name": "cvssV3BaseScore"},
    {"name": "exploitAvailable"}, {"name": "exploitFrameworks"}, {"name": "synopsis"},
    {"name": "solution"}, {"name": "operatingSystem"}, {"name": "firstSeen"},
    {"name": "lastSeen"},
]


class TenableVuln(BaseModel):
    ip: str = ""
    port: str = ""
    protocol: str = ""
    plugin: str = ""
    severity: str = "info"
    cve: str = ""
    cvss: float | None = None
    exploit: bool = False
    frameworks: str = ""
    synopsis: str = ""
    solution: str = ""
    os: str = ""
    first_seen: str = ""
    last_seen: str = ""


class TenableStatus(BaseModel):
    configured: bool
    url: str = ""


def _sev(level: Any) -> str:
    if isinstance(level, dict):
        level = level.get("id", level.get("name", "2"))
    return _SEV.get(str(level).strip().lower(), "medium")


def _cvss(v: dict) -> float | None:
    raw = str(v.get("cvssV3BaseScore", "") or v.get("baseScore", "")).strip()
    try:
        return float(raw) if raw else None
    except ValueError:
        return None


def _load_creds() -> tuple[str, str, str] | None:
    s = get_settings()
    host = (s.tenable_url or "").strip()
    ak = (s.tenable_access_key or "").strip()
    sk = (s.tenable_secret_key or "").strip()
    if not (host and ak and sk):
        return None
    host = host.replace("https://", "").replace("http://", "").strip("/")
    return host, ak, sk


def _fetch(ip: str = "", timeout: int = 30) -> dict:
    creds = _load_creds()
    if not creds:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                            "Tenable.sc not configured (set VAPT_TENABLE_URL/ACCESS_KEY/SECRET_KEY)")
    host, ak, sk = creds
    url = f"https://{host}/rest/analysis"
    filters: list[dict] = []
    if ip:
        filters.append({"filterName": "ip", "operator": "=", "value": ip})
    payload = json.dumps({
        "type": "vuln", "sourceType": "cumulative",
        "query": {"type": "vuln", "tool": "vulndetails", "filters": filters},
        "columns": _VULN_COLUMNS, "startOffset": 0, "endOffset": 5000,
    }).encode()
    req = urllib.request.Request(url, data=payload, method="POST", headers={
        "X-ApiKey": f"accesskey={ak}; secretkey={sk}",
        "Content-Type": "application/json", "Accept": "application/json",
    })
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:  # noqa: S310
            return json.loads(resp.read().decode("utf-8", "replace"))
    except Exception as e:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"Tenable.sc request failed: {e}")


def _parse(response: dict) -> list[TenableVuln]:
    out: list[TenableVuln] = []
    results = ((response or {}).get("response", {}) or {}).get("results", []) or []
    for v in results:
        if not isinstance(v, dict):
            continue
        exploit = str(v.get("exploitAvailable", "")).strip().lower() in ("yes", "true", "1")
        cves = [c.strip().upper() for c in str(v.get("cve", "")).replace(";", ",").split(",")
                if c.strip()]
        base = dict(
            ip=str(v.get("ip", "")),
            port=str(v.get("port", "")),
            protocol=str(v.get("protocol", "")),
            plugin=str(v.get("pluginName", "")),
            severity=_sev(v.get("severity", "2")),
            cvss=_cvss(v),
            exploit=exploit,
            frameworks=str(v.get("exploitFrameworks", "") or ""),
            synopsis=str(v.get("synopsis", ""))[:300],
            solution=str(v.get("solution", ""))[:300],
            os=str(v.get("operatingSystem", "")),
            first_seen=str(v.get("firstSeen", "")),
            last_seen=str(v.get("lastSeen", "")),
        )
        if cves:
            for cve in cves:
                out.append(TenableVuln(**base, cve=cve))
        else:
            out.append(TenableVuln(**base, cve=""))
    return out


@router.get("/status", response_model=TenableStatus)
def tenable_status(user: CurrentUser = Depends(get_current_user)) -> TenableStatus:
    creds = _load_creds()
    s = get_settings()
    return TenableStatus(
        configured=creds is not None,
        url=(s.tenable_url or "").strip().replace("https://", "").replace("http://", "").strip("/"),
    )


class TenablePage(BaseModel):
    items: list[TenableVuln]
    total: int
    page: int
    page_size: int
    pages: int


@router.get("/vulnerabilities", response_model=TenablePage)
def list_vulnerabilities(
    ip: str = Query("", max_length=100, description="Filter by IP address"),
    severity: str = Query("", max_length=20, description="Filter by severity (critical,high,medium,low,info)"),
    search: str = Query("", max_length=200, description="Search plugin name, CVE, or synopsis"),
    page: int = Query(1, ge=1, description="Page number (1-based)"),
    page_size: int = Query(20, ge=1, le=200, description="Items per page"),
    user: CurrentUser = Depends(get_current_user),
) -> TenablePage:
    response = _fetch(ip=ip)
    vulns = _parse(response)
    if severity:
        allowed = {s.strip().lower() for s in severity.split(",")}
        vulns = [v for v in vulns if v.severity in allowed]
    if search:
        q = search.lower()
        vulns = [v for v in vulns if q in v.plugin.lower()
                 or q in v.cve.lower() or q in v.synopsis.lower()
                 or q in v.ip.lower()]
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    vulns.sort(key=lambda v: (sev_order.get(v.severity, 5), -(v.cvss or 0)))
    total = len(vulns)
    pages = max(1, (total + page_size - 1) // page_size)
    start = (page - 1) * page_size
    return TenablePage(items=vulns[start:start + page_size], total=total,
                       page=page, page_size=page_size, pages=pages)
