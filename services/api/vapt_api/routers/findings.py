"""Findings + evidence endpoints (plan §8).

Findings preserve observation vs interpretation: a finding carries a status
(candidate/confirmed/false_positive/inconclusive) and links to the observations that
produced it, each tagged with its source tool.
"""
from __future__ import annotations

import json as _json

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from vapt_domain.enums import Role
from vapt_persistence.models import Engagement, Finding, FindingObservation, Run

from ..deps import CurrentUser, get_current_user, get_db, require_project_role

router = APIRouter(prefix="/api/v2", tags=["findings"])


class ObservationOut(BaseModel):
    id: str
    source_tool: str
    detail: dict
    created_at: str


class FindingOut(BaseModel):
    id: str
    run_id: str
    title: str
    status: str
    severity: str
    description: str
    target_url: str
    resolution_status: str
    notes: str
    enrichment: dict | None = None
    engagement_id: str = ""
    engagement_name: str = ""
    observations: list[ObservationOut] = []
    created_at: str


class FindingUpdate(BaseModel):
    resolution_status: str | None = None
    notes: str | None = None


class EnrichmentOut(BaseModel):
    finding_id: str
    enrichment: dict


def _authz_run(db: Session, user: CurrentUser, run_id: str) -> Run:
    run = db.get(Run, run_id)
    if run is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "run not found")
    eng = db.get(Engagement, run.engagement_id)
    require_project_role(eng.project_id, user, Role.VIEWER, Role.ANALYST, Role.LEAD, Role.REVIEWER)
    return run


def _to_out(db: Session, f: Finding, eng: Engagement | None = None) -> FindingOut:
    obs = db.execute(
        select(FindingObservation).where(FindingObservation.finding_id == f.id)
    ).scalars().all()
    if eng is None:
        run = db.get(Run, f.run_id)
        eng = db.get(Engagement, run.engagement_id) if run else None
    return FindingOut(
        id=f.id,
        run_id=f.run_id,
        title=f.title,
        status=f.status,
        severity=f.severity,
        description=f.description or "",
        target_url=f.target_url or "",
        resolution_status=f.resolution_status or "open",
        notes=f.notes or "",
        enrichment=f.enrichment,
        engagement_id=eng.id if eng else "",
        engagement_name=eng.name if eng else "",
        observations=[
            ObservationOut(
                id=o.id, source_tool=o.source_tool, detail=o.detail or {},
                created_at=o.created_at.isoformat(),
            )
            for o in obs
        ],
        created_at=f.created_at.isoformat(),
    )


@router.get("/runs/{run_id}/findings", response_model=list[FindingOut])
def list_findings(
    run_id: str,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> list[FindingOut]:
    _authz_run(db, user, run_id)
    findings = db.execute(select(Finding).where(Finding.run_id == run_id)).scalars().all()
    return [_to_out(db, f) for f in findings]


@router.get("/findings", response_model=list[FindingOut])
def list_all_findings(
    severity: str | None = Query(None),
    resolution_status: str | None = Query(None),
    finding_status: str | None = Query(None),
    engagement_id: str | None = Query(None),
    search: str | None = Query(None),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> list[FindingOut]:
    """Standalone findings listing across all runs the user can see."""
    q = select(Finding).order_by(Finding.created_at.desc())
    if severity:
        q = q.where(Finding.severity == severity)
    if resolution_status:
        q = q.where(Finding.resolution_status == resolution_status)
    if finding_status:
        q = q.where(Finding.status == finding_status)

    findings = db.execute(q).scalars().all()
    results: list[FindingOut] = []
    for f in findings:
        run = db.get(Run, f.run_id)
        if not run:
            continue
        eng = db.get(Engagement, run.engagement_id)
        if not eng or not user.role_in(eng.project_id):
            continue
        if engagement_id and eng.id != engagement_id:
            continue
        if search:
            s = search.lower()
            if (s not in f.title.lower()
                    and s not in (f.description or "").lower()
                    and s not in (f.target_url or "").lower()):
                continue
        results.append(_to_out(db, f, eng))
    return results


@router.get("/engagements/{engagement_id}/findings", response_model=list[FindingOut])
def list_engagement_findings(
    engagement_id: str,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> list[FindingOut]:
    """All findings across every run of this engagement."""
    eng = db.get(Engagement, engagement_id)
    if not eng:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "engagement not found")
    require_project_role(eng.project_id, user, Role.VIEWER, Role.ANALYST, Role.LEAD, Role.REVIEWER)
    runs = db.execute(select(Run).where(Run.engagement_id == engagement_id)).scalars().all()
    run_ids = {r.id for r in runs}
    findings = db.execute(
        select(Finding).where(Finding.run_id.in_(run_ids)).order_by(Finding.created_at.desc())
    ).scalars().all()
    return [_to_out(db, f, eng) for f in findings]


@router.get("/findings/{finding_id}", response_model=FindingOut)
def get_finding(
    finding_id: str,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> FindingOut:
    f = db.get(Finding, finding_id)
    if f is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")
    _authz_run(db, user, f.run_id)
    return _to_out(db, f)


@router.patch("/findings/{finding_id}", response_model=FindingOut)
def update_finding(
    finding_id: str,
    body: FindingUpdate,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> FindingOut:
    f = db.get(Finding, finding_id)
    if f is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")
    run = _authz_run(db, user, f.run_id)
    eng = db.get(Engagement, run.engagement_id)
    require_project_role(eng.project_id, user, Role.ANALYST, Role.LEAD)
    if body.resolution_status is not None:
        if body.resolution_status not in ("open", "resolved", "accepted_risk", "false_positive"):
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "invalid resolution_status")
        f.resolution_status = body.resolution_status
    if body.notes is not None:
        f.notes = body.notes
    db.commit()
    db.refresh(f)
    return _to_out(db, f, eng)


class EnrichRequest(BaseModel):
    force: bool = False


@router.post("/findings/{finding_id}/enrich", response_model=EnrichmentOut)
def enrich_finding(
    finding_id: str,
    body: EnrichRequest | None = None,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> EnrichmentOut:
    """Generate (or return cached) human-readable enrichment via LLM."""
    f = db.get(Finding, finding_id)
    if f is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")
    _authz_run(db, user, f.run_id)

    force = body.force if body else False
    if f.enrichment and not force:
        return EnrichmentOut(finding_id=f.id, enrichment=f.enrichment)

    obs = db.execute(
        select(FindingObservation).where(FindingObservation.finding_id == f.id)
    ).scalars().all()
    obs_text = "\n".join(
        f"- [{o.source_tool}] {_json.dumps(o.detail, default=str)}" for o in obs
    )

    prompt = (
        "You are a senior penetration tester writing a finding report for a client. "
        "Given the following vulnerability finding, produce a clear, human-readable analysis.\n\n"
        f"Title: {f.title}\n"
        f"Severity: {f.severity}\n"
        f"Status: {f.status}\n"
        f"Description: {f.description or '(none)'}\n"
        f"Target: {f.target_url or '(unknown)'}\n\n"
        f"Evidence/Observations:\n{obs_text or '(none)'}\n\n"
        "Return a JSON object with these keys:\n"
        '- "description": A clear 2-3 sentence description of the vulnerability.\n'
        '- "impact": What damage an attacker could cause by exploiting this.\n'
        '- "steps_to_reproduce": Numbered steps to reproduce the issue.\n'
        '- "recommendations": Specific remediation steps.\n'
        '- "evidence_summary": A plain-English summary of the evidence gathered.\n'
        '- "human_title": A clearer, more readable version of the finding title.\n'
        "Reply with ONLY the JSON object."
    )

    enrichment: dict | None = None
    try:
        from vapt_llm import LLMGateway, profiles_from_env
        profiles = profiles_from_env()
        gateway = LLMGateway(profiles)
        profile_id = "reporting" if "reporting" in profiles else next(iter(profiles))
        resp = gateway.invoke(
            profile_id=profile_id,
            messages=[{"role": "user", "content": prompt}],
            output_schema={
                "type": "object",
                "properties": {
                    "description": {"type": "string"},
                    "impact": {"type": "string"},
                    "steps_to_reproduce": {"type": "string"},
                    "recommendations": {"type": "string"},
                    "evidence_summary": {"type": "string"},
                    "human_title": {"type": "string"},
                },
                "required": ["description", "impact", "steps_to_reproduce", "recommendations",
                             "evidence_summary", "human_title"],
            },
        )
        if resp.parsed:
            enrichment = resp.parsed
    except Exception:
        pass

    if enrichment is None:
        obs_details: list[str] = []
        for o in obs:
            d = o.detail or {}
            parts = []
            for k in ("url", "path", "host", "method", "param", "parameter",
                       "class", "category", "evidence", "reason", "info", "cwe",
                       "message"):
                v = d.get(k)
                if v:
                    if isinstance(v, (dict, list)):
                        v = _json.dumps(v, default=str)[:200]
                    parts.append(f"{k}: {v}")
            if parts:
                obs_details.append(f"[{o.source_tool}] {'; '.join(parts)}")
            elif d:
                obs_details.append(f"[{o.source_tool}] {_json.dumps(d, default=str)[:300]}")

        title_clean = _clean_title(f.title)

        desc = f.description or ""
        if not desc or desc.startswith("Observed by "):
            desc = _build_description(title_clean, f.severity, obs)

        enrichment = {
            "description": desc,
            "impact": _infer_impact(f.severity, title_clean),
            "steps_to_reproduce": _infer_repro(obs),
            "recommendations": _infer_recommendations(title_clean),
            "evidence_summary": "\n".join(obs_details) if obs_details else "No detailed evidence recorded.",
            "human_title": title_clean,
        }

    f.enrichment = enrichment
    db.commit()
    return EnrichmentOut(finding_id=f.id, enrichment=enrichment)


def _clean_title(raw: str) -> str:
    """Strip scanner prefixes and OSVDB tags for a cleaner human title."""
    import re
    t = raw
    for prefix in ("Nikto: ", "ZAP: ", "Wapiti: ", "Nmap: "):
        if t.startswith(prefix):
            t = t[len(prefix):]
    t = re.sub(r"^OSVDB-\d+:\s*", "", t)
    return t.strip()


def _build_description(title: str, severity: str, obs: list) -> str:
    """Build a human-readable description from the finding title and observations."""
    t = title.lower()
    sources = list({o.source_tool for o in obs})
    source_str = ", ".join(sources) if sources else "security scanner"

    if "xss" in t or "cross-site scripting" in t:
        return f"A Cross-Site Scripting (XSS) vulnerability was identified by {source_str}. This allows an attacker to inject malicious client-side scripts into web pages viewed by other users."
    if "sql" in t and "injection" in t:
        return f"An SQL Injection vulnerability was identified by {source_str}. This allows an attacker to interfere with the queries the application makes to its database."
    if "idor" in t or "insecure direct object" in t:
        return f"An Insecure Direct Object Reference (IDOR) vulnerability was identified by {source_str}. Unauthorized users can access or modify resources belonging to other users by manipulating object identifiers."
    if "csp" in t or "content-security-policy" in t:
        return f"The application does not implement a Content Security Policy (CSP) header, or uses a report-only policy. Detected by {source_str}. CSP is a critical defense layer against XSS and code injection attacks."
    if "clickjack" in t or "x-frame" in t:
        return f"The X-Frame-Options header is missing or misconfigured, as detected by {source_str}. Without this header, the application is vulnerable to clickjacking attacks where an attacker can embed the page in a malicious frame."
    if "cors" in t or "access-control" in t:
        return f"A Cross-Origin Resource Sharing (CORS) misconfiguration was detected by {source_str}. The server's access-control headers may allow unauthorized origins to interact with the application."
    if "etag" in t or "inode" in t:
        return f"The web server exposes inode information through ETag headers, as detected by {source_str}. This information disclosure can reveal internal server details to attackers."
    if "cookie" in t:
        return f"A cookie security issue was detected by {source_str}. Improperly configured cookies can lead to session hijacking or other authentication-related attacks."
    if "directory" in t and ("index" in t or "listing" in t):
        return f"Directory listing/indexing is enabled on the server, as detected by {source_str}. This exposes the file structure and potentially sensitive files to unauthorized users."
    if "git" in t:
        return f"An exposed Git repository was detected by {source_str}. This could leak source code, credentials, and internal project history to attackers."
    if "waf" in t or "ids" in t:
        return f"No Web Application Firewall (WAF) or Intrusion Detection System (IDS) was detected by {source_str}. This is an informational finding about the target's defensive posture."

    target = ""
    if obs:
        d = obs[0].detail or {}
        target = d.get("url") or d.get("host") or d.get("path") or ""

    base = f"A {severity}-severity security finding was detected by {source_str}: {title}."
    if target:
        base += f" Target: {target}."
    return base


def _infer_impact(severity: str, title: str) -> str:
    t = title.lower()
    if "xss" in t or "cross-site scripting" in t:
        return "An attacker could inject malicious scripts into web pages viewed by other users, potentially stealing session cookies, credentials, or performing actions on their behalf."
    if "sql" in t and "injection" in t:
        return "An attacker could manipulate database queries to read, modify, or delete data, or in severe cases gain server access."
    if "idor" in t or "insecure direct object" in t:
        return "An attacker could access or modify other users' data by manipulating object references, leading to unauthorized data exposure."
    if "csp" in t or "content-security-policy" in t:
        return "Without a Content Security Policy, the application is more vulnerable to cross-site scripting (XSS) and data injection attacks."
    if "clickjack" in t or "x-frame" in t:
        return "An attacker could embed this page in a frame and trick users into clicking hidden elements, performing unintended actions."
    if "cors" in t or "access-control" in t:
        return "Misconfigured CORS headers could allow unauthorized origins to make authenticated requests on behalf of users."
    if "etag" in t or "inode" in t:
        return "Information leakage through ETags could reveal internal server details useful for further attacks."
    if "header" in t and ("missing" in t or "absent" in t or "not present" in t):
        return "Missing security headers reduce the application's defense-in-depth, making it easier to exploit other vulnerabilities."
    if "cookie" in t:
        return "Insecure cookie configuration could allow session hijacking or cross-site request forgery attacks."
    if "ssl" in t or "tls" in t or "certificate" in t:
        return "Weak TLS configuration could allow man-in-the-middle attacks, exposing sensitive data in transit."
    impact_by_severity = {
        "critical": "This vulnerability poses an immediate, severe risk. Exploitation could lead to full system compromise, data breach, or service takeover.",
        "high": "This vulnerability could allow significant unauthorized access or data exposure if exploited.",
        "medium": "This issue could aid an attacker in further exploitation or cause moderate data exposure.",
        "low": "This is a minor issue that provides limited information or slight security weakening.",
        "info": "This is an informational finding that documents the application's configuration or behavior.",
    }
    return impact_by_severity.get(severity, impact_by_severity["medium"])


def _infer_repro(obs: list) -> str:
    if not obs:
        return "No specific reproduction steps available. Review the raw evidence for details."
    first = obs[0]
    d = first.detail or {}
    steps = []
    url = d.get("url") or d.get("path") or d.get("host") or ""
    method = d.get("method", "GET")
    param = d.get("param") or d.get("parameter") or ""
    if url:
        steps.append(f"1. Navigate to: {url}")
    if method and method != "GET":
        steps.append(f"2. Send a {method} request to the target endpoint.")
    elif not url:
        steps.append("1. Access the target application.")
    if param:
        steps.append(f"{'3' if len(steps) >= 2 else '2'}. Test the parameter: {param}")
    steps.append(f"{len(steps) + 1}. Observe the response for the reported behavior.")
    return "\n".join(steps)


def _infer_recommendations(title: str) -> str:
    t = title.lower()
    if "xss" in t or "cross-site scripting" in t:
        return "Implement proper output encoding/escaping for all user-supplied data. Use a Content Security Policy (CSP) header. Consider using a templating engine with automatic escaping."
    if "sql" in t and "injection" in t:
        return "Use parameterized queries or prepared statements. Implement input validation. Apply the principle of least privilege for database accounts."
    if "idor" in t or "insecure direct object" in t:
        return "Implement proper authorization checks on every data access. Use indirect references. Verify that the authenticated user has permission to access the requested resource."
    if "csp" in t or "content-security-policy" in t:
        return "Add a Content-Security-Policy header with appropriate directives. Start with a restrictive policy and adjust as needed. Use 'report-uri' to monitor violations."
    if "clickjack" in t or "x-frame" in t:
        return "Add the X-Frame-Options header set to 'DENY' or 'SAMEORIGIN'. Also set the Content-Security-Policy frame-ancestors directive."
    if "cors" in t or "access-control" in t:
        return "Restrict the Access-Control-Allow-Origin header to specific trusted origins. Avoid using wildcard (*) for origins. Validate the Origin header server-side."
    if "etag" in t or "inode" in t:
        return "Configure the web server to use hash-based ETags instead of inode-based ones. In Apache, use 'FileETag MTime Size' or 'FileETag None'."
    if "cookie" in t:
        return "Set the Secure, HttpOnly, and SameSite flags on sensitive cookies. Use appropriate cookie scope (Path, Domain)."
    if "ssl" in t or "tls" in t:
        return "Enable TLS 1.2+ only. Disable weak cipher suites. Use HSTS headers. Ensure certificates are valid and properly configured."
    if "header" in t and ("missing" in t or "absent" in t or "not present" in t):
        return "Add the appropriate security header to all HTTP responses. Review OWASP Secure Headers Project for recommended headers and values."
    return "Review the finding details and apply appropriate security controls. Consult OWASP guidelines for remediation best practices."
