"""Service-driven tool router — the best-practice selection layer.

After the scan has discovered open ports/services, this picks the RIGHT follow-up tools for
what was actually found and returns them as (tool_id, args, task_id) for the probe phase to
run through the governed harness. It is DETERMINISTIC, so the right tools fire even when the
LLM planner is offline; when the planner IS online it proposes additional/ordered steps on
top (the two are complementary, not exclusive).

Only P0/P1 (non-destructive) tools are routed for auto-run, and each is gated on being
installed (`harness.tool_available`) so a missing binary doesn't clutter the ledger. P2
exploitation stays with the attack agent (human-gated). Everything still flows through policy
+ approval exactly as for the built-in tools — routing only decides *what to propose*.
"""
from __future__ import annotations

import ipaddress

from sqlalchemy import select
from sqlalchemy.orm import Session
from vapt_persistence.models import Finding, FindingObservation

from . import phases
from .runscope import RunScope

# Common web, TLS and service ports we key selection on (service name is also checked).
_WEB_PORTS = {"80", "443", "3000", "3001", "4200", "5000", "5001", "5601", "8000", "8001",
              "8002", "8008", "8080", "8081", "8088", "8090", "8443", "8888", "9000", "9001",
              "9443", "5985", "5986"}
_TLS_PORTS = {"443", "8443", "9443", "993", "995", "465", "636", "990"}


def _is_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def _services(db: Session, run_id: str) -> list[tuple[str, str]]:
    """(port, service-name lowercased) for every nmap service finding on the run."""
    out: list[tuple[str, str]] = []
    for fid in db.execute(select(Finding.id).where(Finding.run_id == run_id)).scalars().all():
        for o in db.execute(
            select(FindingObservation).where(FindingObservation.finding_id == fid)
        ).scalars().all():
            if o.source_tool != "nmap_service_scan":
                continue
            d = o.detail or {}
            port = str(d.get("port", "")).strip()
            svc = str(d.get("service", "")).lower()
            if port:
                out.append((port, svc))
    return out


def _web_targets(services: list[tuple[str, str]], *, cap: int = 6) -> list[dict]:
    """Every distinct web endpoint (scheme + optional non-standard port), so recon runs against
    each web service — not just the first. A host commonly serves several (e.g. an IIS default
    site on :80 AND the real app on :5000); scanning only one silently misses the others. App
    ports (anything but 80/443) are returned first so a default site on :80 can't crowd the real
    app out of the action budget. De-duped by (scheme, port) and bounded to `cap`."""
    web = [(p, s) for p, s in services
           if p in _WEB_PORTS or "http" in s or "wsman" in s]
    if not web:
        return []

    def _rank(ps: tuple[str, str]) -> tuple[int, str]:
        p = ps[0]
        return (1 if p in ("80", "443") else 0, p)   # app ports first, then 80/443

    eps: list[dict] = []
    seen: set[tuple] = set()
    for p, _s in sorted(web, key=_rank):
        if p == "80":
            ep = {"scheme": "http"}
        elif p == "443":
            ep = {"scheme": "https"}
        else:
            ep = {"scheme": ("https" if p in _TLS_PORTS else "http"), "port": p}
        key = (ep.get("scheme"), ep.get("port"))
        if key not in seen:
            seen.add(key)
            eps.append(ep)
        if len(eps) >= cap:
            break
    return eps


def route_actions(db: Session, scope: RunScope, harness, *, limit: int = 32
                  ) -> list[tuple[str, dict, str]]:
    """Choose follow-up tools for the discovered services. Returns [(tool_id, args, task_id)]
    for installed, non-destructive (P0/P1) tools only."""
    services = _services(db, scope.run_id)
    ports = {p for p, _ in services}
    names = " ".join(s for _, s in services)
    actions: list[tuple[str, dict, str]] = []
    seen: set[str] = set()

    def add(tool_id: str, args: dict, *, tag: str = "") -> None:
        key = f"{tool_id}:{tag}" if tag else tool_id
        if len(actions) >= limit or key in seen:
            return
        if harness.tool_available(tool_id, {**args, "target": scope.target}):
            seen.add(key)
            task_id = f"route-{tool_id}-{tag}" if tag else f"route-{tool_id}"
            actions.append((tool_id, args, task_id))

    # --- Web surface (run against EVERY web endpoint, app ports first) ----------------
    for web in _web_targets(services):
        tag = str(web.get("port") or web["scheme"])
        add("whatweb", dict(web), tag=tag)      # tech fingerprint
        add("katana", dict(web), tag=tag)       # crawl / endpoint discovery
        add("nikto", dict(web), tag=tag)        # server misconfig
        add("shcheck", dict(web), tag=tag)      # security headers
        add("cmseek", dict(web), tag=tag)       # CMS detect (self-identifies WP/Joomla/Drupal)
        add("wafw00f", dict(web), tag=tag)      # WAF detection
        add("feroxbuster", dict(web), tag=tag)  # content discovery
        # NOTE: parameter discovery (arjun) is NOT routed here — on the site root it finds
        # nothing. probe_services runs arjun per DISCOVERED endpoint instead (where params live).

    # --- TLS -------------------------------------------------------------------------
    if any(p in _TLS_PORTS for p in ports) or phases.has_tls_port(db, scope.run_id) is True:
        add("sslyze", {})

    # --- SSH -------------------------------------------------------------------------
    if "22" in ports or "ssh" in names:
        add("ssh_audit", {})

    # --- SMB / Windows ---------------------------------------------------------------
    if {"445", "139"} & ports or "microsoft-ds" in names or "netbios" in names or "smb" in names:
        add("smbmap", {})
        add("enum4linux_ng", {})

    # --- SMTP ------------------------------------------------------------------------
    if {"25", "465", "587"} & ports or "smtp" in names:
        add("swaks_relay", {})

    # --- LDAP / AD -------------------------------------------------------------------
    if {"389", "636", "3268"} & ports or "ldap" in names:
        add("ldapsearch_base", {})

    # --- Subdomain takeover (named targets only) -------------------------------------
    if scope.domains and not _is_ip(scope.target):
        add("subzy", {})

    return actions
