"""Reusable recon / scan / validate building blocks (plan §5, §6).

ONE implementation of each phase, shared by both callers:
  * run_web_network_pipeline() — the sequential library path (and its Week-3 test);
  * the LangGraph engagement graph — per-agent nodes that call the same helpers.

Every block drives the GovernedHarness, so policy, scope, the ledger and approval
gating apply identically no matter who calls it. Nothing here authorizes an action;
the harness + policy engine do, and a human approves anything intrusive.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session
from vapt_domain.enums import AgentRole, FindingStatus
from vapt_harness import ActionContext, ActionOutcome, GovernedHarness
from vapt_persistence import ledger
from vapt_persistence.models import Approval, Finding, FindingObservation
from vapt_tools import action_digest, idempotency_key

from .normalize import Observation, normalize
from .runscope import RunScope

# A broad-but-bounded default port set used when the engagement pins none: common web,
# remote-access, mail, directory, database and Windows service ports. The engagement's
# own "Allowed ports" field overrides this (including a full-range sweep like 1-65535).
DEFAULT_PORTS = (
    "21,22,23,25,53,80,110,135,139,143,389,443,445,465,587,636,993,995,"
    "1433,1521,2049,3000,3001,3306,3389,4200,5000,5001,5432,5601,5900,5985,5986,6379,"
    "7001,7070,8000,8001,8002,8008,8080,8081,8088,8090,8443,8888,9000,9001,9200,27017"
)

# Default bounded black/gray-box web+network adapter set, used when no plan is given.
# NOTE: ports here are a placeholder; callers that have a RunScope should use
# scan_plan_for(scope) so the engagement's Allowed ports actually bound the scan.
DEFAULT_SCAN_TOOLS: list[tuple[str, dict]] = [
    ("nmap_service_scan", {"ports": "80,443,22"}),
    ("http_probe", {}),
    ("nuclei_safe", {"severity": "info,low,medium"}),
]


def ports_for(scope: "RunScope") -> str:
    """The port spec this run should scan: the engagement's Allowed ports if set,
    otherwise the broad default service set."""
    return (getattr(scope, "allowed_ports", "") or "").strip() or DEFAULT_PORTS


def scan_plan_for(scope: "RunScope") -> list[tuple[str, dict]]:
    """The default scan plan bound to a run's scope, so nmap probes exactly the ports
    the engagement authorized (or the default set when none were pinned)."""
    return [
        ("nmap_service_scan", {"ports": ports_for(scope)}),
        ("http_probe", {}),
        ("nuclei_safe", {"severity": "info,low,medium"}),
    ]

# White-box source static-analysis set (plan §5, BAR-27). Each runs against the
# engagement's uploaded bundle; `path` is injected by the source pipeline, never a model.
DEFAULT_SOURCE_TOOLS: list[str] = ["semgrep_scan", "gitleaks_scan", "dep_audit"]


@dataclass
class ScanStep:
    """The outcome of proposing one scan action through the harness."""

    tool_id: str
    task_id: str
    outcome: ActionOutcome
    candidate_ids: list[str] = field(default_factory=list)


def ctx_for(
    scope: RunScope, *, task_id: str, agent: AgentRole, tool_id: str, args: dict
) -> ActionContext:
    """Build an ActionContext bound to this run's scope. target defaults to the scope
    target but an arg-supplied target is honored (still scope-checked in the harness)."""
    merged = {"target": scope.target, **args}
    return ActionContext(
        run_id=scope.run_id,
        task_id=task_id,
        agent_role=agent,
        testing_mode=scope.testing_mode,
        tool_id=tool_id,
        profile_id="default",
        target_ref=str(merged.get("target", scope.target)),
        args=merged,
        allowed_action_classes=scope.allowed_action_classes,
        scope_domains=scope.domains,
        scope_ip_cidrs=scope.ip_cidrs,
        signed_profile=scope.signed_profile,
    )


def action_key(scope: RunScope, *, task_id: str, tool_id: str, args: dict) -> str:
    """The idempotency key the harness will use for this exact action — lets a
    re-entrant caller (the graph) tell whether it already ran."""
    merged = {"target": scope.target, **args}
    digest = action_digest(tool_id, "default", str(merged.get("target", scope.target)), merged)
    return idempotency_key(scope.run_id, task_id, digest)


def already_executed(db: Session, scope: RunScope, *, task_id: str, tool_id: str, args: dict) -> bool:
    key = action_key(scope, task_id=task_id, tool_id=tool_id, args=args)
    rec = ledger.get_action_by_key(db, key)
    return rec is not None and rec.state == "executed"


def prior_decision(db: Session, scope: RunScope, *, task_id: str, tool_id: str, args: dict) -> str | None:
    """The human verdict already recorded for this exact action, if any.

    A self-looping gated graph node re-runs from the top every time the run resumes after
    an approval (LangGraph replays the interrupted node). If it simply re-proposed the
    action, the harness would mint a FRESH pending approval each replay — because the
    prior approval is no longer 'pending' — and under polling/auto-approval that becomes a
    runaway loop (same action approved + executed dozens of times). So before proposing, a
    node asks here whether this action's approval was already decided and acts on that
    directly instead.

    Returns the Approval state for the action's digest ('approved' | 'approved_batch' |
    'rejected' | 'changes_requested' | 'expired'), or None when the action was never
    proposed or its approval is still pending. The digest is read from the recorded
    ToolActionRecord, so it matches exactly what the harness stored for the approval."""
    rec = ledger.get_action_by_key(db, action_key(scope, task_id=task_id, tool_id=tool_id, args=args))
    if rec is None:
        return None
    appr = db.execute(
        select(Approval)
        .where(
            Approval.run_id == scope.run_id,
            Approval.action_digest == rec.action_digest,
            Approval.state != "pending",
        )
        .order_by(Approval.created_at.desc())
    ).scalars().first()
    return appr.state if appr else None


def candidate_ids_for_run(db: Session, run_id: str) -> list[str]:
    """All finding ids for a run (any status). The DB, not graph state, is the source
    of truth for what the scan phase produced — a graph interrupt discards in-node
    state accumulation, but committed findings survive."""
    from sqlalchemy import select as _select

    return list(
        db.execute(_select(Finding.id).where(Finding.run_id == run_id).order_by(Finding.created_at)).scalars().all()
    )


# Ports (beyond the 80/443 the base http_probe already covers) that commonly front an
# HTTP service worth a follow-up probe. Service names containing "http"/"wsman" also qualify.
_WEB_PORTS = {
    591, 2082, 2083, 2086, 2087, 2095, 2096, 3000, 3001, 4200, 5000, 5001, 5601, 5985,
    5986, 7001, 7002, 8000, 8001, 8002, 8008, 8080, 8081, 8088, 8090, 8443, 8834, 8888,
    9000, 9001, 9043, 9080, 9090, 9200, 9443, 10000,
}


def web_ports_from_findings(db: Session, run_id: str) -> list[tuple[str, str]]:
    """Distinct (port, service) pairs from this run's nmap findings that look like an HTTP
    service worth a follow-up httpx probe. Excludes 80/443 (the base http_probe already
    covers those) so follow-up probes target the non-standard web ports nmap discovered."""
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    findings = db.execute(select(Finding.id).where(Finding.run_id == run_id)).scalars().all()
    for fid in findings:
        obs = db.execute(
            select(FindingObservation).where(FindingObservation.finding_id == fid)
        ).scalars().all()
        for o in obs:
            if o.source_tool != "nmap_service_scan":
                continue
            d = o.detail or {}
            port = str(d.get("port", "")).strip()
            svc = str(d.get("service", "")).lower()
            if not port.isdigit() or port in seen:
                continue
            if int(port) in (80, 443):
                continue  # already probed by the base http_probe
            if ("http" in svc) or ("wsman" in svc) or (int(port) in _WEB_PORTS):
                seen.add(port)
                out.append((port, svc))
    return out


# Windows service ports worth a bounded NSE host-script follow-up (SMB/RDP/MSRPC/NetBIOS).
_NSE_PORTS = {135, 139, 445, 3389}


def service_ports_from_findings(db: Session, run_id: str) -> list[str]:
    """Distinct Windows service ports nmap found that warrant an NSE host-script probe."""
    out: list[str] = []
    seen: set[str] = set()
    for fid in db.execute(select(Finding.id).where(Finding.run_id == run_id)).scalars().all():
        obs = db.execute(
            select(FindingObservation).where(FindingObservation.finding_id == fid)
        ).scalars().all()
        for o in obs:
            if o.source_tool != "nmap_service_scan":
                continue
            port = str((o.detail or {}).get("port", "")).strip()
            if port.isdigit() and int(port) in _NSE_PORTS and port not in seen:
                seen.add(port)
                out.append(port)
    return out


def open_ports_from_findings(db: Session, run_id: str) -> list[str]:
    """Every distinct open port nmap discovered — for a service→CVE (vulners) pass."""
    out: list[str] = []
    seen: set[str] = set()
    for fid in db.execute(select(Finding.id).where(Finding.run_id == run_id)).scalars().all():
        obs = db.execute(
            select(FindingObservation).where(FindingObservation.finding_id == fid)
        ).scalars().all()
        for o in obs:
            if o.source_tool != "nmap_service_scan":
                continue
            port = str((o.detail or {}).get("port", "")).strip()
            if port.isdigit() and port not in seen:
                seen.add(port)
                out.append(port)
    return out


def webvuln_seed_urls(db: Session, scope: RunScope, *, base_url: str, cap: int = 80) -> list[str]:
    """Extra entry-point URLs to seed an active web scan for one base (scheme://host[:port]).

    The bare-root scan only reaches pages linked from '/', so unlinked routes (most of an
    app's real attack surface) are never tested. This gathers seeds from two sources and
    resolves each against `base_url`, restricted to the base host so the scan stays in scope:
      1. every endpoint the recon/probe discovery tools already found. Both the link crawler
         (katana) and the content-discovery brute-forcer (feroxbuster) store their hits in a
         finding's `detail.sample`; we harvest any observation that carries such a list, so
         unlinked routes a brute-force found (e.g. /login, /admin) get scanned too — not just
         what the crawler could reach from '/'. This is what makes seeding automatic.
      2. an optional operator path/URL list via the VAPT_WEBVULN_SEED_PATHS env var
         (comma / whitespace / newline separated) — an override, no longer required.
    De-duped and bounded to `cap`."""
    from urllib.parse import urljoin, urlparse

    base = base_url.rstrip("/") + "/"
    base_host = urlparse(base_url).hostname
    raw: list[str] = []
    # (1) endpoints any discovery tool already found (katana crawl + feroxbuster content
    # discovery, and any future tool that records a `sample` URL list).
    for fid in db.execute(select(Finding.id).where(Finding.run_id == scope.run_id)).scalars().all():
        for o in db.execute(
            select(FindingObservation).where(FindingObservation.finding_id == fid)
        ).scalars().all():
            sample = (o.detail or {}).get("sample")
            if isinstance(sample, list):
                raw += [str(u) for u in sample]
    # (2) optional operator-provided paths/URLs (override)
    raw += [p for p in re.split(r"[\s,]+", os.environ.get("VAPT_WEBVULN_SEED_PATHS", "")) if p]

    seeds: list[str] = []
    seen: set[str] = set()
    for item in raw:
        item = item.strip()
        if not item:
            continue
        url = item if item.lower().startswith(("http://", "https://")) \
            else urljoin(base, item.lstrip("/"))
        if urlparse(url).hostname != base_host:
            continue                       # keep seeds on the in-scope host
        if url not in seen:
            seen.add(url)
            seeds.append(url)
        if len(seeds) >= cap:
            break
    return seeds


_WAPITI_PATH_RE = re.compile(r"wapiti:\s*[^\n]*?\s+at\s+(/[^\s(]+)")


def discovered_endpoint_urls(db: Session, scope: RunScope, *, base_url: str,
                             cap: int = 12) -> list[str]:
    """Distinct endpoint URLs (scheme://netloc/path, query/fragment dropped) that discovery
    already found for THIS base — so parameter discovery (arjun) can be pointed at each real
    route (/search, /order, …) instead of only the site root, where there are no params to find.

    Pulled from THREE sources now, in order:
      1. katana/feroxbuster `detail.sample` lists (the usual crawl output);
      2. wapiti finding titles ("wapiti: Unencrypted Channels at /fetch/logo", …) — wapiti
         internally crawls routes katana skips because they return non-HTML content types
         (image/octet-stream for /fetch/logo), so this is how we catch file-serving routes
         like /fetch/logo that are the real traversal/SSRF sinks on DineHub-style apps;
      3. explicit login-form URLs discovered by wapiti so authenticated-only routes also probe.
    All matched on the base's full netloc (host:port). Deduped and bounded to `cap`."""
    from urllib.parse import urldefrag, urljoin, urlparse

    base = base_url.rstrip("/") + "/"
    base_netloc = urlparse(base_url).netloc
    out: list[str] = []
    seen: set[str] = set()

    def _consider(u: str) -> bool:
        """Add `u` relative to base; return True if cap reached."""
        u = str(u).strip()
        if not u:
            return False
        url = u if u.lower().startswith(("http://", "https://")) \
            else urljoin(base, u.lstrip("/"))
        url = urldefrag(url)[0]
        p = urlparse(url)
        if p.netloc != base_netloc:
            return False
        path = p.path or "/"
        if path == "/":
            return False
        clean = f"{p.scheme}://{p.netloc}{path}"
        if clean in seen:
            return False
        seen.add(clean)
        out.append(clean)
        return len(out) >= cap

    for fid in db.execute(select(Finding.id).where(Finding.run_id == scope.run_id)).scalars().all():
        f = db.get(Finding, fid)
        obs_rows = db.execute(
            select(FindingObservation).where(FindingObservation.finding_id == fid)
        ).scalars().all()
        # Source 2: wapiti's own path mentions in finding titles — catches /fetch/logo
        # etc. The wapiti observation's detail.host carries the actual Host header
        # wapiti saw (e.g. "172.25.188.23:5000"). Only include the path if that host
        # matches our current base — otherwise /fetch/logo (a port-5000 route) would
        # get probed against port 80 (IIS) and produce 404s on every probe.
        if f is not None and f.title:
            m = _WAPITI_PATH_RE.search(f.title)
            if m:
                path = m.group(1)
                wapiti_host = ""
                for o in obs_rows:
                    if o.source_tool == "wapiti":
                        wapiti_host = str((o.detail or {}).get("host", "")).strip()
                        if wapiti_host:
                            break
                # If wapiti recorded a Host and it DOESN'T match this base, skip.
                # If it matches OR wapiti didn't record one (fall back to urljoin), take it.
                if wapiti_host and wapiti_host != base_netloc:
                    pass  # cross-base wapiti finding — not relevant to this base
                elif _consider(path):
                    break
        for o in obs_rows:
            # Source 1: katana/feroxbuster sample arrays
            sample = (o.detail or {}).get("sample")
            if isinstance(sample, list):
                for u in sample:
                    if _consider(u):
                        break
                else:
                    continue
                break
        if len(out) >= cap:
            break
    # Rank: routes whose path hints at a file/fetch/download/view sink come FIRST, because
    # traversal/SSRF/XXE live there far more often than on /, /about, /register. Within each
    # tier the original discovery order is preserved so deterministic ordering is intact.
    def _tier(u: str) -> int:
        return 0 if is_file_sink_route(u) else 1
    order = {u: i for i, u in enumerate(out)}
    out.sort(key=lambda u: (_tier(u), order[u]))
    return out


# File-sink path markers — traversal/SSRF/XXE/RCE live on these far more often than on
# generic routes like /, /register, /about. Also used by the webvuln planner to ALWAYS
# probe sink routes before the generic cap applies, so noisy recon (many static assets)
# can't push /fetch/logo past the probe-plan boundary.
_FILE_SINK_HINTS = ("fetch", "download", "file", "view", "static", "serve", "load",
                    "image", "images", "img", "upload", "attach", "export",
                    "import", "render", "proxy")


def is_file_sink_route(url: str) -> bool:
    """True if the URL's path contains any token that commonly marks a file-serving /
    fetch / proxy sink. Deterministic, token-driven, no hardcoded path list."""
    from urllib.parse import urlparse as _up
    p = _up(url).path.lower()
    return any(h in p for h in _FILE_SINK_HINTS)


# Path tokens that commonly mark a POST-only sink (register, login, feedback, cart/add,
# profile update, review, comment, submit, etc.). Used by the webvuln planner to emit
# a POST-body variant of the web_param_probe for these endpoints — otherwise forms
# that only accept POST get probed as GET and reply 405 + no coverage. Pattern-driven,
# not a hardcoded path list — matches the Flask/Django/Rails/Express conventions.
_POST_SINK_HINTS = ("register", "signup", "sign_up", "signin", "sign_in",
                    "login", "logon", "auth/log", "feedback", "comment",
                    "comments", "review", "reviews", "submit", "post",
                    "create", "add", "update", "edit", "save", "delete",
                    "remove", "upload", "profile", "password", "contact",
                    "subscribe", "checkout", "order", "cart/add", "cart/update",
                    # Admin form endpoints — DineHub /admin/announcement, /admin/offer
                    # are POST-only; adding the substrings catches them cheaply.
                    "announce", "offer", "message", "greeting")


def is_post_sink_route(url: str) -> bool:
    """True if the URL's path contains any token that marks it as a probable POST
    endpoint (register/login/feedback/comment/submit/update/add/edit/...). Used to
    emit a POST-body variant of the parameterised probe so sinks behind forms get
    coverage. Deterministic, token-driven, no hardcoded path list."""
    from urllib.parse import urlparse as _up
    p = _up(url).path.lower()
    return any(h in p for h in _POST_SINK_HINTS)


def has_admin_route(db: Session, run_id: str) -> bool:
    """True iff any prior-recon source (katana, feroxbuster, wapiti, or an
    authenticated-arjun seed) saw a path matching ``/admin`` or ``/admin/*``.
    Used by the webvuln planner to gate the admin wordlist seeder — probing
    /admin/logs, /admin/config, /admin/import on apps that have NO admin
    surface at all is wasted budget and generates 404 noise. Any evidence
    (a single /admin/login reference) is enough to unlock the fan-out.

    Deliberately permissive: we check finding titles, observation samples,
    and arjun seeds. The next phase's own probes will filter the 404s; this
    just avoids kicking off a 24-request pass on hopeless targets."""
    from urllib.parse import urlparse as _up
    _ADMIN_RE = re.compile(r"(?:^|[\s/])/?admin(?:/|$)", re.IGNORECASE)
    for fid in db.execute(
            select(Finding.id).where(Finding.run_id == run_id)).scalars().all():
        f = db.get(Finding, fid)
        if f and f.title and _ADMIN_RE.search(f.title):
            return True
        obs_rows = db.execute(
            select(FindingObservation).where(FindingObservation.finding_id == fid)
        ).scalars().all()
        for o in obs_rows:
            d = o.detail or {}
            # katana / feroxbuster sample lists
            sample = d.get("sample")
            if isinstance(sample, list):
                for s in sample:
                    try:
                        p = _up(str(s)).path
                    except Exception:
                        continue
                    if p and _ADMIN_RE.search(p):
                        return True
            # wapiti finding `url` or `path` strings
            for key in ("url", "path", "endpoint"):
                v = d.get(key)
                if isinstance(v, str) and _ADMIN_RE.search(v):
                    return True
    return False


def arjun_params_for_url(db: Session, run_id: str, url: str) -> list[str]:
    """Param names arjun discovered on exactly this URL, matched by
    scheme+netloc+path (query/fragment ignored). Empty list when arjun didn't
    run on that URL or found nothing. Reads the arjun observation's `sample`
    detail (list of `http://host/path?p=1` seed URLs) and parses the query-
    string names out. Used by the dalfox POST / web_param_probe POST tiers so
    stored-XSS/SQLi body probes carry REAL field names instead of a generic
    guess that often misses the actual sink field."""
    from urllib.parse import parse_qs, urlparse as _up
    tp = _up(url)
    target_key = f"{tp.scheme}://{tp.netloc}{tp.path}"
    params: list[str] = []
    seen: set[str] = set()
    for fid in db.execute(
            select(Finding.id).where(Finding.run_id == run_id)).scalars().all():
        obs_rows = db.execute(
            select(FindingObservation).where(FindingObservation.finding_id == fid)
        ).scalars().all()
        for o in obs_rows:
            if o.source_tool != "arjun":
                continue
            sample = (o.detail or {}).get("sample")
            if not isinstance(sample, list):
                continue
            for seed_url in sample:
                try:
                    sp = _up(str(seed_url))
                except Exception:
                    continue
                seed_key = f"{sp.scheme}://{sp.netloc}{sp.path}"
                if seed_key != target_key:
                    continue
                q = parse_qs(sp.query, keep_blank_values=True)
                for name in q.keys():
                    name = (name or "").strip()
                    if name and name not in seen:
                        seen.add(name)
                        params.append(name)
    return params


# Path tails that mark a login / authentication entry point, most specific first. The crawl
# and content-discovery phases already surface these (e.g. /auth/login, /login, /signin), so
# the authenticated scan can find WHERE to log in without the operator typing a URL. Matched
# against the end of a discovered URL's path, so "/login" won't match "/mylogin".
_LOGIN_URL_HINTS = (
    "/auth/login", "/account/login", "/accounts/login", "/users/sign_in", "/user/login",
    "/admin/login", "/login", "/signin", "/sign-in", "/session/new", "/auth",
)


def detect_login_url(db: Session, scope: RunScope, *, base_url: str) -> str | None:
    """Best-guess login-form URL for one base (scheme://host[:port]), taken from what the
    recon/probe discovery ALREADY found — so an authenticated scan can log itself in without
    the operator supplying the URL.

    Scans the same discovered endpoint set as `webvuln_seed_urls` (katana crawl + feroxbuster
    content discovery, stored in each finding's `detail.sample`) for a path that looks like a
    login endpoint, preferring the most specific hint and, within a hint, the shortest path
    (closest to the bare login page, not a sub-page). In-scope host only. Returns None when
    nothing matches, in which case the scan simply runs unauthenticated as before. Makes no
    new requests — it only reads URLs discovery already recorded."""
    from urllib.parse import urljoin, urlparse

    base = base_url.rstrip("/") + "/"
    _parsed_base = urlparse(base_url)
    base_host = _parsed_base.hostname
    base_port = _parsed_base.port or (443 if _parsed_base.scheme == "https" else 80)
    cands: list[str] = []
    seen: set[str] = set()
    for fid in db.execute(select(Finding.id).where(Finding.run_id == scope.run_id)).scalars().all():
        for o in db.execute(
            select(FindingObservation).where(FindingObservation.finding_id == fid)
        ).scalars().all():
            sample = (o.detail or {}).get("sample")
            if not isinstance(sample, list):
                continue
            for u in sample:
                u = str(u).strip()
                if not u:
                    continue
                url = u if u.lower().startswith(("http://", "https://")) \
                    else urljoin(base, u.lstrip("/"))
                pu = urlparse(url)
                cand_port = pu.port or (443 if pu.scheme == "https" else 80)
                if pu.hostname != base_host or cand_port != base_port or url in seen:
                    continue
                seen.add(url)
                cands.append(url)
    for hint in _LOGIN_URL_HINTS:
        matches = [c for c in cands if urlparse(c).path.rstrip("/").lower().endswith(hint)]
        if matches:
            return sorted(matches, key=lambda c: len(urlparse(c).path))[0]
    return None


# Ports that actually front a TLS service — a tls_check (testssl.sh) only makes sense
# against one of these; run against a plain-HTTP/closed host it just errors out.
_TLS_PORTS = {443, 465, 563, 636, 853, 989, 990, 992, 993, 994, 995, 1443, 2376, 2484,
              3269, 4433, 5061, 5986, 6697, 8443, 9443, 9091, 10443}
_TLS_SVC_HINTS = ("https", "ssl", "tls", "imaps", "pop3s", "smtps", "ldaps", "ftps")


def has_tls_port(db: Session, run_id: str) -> bool | None:
    """Did nmap find a TLS-fronted service on this run? True if yes, False if nmap produced
    service findings but none is TLS, None if nmap hasn't produced any service finding yet
    (so a caller can avoid skipping a tls_check prematurely)."""
    saw_service = False
    for fid in db.execute(select(Finding.id).where(Finding.run_id == run_id)).scalars().all():
        for o in db.execute(
            select(FindingObservation).where(FindingObservation.finding_id == fid)
        ).scalars().all():
            if o.source_tool != "nmap_service_scan":
                continue
            saw_service = True
            d = o.detail or {}
            port = str(d.get("port", "")).strip()
            svc = str(d.get("service", "")).lower()
            if (port.isdigit() and int(port) in _TLS_PORTS) or any(h in svc for h in _TLS_SVC_HINTS):
                return True
    return False if saw_service else None


def smb_ports_from_findings(db: Session, run_id: str) -> list[str]:
    """Discovered SMB/NetBIOS ports (445/139) — for the Windows vuln-check pass."""
    out: list[str] = []
    for p in service_ports_from_findings(db, run_id):
        if p in ("445", "139"):
            out.append(p)
    return out


# Common Windows build/version → OS name, for resolving an NVD OS CPE. Keyed by the
# version prefix nmap reports (rdp-ntlm-info Product_Version, or smb-os-discovery).
_WIN_BUILD_OS = {
    "10.0.26100": "Windows Server 2025", "10.0.20348": "Windows Server 2022",
    "10.0.17763": "Windows Server 2019", "10.0.14393": "Windows Server 2016",
    "6.3": "Windows Server 2012 R2", "6.2": "Windows Server 2012",
    "6.1": "Windows Server 2008 R2", "6.0": "Windows Server 2008",
    "5.2": "Windows Server 2003",
}


def os_hint_from_findings(db: Session, run_id: str) -> str | None:
    """Best-effort Windows OS name from this run's NSE evidence — rdp-ntlm-info's
    Product_Version build, or an 'smb-os-discovery' OS string — for OS-CPE CVE matching.
    None when nothing usable was detected (e.g. a hardened host that revealed no OS)."""
    for fid in db.execute(select(Finding.id).where(Finding.run_id == run_id)).scalars().all():
        for o in db.execute(
            select(FindingObservation).where(FindingObservation.finding_id == fid)
        ).scalars().all():
            if o.source_tool != "host_scripts":
                continue
            detail = str((o.detail or {}).get("detail", ""))
            # Direct OS name (smb-os-discovery): "Windows Server 2019 Standard ..."
            m = re.search(r"Windows Server \d{4}(?: R2)?", detail)
            if m:
                return m.group(0)
            # Build number (rdp-ntlm-info): Product_Version: 10.0.17763
            m = re.search(r"Product_Version:\s*([\d.]+)", detail)
            if m:
                build = m.group(1)
                for prefix, name in _WIN_BUILD_OS.items():
                    if build == prefix or build.startswith(prefix + "."):
                        return name
    return None


def os_cpe_findings(db: Session, run_id: str, *, matcher=None, limit: int = 10) -> int:
    """OS-level CVE leads: for the detected Windows OS version, surface the top critical
    CVEs affecting that OS CPE (via NVD). These are version-based LEADS (patch level
    unknown), so they are recorded as candidates and flow through the same confirmation
    path (nuclei/KEV) — KEV membership promotes them to exploit-available, else they stay
    leads. Deduped, bounded, offline-safe. Returns how many were created."""
    os_name = os_hint_from_findings(db, run_id)
    if not os_name:
        return 0
    if matcher is None:
        from .cve import os_cpe_cve_match as matcher
    try:
        matches = matcher(os_name) or []
    except Exception:
        return 0
    seen = _run_cve_ids(db, run_id)
    created = 0
    for m in matches[:limit]:
        cve = str(m.get("cve_id", "")).strip().upper()
        if not cve or cve in seen:
            continue
        seen.add(cve)
        sev = str(m.get("severity", "info"))
        score = m.get("cvss")
        title = f"{cve}" + (f" (CVSS {score:g})" if isinstance(score, (int, float)) else "") + \
            f" — {os_name} (OS version lead, patch unverified)"
        finding = Finding(run_id=run_id, title=title, status=FindingStatus.CANDIDATE.value,
                          severity=sev, description=str(m.get("description", ""))[:400])
        db.add(finding)
        db.flush()
        detail = {"cve": cve, "os": os_name, "basis": f"NVD OS CPE ({os_name}) — patch level unverified"}
        if score is not None:
            detail["cvss"] = score
        db.add(FindingObservation(finding_id=finding.id, source_tool="nvd_os_cpe", detail=detail))
        db.flush()
        ledger.record_event(db, run_id, "finding.candidate",
                            {"finding_id": finding.id, "title": title, "severity": sev,
                             "source": "nvd_os_cpe"})
        created += 1
    return created


def _run_cve_ids(db: Session, run_id: str) -> set[str]:
    """CVE ids already present on this run's findings (from vulners or the NVD fallback),
    so the two matchers don't duplicate each other."""
    ids: set[str] = set()
    for fid in db.execute(select(Finding.id).where(Finding.run_id == run_id)).scalars().all():
        for o in db.execute(
            select(FindingObservation).where(FindingObservation.finding_id == fid)
        ).scalars().all():
            cve = str((o.detail or {}).get("cve", "")).strip().upper()
            if cve:
                ids.add(cve)
    return ids


def nvd_cpe_findings(db: Session, run_id: str, *, matcher=None, limit_services: int = 8) -> int:
    """Fallback CVE matching via NVD's CPE dictionary: for each service with a detected
    product+version (from nmap -sV), ask NVD which CVEs affect that exact version — so CVE
    coverage doesn't depend on vulners.com being reachable. Deduped against existing CVE
    findings, bounded, offline-safe. Returns how many new CVE findings were created."""
    if matcher is None:
        from .cve import cpe_cve_match as matcher

    seen = _run_cve_ids(db, run_id)
    created = 0
    svc_findings = db.execute(
        select(Finding.id).where(Finding.run_id == run_id)
    ).scalars().all()

    services: list[tuple[str, str, str]] = []  # (product, version, port)
    for fid in svc_findings:
        for o in db.execute(
            select(FindingObservation).where(FindingObservation.finding_id == fid)
        ).scalars().all():
            if o.source_tool != "nmap_service_scan":
                continue
            d = o.detail or {}
            prod = str(d.get("product_name", "")).strip()
            ver = str(d.get("version", "")).strip()
            port = str(d.get("port", "")).strip()
            if prod and ver:
                services.append((prod, ver, port))

    for prod, ver, port in services[:limit_services]:
        try:
            matches = matcher(prod, ver) or []
        except Exception:
            matches = []
        for m in matches:
            cve = str(m.get("cve_id", "")).strip().upper()
            if not cve or cve in seen:
                continue
            seen.add(cve)
            sev = str(m.get("severity", "info"))
            score = m.get("cvss")
            title = f"{cve}" + (f" (CVSS {score:g})" if isinstance(score, (int, float)) else "")
            if port:
                title += f" on port {port}"
            finding = Finding(run_id=run_id, title=title,
                              status=FindingStatus.CANDIDATE.value, severity=sev,
                              description=str(m.get("description", ""))[:400])
            db.add(finding)
            db.flush()
            detail = {"cve": cve, "basis": "NVD CPE match (vulners fallback)"}
            if score is not None:
                detail["cvss"] = score
            if port:
                detail["port"] = port
            db.add(FindingObservation(finding_id=finding.id, source_tool="nvd_cpe", detail=detail))
            db.flush()
            ledger.record_event(db, run_id, "finding.candidate",
                                {"finding_id": finding.id, "title": title, "severity": sev,
                                 "source": "nvd_cpe"})
            created += 1
    return created


# --------------------------------------------------------------------------- #
# External authenticated-scanner intel: Tenable.sc (live API) + .nessus import.
# Read-only, P0 passive. Results come from an AUTHORIZED authenticated scan, so they are
# real on-target evidence — recorded as CONFIRMED, used to corroborate (and promote) the
# active scan's own CVE findings, and `exploit=true` is treated like CISA KEV.
# --------------------------------------------------------------------------- #
def tenable_configured() -> bool:
    """True when Tenable.sc creds are available — either all three env vars (URL + both API
    keys) OR V1's credentials file (~/.vapt_ai/tenable.json, overridable via
    VAPT_TENABLE_CREDS). So an existing V1 setup is detected without copying secrets into
    .env. Values are read by name/file; they never enter the ledger."""
    if all(os.environ.get(k, "").strip() for k in
           ("VAPT_TENABLE_URL", "VAPT_TENABLE_ACCESS_KEY", "VAPT_TENABLE_SECRET_KEY")):
        return True
    import json as _json
    path = os.environ.get("VAPT_TENABLE_CREDS", os.path.expanduser("~/.vapt_ai/tenable.json"))
    try:
        with open(path) as f:
            c = _json.load(f)
        return all(str(c.get(k, "")).strip() for k in ("host", "access_key", "secret_key"))
    except Exception:
        return False


def _run_intel_tool(db: Session, scope: RunScope, harness: GovernedHarness,
                    *, tool_id: str, args: dict, task_id: str) -> list[Observation]:
    """Run a P0 intel tool through the harness and normalize its output. Returns [] when the
    tool is denied, unavailable, or produced no usable result (honest, no fabrication)."""
    outcome = harness.run_action(
        db, ctx_for(scope, task_id=task_id, agent=AgentRole.SCAN, tool_id=tool_id, args=args)
    )
    if not outcome.executed or not outcome.result or outcome.result.outcome != "ok":
        return []
    return normalize(tool_id, outcome.result.observations)


def _cve_to_finding(db: Session, run_id: str) -> dict[str, str]:
    """Map each CVE id already on this run to one of its finding ids (for corroboration)."""
    out: dict[str, str] = {}
    for fid in db.execute(select(Finding.id).where(Finding.run_id == run_id)).scalars().all():
        for o in db.execute(
            select(FindingObservation).where(FindingObservation.finding_id == fid)
        ).scalars().all():
            cve = str((o.detail or {}).get("cve", "")).strip().upper()
            if cve:
                out.setdefault(cve, fid)
    return out


def _mark_exploit_intel(db: Session, run_id: str, finding_id: str, cve: str, source: str,
                        frameworks: str) -> None:
    """Flag a finding as having a known exploit (same tier as CISA KEV), from the intel
    source's exploit-available signal."""
    basis = f"{source}: exploit available" + (f" ({frameworks})" if frameworks else "")
    db.add(FindingObservation(finding_id=finding_id, source_tool="exploit-intel",
                              detail={"cve": cve, "basis": basis}))
    db.flush()
    ledger.record_event(db, run_id, "finding.exploit_available",
                        {"finding_id": finding_id, "cve": cve, "basis": basis})


def ingest_external_intel(db: Session, scope: RunScope, harness: GovernedHarness,
                          *, nessus_path: str | None = None) -> int:
    """Pull authenticated-scanner intel and fold it into this run. Tenable.sc (live) runs
    when it's configured AND its shim is available; a .nessus export is imported when a
    workspace-relative path is supplied. Each intel finding either CORROBORATES an existing
    CVE finding (promoting it to confirmed) or becomes a new confirmed finding. Deduped,
    bounded, fully best-effort (any tool failure degrades to a no-op). Returns how many
    findings were created or corroborated."""
    observations: list[Observation] = []
    if tenable_configured() and harness.tool_available("tenable_scan", {"target": scope.target}):
        observations += _run_intel_tool(db, scope, harness, tool_id="tenable_scan",
                                        args={}, task_id="tenable")
    if nessus_path:
        observations += _run_intel_tool(db, scope, harness, tool_id="nessus_import",
                                        args={"path": nessus_path}, task_id="nessus")
    if not observations:
        return 0

    cve_to_fid = _cve_to_finding(db, scope.run_id)
    touched = 0
    for o in observations:
        detail = dict(o.detail or {})
        cve = str(detail.get("cve", "")).strip().upper()
        sev = o.severity
        source = str(detail.get("source", "intel"))
        exploit = bool(detail.get("exploit"))
        frameworks = str(detail.get("frameworks", ""))
        # Skip low-value corroboration noise: an info/low item with no CVE is usually just a
        # re-listing of an open port the active scan already has.
        if not cve and sev not in ("medium", "high", "critical"):
            continue

        if cve and cve in cve_to_fid:
            fid = cve_to_fid[cve]
            f = db.get(Finding, fid)
            if f is not None and f.status != FindingStatus.CONFIRMED.value:
                f.status = FindingStatus.CONFIRMED.value
            db.add(FindingObservation(
                finding_id=fid, source_tool=source,
                detail={**detail, "basis": f"corroborated by {source}: {detail.get('basis', '')}"}))
            db.flush()
            ledger.record_event(db, scope.run_id, "finding.confirmed",
                                {"finding_id": fid, "basis": f"{source} corroboration: {cve}"})
            if exploit:
                _mark_exploit_intel(db, scope.run_id, fid, cve, source, frameworks)
            touched += 1
            continue

        # New confirmed finding straight from the authenticated scanner.
        finding = Finding(run_id=scope.run_id, title=o.title,
                          status=FindingStatus.CONFIRMED.value, severity=sev,
                          description=str(detail.get("solution", ""))[:400])
        db.add(finding)
        db.flush()
        db.add(FindingObservation(finding_id=finding.id, source_tool=source, detail=detail))
        db.flush()
        ledger.record_event(db, scope.run_id, "finding.confirmed",
                            {"finding_id": finding.id, "title": o.title, "severity": sev,
                             "source": source})
        if cve:
            cve_to_fid[cve] = finding.id
        if exploit:
            _mark_exploit_intel(db, scope.run_id, finding.id, cve, source, frameworks)
        touched += 1
    return touched


def confirmed_ids_for_run(db: Session, run_id: str) -> list[str]:
    from sqlalchemy import select as _select

    return list(
        db.execute(
            _select(Finding.id).where(
                Finding.run_id == run_id,
                Finding.status == FindingStatus.CONFIRMED.value,
            )
        ).scalars().all()
    )


# --- cross-run engagement memory -----------------------------------------
# Normalizer for finding titles: collapses run-specific suffixes/prefixes so
# "SSTI confirmed (param offer, engine Jinja2)" and "SSTI confirmed (param
# offer, engine Jinja2) (COPY 2)" collapse to the same identity for dedup.
# Case-insensitive, whitespace-folded, trailing-noise stripped.
_TITLE_NOISE_RE = re.compile(
    r"\s*(?:"
    r"\(copy\s*\d+\)|"
    r"\[run[-:\s_]*[A-Za-z0-9-]{3,}\]|"
    r"#\d+\s*$|"
    r"\s+at\s+\d{4}-\d{2}-\d{2}.*$"
    r")\s*",
    re.IGNORECASE,
)


def _normalize_finding_title(title: str) -> str:
    """Lowercase + whitespace-fold + strip run-specific noise. Used as part of
    the dedup key for engagement_prior_findings so copies / re-runs collapse."""
    if not title:
        return ""
    t = _TITLE_NOISE_RE.sub(" ", str(title).strip().lower())
    return re.sub(r"\s+", " ", t).strip()


def engagement_prior_findings(
    db: Session,
    scope: RunScope,
    *,
    limit: int = 40,
    statuses: tuple[str, ...] = ("confirmed", "candidate"),
    min_severity: str = "info",
) -> list[dict]:
    """Return deduplicated findings from PRIOR runs of this engagement
    (excludes the current run). Grouped by (normalized_title, severity,
    source_tool); each group becomes one dict with occurrence stats:
      {"title": <representative title>, "severity": <sev>,
       "source_tool": <tool>, "seen": <int>, "last_seen": <ISO date>,
       "last_run_id": <uuid>}
    Newest-first, capped at `limit`.

    Returns [] cleanly when:
      * This is the first run of the engagement (no priors).
      * `scope.engagement_id` is unset for any reason.
      * Any DB error (fail-safe — prior-findings context is advisory, never
        critical to running the engagement).

    `statuses` lets callers restrict to CONFIRMED only (reporting) or
    include CANDIDATE (planning/exploration).
    `min_severity` filters out anything below the given level; the default
    "info" keeps everything (useful for the planner; the reporter would want
    "medium" or higher).
    """
    from sqlalchemy import select as _select

    _SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    try:
        _min = _SEV_RANK.get(min_severity.lower(), 0)
    except Exception:
        _min = 0

    try:
        from vapt_persistence.models import Run as _Run
        # RunScope doesn't carry engagement_id — look it up via scope.run_id.
        current_run = db.execute(
            _select(_Run).where(_Run.id == scope.run_id)
        ).scalars().first()
        if current_run is None or not getattr(current_run, "engagement_id", None):
            return []
        engagement_id = current_run.engagement_id
        # Prior-run IDs — same engagement, not THIS run.
        prior_run_ids = db.execute(
            _select(_Run.id).where(
                _Run.engagement_id == engagement_id,
                _Run.id != scope.run_id,
            )
        ).scalars().all()
        prior_run_ids = list(prior_run_ids)
        if not prior_run_ids:
            return []
        # Pull findings for all prior runs in ONE query, newest-first.
        rows = db.execute(
            _select(Finding).where(
                Finding.run_id.in_(prior_run_ids),
                Finding.status.in_(statuses),
            ).order_by(Finding.created_at.desc())
        ).scalars().all()
        # Dedup by (normalized_title, severity, source_tool). Source_tool
        # comes from the FIRST observation attached to each finding — use
        # "unknown" when a finding has no observations (shouldn't happen
        # under normal paths; defensive).
        groups: dict[tuple[str, str, str], dict] = {}
        for f in rows:
            sev = str(f.severity or "info").lower()
            if _SEV_RANK.get(sev, 0) < _min:
                continue
            norm_title = _normalize_finding_title(f.title or "")
            if not norm_title:
                continue
            # First observation's source_tool.
            obs = db.execute(
                _select(FindingObservation.source_tool)
                .where(FindingObservation.finding_id == f.id)
                .limit(1)
            ).scalars().first()
            source_tool = str(obs or "unknown").lower()
            key = (norm_title, sev, source_tool)
            created_iso = (f.created_at.isoformat()
                           if getattr(f, "created_at", None) else "")
            if key not in groups:
                groups[key] = {
                    "title": f.title or "",   # preserve first (newest) title verbatim
                    "severity": sev,
                    "source_tool": source_tool,
                    "seen": 1,
                    "last_seen": created_iso,
                    "last_run_id": f.run_id,
                }
            else:
                groups[key]["seen"] += 1
        # Rank: severity desc, then seen desc, then last_seen desc.
        out = sorted(
            groups.values(),
            key=lambda g: (
                -_SEV_RANK.get(g["severity"], 0),
                -g["seen"],
                g["last_seen"],
            ),
            reverse=False,
        )
        # Flip last_seen reverse so NEWER is first within same (sev, seen):
        out.sort(key=lambda g: (
            -_SEV_RANK.get(g["severity"], 0),
            -g["seen"],
            # Negative isoformat sort → newest first. isoformat is lexically
            # comparable, so simply reverse the comparison via sort reverse
            # key below.
            g["last_seen"],
        ))
        # Simpler: just reverse-sort within the tiebreaker.
        out = sorted(
            groups.values(),
            key=lambda g: (
                -_SEV_RANK.get(g["severity"], 0),
                -g["seen"],
            ),
        )
        # Now stably break ties on last_seen by sorting newest-first within.
        out.sort(key=lambda g: g["last_seen"], reverse=True)
        # Final re-sort by severity+seen (stable, so last_seen order preserved
        # within ties).
        out.sort(
            key=lambda g: (
                -_SEV_RANK.get(g["severity"], 0),
                -g["seen"],
            ),
        )
        return out[:limit]
    except Exception:
        # Prior-findings context is advisory — never let a DB blip take down
        # a run. Return [] and let the LLM plan without the extra context.
        return []


def summarize_prior_findings_for_llm(priors: list[dict], *, cap_bytes: int = 3500) -> str:
    """Compact single-string rendering of engagement_prior_findings() output
    for direct injection into an LLM prompt. One line per finding, severity-
    tagged, with seen-count + last-date. Truncates to `cap_bytes` with a
    trailing "(+N more)" if the list is long.

    Returns "" on an empty input list — callers can `if block:` to decide
    whether to add a surrounding "Prior findings:" header to the prompt."""
    if not priors:
        return ""
    lines: list[str] = []
    for p in priors:
        sev = p.get("severity", "info")
        title = str(p.get("title", ""))[:140]
        seen = int(p.get("seen", 1))
        last = str(p.get("last_seen", ""))[:10]  # YYYY-MM-DD only
        tool = str(p.get("source_tool", ""))
        suffix = f" (seen {seen}×, last {last}, via {tool})" if last else \
                 f" (seen {seen}×, via {tool})"
        lines.append(f"- [{sev}] {title}{suffix}")
    text = "\n".join(lines)
    if len(text.encode("utf-8")) <= cap_bytes:
        return text
    # Truncate progressively from the tail.
    kept: list[str] = []
    size = 0
    for ln in lines:
        _add = len(ln.encode("utf-8")) + 1
        if size + _add > cap_bytes - 40:
            break
        kept.append(ln)
        size += _add
    remainder = len(lines) - len(kept)
    if remainder > 0:
        kept.append(f"- (+{remainder} more older findings omitted for brevity)")
    return "\n".join(kept)


def _existing_candidate(db: Session, run_id: str, obs: Observation) -> Finding | None:
    """A finding already persisted for this run with the SAME title + source tool. Used to
    collapse duplicates when a re-entrant node repeats a step — e.g. the probe node re-running
    host_scripts after a mid-node approval interrupt. An identical (title, tool) pair is the
    same observation, so we return the existing row instead of inserting a visible duplicate."""
    rows = db.execute(
        select(Finding).where(Finding.run_id == run_id, Finding.title == obs.title)
    ).scalars().all()
    for f in rows:
        srcs = db.execute(
            select(FindingObservation.source_tool).where(FindingObservation.finding_id == f.id)
        ).scalars().all()
        if obs.source_tool in srcs:
            return f
    return None


def persist_candidate(db: Session, run_id: str, obs: Observation) -> Finding:
    dup = _existing_candidate(db, run_id, obs)
    if dup is not None:            # idempotent: don't double-persist a repeated observation
        return dup
    finding = Finding(
        run_id=run_id,
        title=obs.title,
        status=FindingStatus.CANDIDATE.value,
        severity=obs.severity,
        description=f"Observed by {obs.source_tool}.",
    )
    db.add(finding)
    db.flush()
    db.add(FindingObservation(finding_id=finding.id, source_tool=obs.source_tool, detail=obs.detail))
    db.flush()
    ledger.record_event(
        db, run_id, "finding.candidate",
        {"finding_id": finding.id, "title": obs.title, "severity": obs.severity},
    )
    return finding


# --------------------------------------------------------------------------- #
# Recon
# --------------------------------------------------------------------------- #
def recon_phase(db: Session, scope: RunScope, harness: GovernedHarness) -> list[str]:
    """Establish the asset is reachable (passive + bounded). Returns asset refs."""
    import ipaddress

    ledger.record_event(db, scope.run_id, "phase.recon", {})
    # DNS resolution of a bare IP is meaningless (dnsx expects a name) and only ever
    # fails — skip it for IP targets rather than logging a spurious failure. The scan
    # phase establishes reachability for those.
    try:
        ipaddress.ip_address(scope.target)
        ledger.record_event(db, scope.run_id, "recon.note",
                            {"detail": "ip target; dns resolution not applicable"})
        return [scope.target]
    except ValueError:
        pass
    outcome = harness.run_action(
        db, ctx_for(scope, task_id="recon", agent=AgentRole.RECON,
                    tool_id="dns_resolve", args={"target": scope.target})
    )
    return [scope.target] if outcome.executed else []


# --------------------------------------------------------------------------- #
# Scan (one action) — the unit both callers share. The caller decides what to do
# when the outcome asks for approval (sequential: record+skip; graph: interrupt).
# --------------------------------------------------------------------------- #
def scan_action(
    db: Session, scope: RunScope, harness: GovernedHarness,
    *, tool_id: str, args: dict, task_id: str,
) -> ScanStep:
    """Dispatch a scan action through the harness. If the broker raises (an argv-builder
    ValueError, a Python-level shim bug, an OSError), the harness has already recorded
    `action.executed outcome=failed` with the exception's reason; we catch here and
    synthesize a non-executed ActionOutcome so the scan node's existing "coverage gap"
    path takes over instead of crashing the engagement.

    The bloghub-ext.nuasec.com run 2026-10-28 died at scan-10 because dom_xss_probe's
    argv builder raised `ValueError: dom_xss_probe needs comma-separated urls` and the
    exception propagated up through scan_action → scan node → Celery task. The ledger
    stopped at event 60 (the harness's own action.executed row for the failure) and the
    remaining scan steps never ran."""
    try:
        outcome = harness.run_action(
            db, ctx_for(scope, task_id=task_id, agent=AgentRole.SCAN,
                        tool_id=tool_id, args=args)
        )
    except Exception as e:
        # Harness has already written the action.executed/failed ledger event; the
        # digest + key would have been recomputed from ctx. Return a non-executed
        # outcome so the scan node continues to the next tool. Store the reason
        # for the "coverage_gaps" log line.
        from vapt_domain.enums import PolicyDecision  # noqa: PLC0415
        reason = f"broker raised: {type(e).__name__}: {str(e)[:200]}"
        merged = {"target": scope.target, **args}
        digest = action_digest(tool_id, "default", str(merged.get("target", "")), merged)
        key = idempotency_key(scope.run_id, task_id, digest)
        outcome = ActionOutcome(PolicyDecision.DENY, False, reason, digest, key)
    step = ScanStep(tool_id=tool_id, task_id=task_id, outcome=outcome)
    if outcome.executed:
        step.candidate_ids = _candidates_from(db, scope.run_id, tool_id, outcome)
    return step


def execute_scan_after_approval(
    db: Session, scope: RunScope, harness: GovernedHarness,
    *, tool_id: str, args: dict, task_id: str,
) -> ScanStep:
    """Run an approved scan action via the harness's post-approval path (re-validates
    scope), then normalize its output into candidate findings. Same broker-raise
    protection as scan_action — a buggy argv builder cannot kill the engagement."""
    try:
        outcome = harness.execute_approved(
            db, ctx_for(scope, task_id=task_id, agent=AgentRole.SCAN,
                        tool_id=tool_id, args=args)
        )
    except Exception as e:
        from vapt_domain.enums import PolicyDecision  # noqa: PLC0415
        reason = f"broker raised: {type(e).__name__}: {str(e)[:200]}"
        merged = {"target": scope.target, **args}
        digest = action_digest(tool_id, "default", str(merged.get("target", "")), merged)
        key = idempotency_key(scope.run_id, task_id, digest)
        outcome = ActionOutcome(PolicyDecision.DENY, False, reason, digest, key)
    step = ScanStep(tool_id=tool_id, task_id=task_id, outcome=outcome)
    if outcome.executed:
        step.candidate_ids = _candidates_from(db, scope.run_id, tool_id, outcome)
    return step


def _candidates_from(db: Session, run_id: str, tool_id: str, outcome: ActionOutcome) -> list[str]:
    # Only mine findings from a tool that actually succeeded. A failed/unknown run
    # (binary missing, wrong binary, non-zero exit) produces error text, not results —
    # never turn that into findings.
    if not outcome.result or outcome.result.outcome != "ok":
        return []
    obs = normalize(tool_id, outcome.result.observations)
    ids: list[str] = []
    for o in obs:
        ids.append(persist_candidate(db, run_id, o).id)
    return ids


# --------------------------------------------------------------------------- #
# Validate (one candidate) — independent re-check; only this marks CONFIRMED.
# --------------------------------------------------------------------------- #
# --------------------------------------------------------------------------- #
# Attack (one PoC per confirmed finding) — opt-in, and ALWAYS human-gated.
# --------------------------------------------------------------------------- #
_URL_RE = re.compile(r"(https?)://[^\s/:]+(?::(\d+))?")


def poc_args_for(db: Session, finding_id: str) -> dict:
    """PoC request args (scheme/port) aimed at the finding's ACTUAL service, so an
    http_evidence PoC hits the real confirmed endpoint instead of a hardcoded https/443.
    For an HTTP-service finding, the scheme+port come from its http_probe evidence line;
    otherwise it targets the host's plain-HTTP service (the reachable web surface)."""
    obs = db.execute(
        select(FindingObservation).where(FindingObservation.finding_id == finding_id)
    ).scalars().all()
    for o in obs:
        if o.source_tool != "http_probe":
            continue
        m = _URL_RE.search(str((o.detail or {}).get("line", "")))
        if m:
            args: dict = {"scheme": m.group(1)}
            if m.group(2):
                args["port"] = m.group(2)
            return args
    return {"scheme": "http"}  # non-HTTP finding: evidence against the base web service


def _is_http_finding(db: Session, finding_id: str) -> bool:
    """A finding that represents an HTTP service (probed by http_probe) — the only kind
    the HTTP evidence / screenshot playbooks can meaningfully act on."""
    obs = db.execute(
        select(FindingObservation).where(FindingObservation.finding_id == finding_id)
    ).scalars().all()
    return any(o.source_tool == "http_probe" for o in obs)


# Playbooks whose PoC only makes sense against an HTTP service.
_HTTP_PLAYBOOKS = {"http_evidence", "screenshot"}


def poc_targets_for(db: Session, run_id: str, playbook_id: str) -> list[str]:
    """Which confirmed findings a playbook should actually run against — so an HTTP PoC
    isn't fired at every SMB/RDP/CVE finding. HTTP playbooks target only HTTP-service
    findings; a non-HTTP playbook falls back to all confirmed findings."""
    confirmed = confirmed_ids_for_run(db, run_id)
    if playbook_id in _HTTP_PLAYBOOKS:
        return [fid for fid in confirmed if _is_http_finding(db, fid)]
    return confirmed


def propose_attack(
    db: Session, scope: RunScope, harness: GovernedHarness,
    *, task_id: str, tool_id: str = "burp_request", args: dict | None = None,
) -> ActionOutcome:
    """Propose one PoC action for the ATTACK agent. Never executes: it forces a human
    approval (the ATTACK manifest always escalates) and returns the approval outcome."""
    ctx = ctx_for(scope, task_id=task_id, agent=AgentRole.ATTACK, tool_id=tool_id, args=args or {})
    return harness.require_approval(
        db, ctx, reason="attack agent: PoC requires explicit human approval"
    )


def execute_attack_after_approval(
    db: Session, scope: RunScope, harness: GovernedHarness,
    *, task_id: str, tool_id: str = "burp_request", args: dict | None = None,
) -> ActionOutcome:
    ctx = ctx_for(scope, task_id=task_id, agent=AgentRole.ATTACK, tool_id=tool_id, args=args or {})
    return harness.execute_approved(db, ctx)


def record_poc_evidence(
    db: Session, finding_id: str, *, playbook_id: str, tool_id: str, outcome: ActionOutcome
) -> None:
    """Link PoC evidence from an executed, approved playbook to its confirmed finding.
    Stores a bounded summary (tool outcome + a short stdout excerpt / artifact path),
    never raw captures or secrets."""
    excerpt = ""
    if outcome.result and outcome.result.observations:
        first = outcome.result.observations[0]
        if isinstance(first, dict):
            excerpt = str(first.get("stdout", first.get("note", "")))[:300]
    db.add(FindingObservation(
        finding_id=finding_id,
        source_tool=f"poc:{playbook_id}",
        detail={"tool": tool_id, "outcome": outcome.result.outcome if outcome.result else "unknown",
                "evidence": excerpt},
    ))
    db.flush()


def validate_source_candidate(
    db: Session, finding_id: str, bundle_root: str
) -> bool:
    """Evidence-anchored validation for a static-analysis candidate: confirm only if the
    file it points at actually exists inside the uploaded bundle. This rejects findings
    with a missing or misattributed location (a hallucinated or stale path) rather than
    trusting analyzer output outright — candidate vs confirmed still holds for SAST.
    Returns True if confirmed."""
    import os

    finding = db.get(Finding, finding_id)
    if finding is None:
        return False
    obs = db.execute(
        select(FindingObservation).where(FindingObservation.finding_id == finding_id)
    ).scalars().all()
    confirmed = False
    for o in obs:
        detail = o.detail or {}
        rel = str(detail.get("file", "")).strip()
        if rel:
            # File-anchored (semgrep/gitleaks): confirm only if the file really exists
            # inside the bundle, refusing any path that escapes it.
            root = os.path.realpath(bundle_root)
            full = os.path.realpath(os.path.join(root, rel.lstrip("/")))
            if (full == root or full.startswith(root + os.sep)) and os.path.exists(full):
                confirmed = True
                break
        elif str(detail.get("advisory", "")).strip() or str(detail.get("package", "")).strip():
            # Advisory-anchored (dependency audit): the advisory id / package is the
            # evidence; there is no source line to verify.
            confirmed = True
            break
    run_id = finding.run_id
    if confirmed:
        finding.status = FindingStatus.CONFIRMED.value
        db.flush()
        ledger.record_event(db, run_id, "finding.confirmed",
                            {"finding_id": finding_id, "basis": "source location exists"})
    else:
        finding.status = FindingStatus.INCONCLUSIVE.value
        db.flush()
        ledger.record_event(db, run_id, "finding.inconclusive",
                            {"finding_id": finding_id, "basis": "source location not found"})
    return confirmed


def _finding_port(db: Session, finding_id: str) -> str | None:
    """The port a finding is about, from its first observation detail (if any)."""
    obs = db.execute(
        select(FindingObservation).where(FindingObservation.finding_id == finding_id)
    ).scalars().all()
    for o in obs:
        p = str((o.detail or {}).get("port", "")).strip()
        if p.isdigit():
            return p
    return None


def cve_ref_for(db: Session, finding_id: str) -> tuple[str, str | None, str] | None:
    """(cve_id, port, scheme) if this finding came from nmap vulners, else None.
    scheme defaults to http unless the port is a common TLS port."""
    obs = db.execute(
        select(FindingObservation).where(FindingObservation.finding_id == finding_id)
    ).scalars().all()
    for o in obs:
        if o.source_tool not in ("nmap_vuln", "nvd_cpe", "nvd_os_cpe"):  # version-matched CVEs
            continue
        d = o.detail or {}
        cve = str(d.get("cve", "")).strip()
        if not cve:
            continue
        port = str(d.get("port", "")).strip() or None
        scheme = "https" if port in ("443", "8443", "9443") else "http"
        return cve, port, scheme
    return None


def _is_os_cpe_lead(db: Session, finding_id: str) -> bool:
    """True if this finding is an OS-version CVE lead (source nvd_os_cpe) — matched from the
    detected OS, not an on-target service. nuclei can't test these, so the nuclei step is
    skipped for them."""
    obs = db.execute(
        select(FindingObservation).where(FindingObservation.finding_id == finding_id)
    ).scalars().all()
    return any(o.source_tool == "nvd_os_cpe" for o in obs)


def _result_has_stdout(result) -> bool:
    if not result or result.outcome != "ok":
        return False
    for o in result.observations or []:
        if isinstance(o, dict) and str(o.get("stdout", "")).strip():
            return True
    return False


# CVE families we can confirm ON-TARGET with a SAFE (P1, non-crashing) NSE check, and the
# tool + default port that does it. A VULNERABLE result here is real proof, so an OS-CPE
# lead for one of these is promoted from inconclusive to CONFIRMED. Extensible: add a row
# when a safe check for another CVE family is registered. (ms17-010 covers the EternalBlue
# family CVE-2017-0143..0148.)
_SAFE_CVE_CHECKS: dict[str, tuple[str, str]] = {
    f"CVE-2017-014{n}": ("win_vuln_scan", "445") for n in range(3, 9)
}


def _safe_cve_check(cve: str) -> tuple[str, str] | None:
    """(tool_id, default_port) for a safe on-target check of this CVE, or None."""
    return _SAFE_CVE_CHECKS.get((cve or "").upper().strip())


def _nse_reports_vulnerable(result) -> bool:
    """True if a vuln NSE check's output contains a positive VULNERABLE verdict (and not
    only 'NOT VULNERABLE'). Mirrors the `_win_vuln` normalizer's own detection."""
    if not result or result.outcome != "ok":
        return False
    for o in result.observations or []:
        text = str((o or {}).get("stdout", "")) if isinstance(o, dict) else ""
        # Strip the negative form so a lone "NOT VULNERABLE" doesn't count as a hit.
        if "VULNERABLE" in text.replace("NOT VULNERABLE", ""):
            return True
    return False


def _searchsploit_has_hit(result) -> bool:
    """True if searchsploit -j returned at least one Exploit-DB entry."""
    if not result or result.outcome != "ok":
        return False
    import json as _json

    for o in result.observations or []:
        text = str((o or {}).get("stdout", "")) if isinstance(o, dict) else ""
        if not text.strip():
            continue
        try:
            data = _json.loads(text[text.index("{"):])
        except Exception:
            continue
        if isinstance(data, dict) and data.get("RESULTS_EXPLOIT"):
            return True
    return False


def validate_cve_candidate(
    db: Session, scope: RunScope, harness: GovernedHarness, finding_id: str,
    *, exploit_check=None,
) -> str:
    """Confirm a version-matched CVE (from nmap vulners), ported from V1's
    validate_cve_on_target but governed and evidence-linked. Returns one of:
      'confirmed'         — the CVE's nuclei template actually fired on the host;
      'exploit_available' — unconfirmed on-target, but public exploitation intel exists
                            (CISA KEV / NVD exploit reference — via API, no local DB);
      'inconclusive'      — version-match only, no template hit, no known exploit.
    Each outcome attaches evidence to the finding and records a ledger event. `exploit_check`
    is an injection point for the exploitation-intel lookup (tests pass a stub)."""
    finding = db.get(Finding, finding_id)
    ref = cve_ref_for(db, finding_id)
    if finding is None or ref is None:
        return "inconclusive"
    cve, port, scheme = ref
    base = {"cve": cve, "scheme": scheme}
    if port:
        base["port"] = port

    # 0) Safe on-target NSE check for CVE families we can confirm without risk (ms17-010,
    #    etc.). A VULNERABLE verdict is real on-target proof — the strongest confirmation
    #    we can give, so it outranks a template hit. The check tool is P1 (safe), so it
    #    runs without approval. Only fires for CVEs in `_SAFE_CVE_CHECKS`.
    check = _safe_cve_check(cve)
    if check:
        tool_id, default_port = check
        ports = smb_ports_from_findings(db, scope.run_id) or [default_port]
        nse = harness.run_action(
            db, ctx_for(scope, task_id=f"cvn-{finding_id[:8]}", agent=AgentRole.VALIDATE,
                        tool_id=tool_id, args={"ports": ",".join(ports)})
        )
        if nse.executed and _nse_reports_vulnerable(nse.result):
            finding.status = FindingStatus.CONFIRMED.value
            db.add(FindingObservation(
                finding_id=finding_id, source_tool="win_vuln_scan",
                detail={"cve": cve, "basis": f"{tool_id} reported VULNERABLE on-target"}))
            db.flush()
            ledger.record_event(db, scope.run_id, "finding.confirmed",
                                {"finding_id": finding_id, "basis": f"{tool_id} on-target: {cve}"})
            return "confirmed"

    # 1) Targeted nuclei template — did the CVE actually fire against the host?
    #    SKIPPED for OS-CPE leads: nuclei-templates has no template for OS-level CVEs
    #    (SMB/RDP/PGM/PEAP RCEs, OS-bundled components), so `nuclei -id cve-xxxx` always
    #    exits 1 with no match and only produces a noisy "did not complete" coverage gap.
    #    Those leads are confirmed (if at all) by the safe NSE check above and KEV below.
    if not _is_os_cpe_lead(db, finding_id):
        nc = harness.run_action(
            db, ctx_for(scope, task_id=f"cvv-{finding_id[:8]}", agent=AgentRole.VALIDATE,
                        tool_id="nuclei_cve", args=dict(base))
        )
    else:
        nc = None
    if nc is not None and nc.executed and _result_has_stdout(nc.result):
        finding.status = FindingStatus.CONFIRMED.value
        db.add(FindingObservation(finding_id=finding_id, source_tool="nuclei",
                                  detail={"cve": cve, "basis": "nuclei template fired"}))
        db.flush()
        ledger.record_event(db, scope.run_id, "finding.confirmed",
                            {"finding_id": finding_id, "basis": f"nuclei template {cve} fired"})
        return "confirmed"

    # 2) Exploitation intel via public APIs (no local Exploit-DB): CISA KEV + NVD exploit
    #    references. A strong priority signal, not on-target proof.
    if exploit_check is None:
        from .cve import is_exploited as exploit_check  # lazy to avoid import cycle
    try:
        intel = exploit_check(cve) or {}
    except Exception:
        intel = {}
    if intel.get("exploited"):
        db.add(FindingObservation(finding_id=finding_id, source_tool="exploit-intel",
                                  detail={"cve": cve, "basis": intel.get("basis", "public exploit")}))
        db.flush()
        ledger.record_event(db, scope.run_id, "finding.exploit_available",
                            {"finding_id": finding_id, "cve": cve, "basis": intel.get("basis", "")})
        return "exploit_available"   # stays a candidate — a strong lead needing manual check

    # 3) Version-match only.
    finding.status = FindingStatus.INCONCLUSIVE.value
    db.flush()
    ledger.record_event(db, scope.run_id, "finding.inconclusive",
                        {"finding_id": finding_id, "basis": f"version-match only ({cve})"})
    return "inconclusive"


# Source tools whose findings assert "a service exists/responds on this port" — for those,
# a reachability re-probe IS a valid independent confirmation (the asserted fact is exactly
# that the service is reachable). A finding from an active vulnerability scanner (wapiti,
# nuclei, nikto, …) asserts a *vulnerability*, which reachability does NOT prove — confirming
# those on a mere port re-probe over-claims. Such findings stay `candidate` (reported but not
# independently verified) until an active re-verification tier confirms them.
_SERVICE_SOURCE_TOOLS = {"nmap_service_scan", "http_probe"}

_WAPITI_XSS_TITLE_RE = re.compile(
    r"wapiti:\s*Reflected Cross Site Scripting at (\S+)\s*\(param:\s*([^)]+)\)",
    re.IGNORECASE,
)
# Wapiti's finding title for an SQLi hit. Wapiti labels these as either
# "SQL Injection" (error-based / boolean reflection) or "Blind SQL Injection"
# (timing-based). Both become sqli_detect confirmation candidates.
_WAPITI_SQLI_TITLE_RE = re.compile(
    r"wapiti:\s*(?:Blind\s+)?SQL\s+Injection\s+at\s+(\S+)\s*\(param:\s*([^)]+)\)",
    re.IGNORECASE,
)

# Map CAPTURED tech/server tokens → sstimap engine name. We only emit an engine hint when the
# evidence is unambiguous: the token appears in a tech/server banner we actually captured for
# this run. Ambiguous stacks (plain "php", "node", "express") deliberately return None so
# sstimap probes everything (correct behaviour, not a guess). Keys are lowercased.
_ENGINE_BY_TOKEN = {
    # Jinja2 — Flask (uses Werkzeug + Jinja by default) and direct markers
    "flask": "Jinja2",
    "jinja": "Jinja2",
    "jinja2": "Jinja2",
    "werkzeug": "Jinja2",
    # Python WSGI servers — Jinja2 is the default template engine on all mainstream
    # Python web frameworks except Django (which has its own `django` token below).
    # Waitress/gunicorn/uwsgi serving a Python app without a Django marker is
    # Jinja2 in >95% of real stacks; this is deterministic from the captured server
    # token, not a per-run guess. If the stack IS Django, the `django` token below
    # takes precedence because dict insertion order is preserved and we iterate above.
    "waitress": "Jinja2",
    "gunicorn": "Jinja2",
    "uwsgi": "Jinja2",
    # Django — its own template language
    "django": "Django",
    # ERB — Ruby/Rails (Puma/Thin/Unicorn are the common WSGI servers)
    "rails": "ERB",
    "puma": "ERB",
    "thin": "ERB",
    "unicorn": "ERB",
    # Twig — Symfony
    "symfony": "Twig",
    "twig": "Twig",
    # Freemarker — JSP stacks that declare it
    "freemarker": "Freemarker",
    # Velocity
    "velocity": "Velocity",
    # Smarty
    "smarty": "Smarty",
}


_ENGINE_TOKEN_PRIORITY = (
    # Framework markers beat server markers — a Django app on gunicorn is Django,
    # not Jinja2, so check framework tokens first.
    "django", "jinja2", "jinja", "flask", "werkzeug", "rails", "symfony", "twig",
    "freemarker", "velocity", "smarty",
    # Server markers that default to Jinja2 on Python stacks (checked last so a
    # framework token can win if present).
    "waitress", "gunicorn", "uwsgi", "puma", "thin", "unicorn",
)


def infer_template_engine(db: Session, run_id: str) -> str | None:
    """Infer the server-side template engine from TECH/SERVER data the http_probe (httpx)
    normalizer already captured for this run, and from the whatweb report's own fields
    when present — nothing hardcoded, nothing guessed. Returns the sstimap `-e ENGINE`
    value if a captured token maps unambiguously; otherwise None (sstimap probes the full
    engine set, correct fallback).

    Resolution order: collect all tokens from http_probe/whatweb observations across this
    run, then pick the highest-priority token present in `_ENGINE_TOKEN_PRIORITY` — so a
    Django app served by gunicorn resolves to `Django`, not `Jinja2`. This avoids the
    first-finding-wins race that returned a wrong engine on previous DineHub runs where
    httpx captured `waitress` before `flask`."""
    tokens: set[str] = set()
    for fid in db.execute(select(Finding.id).where(Finding.run_id == run_id)).scalars().all():
        for o in db.execute(
            select(FindingObservation).where(FindingObservation.finding_id == fid)
        ).scalars().all():
            if o.source_tool not in ("http_probe", "whatweb"):
                continue
            d = o.detail or {}
            if isinstance(d.get("tech"), list):
                for t in d["tech"]:
                    tokens.add(str(t).strip().lower())
            if isinstance(d.get("server"), str) and d["server"]:
                # "Werkzeug/3.0.1" → "werkzeug"
                tokens.add(d["server"].split("/", 1)[0].strip().lower())
            # whatweb emits a free-text "line" field; scan it for engine markers too.
            line = d.get("line")
            if isinstance(line, str):
                low = line.lower()
                for key in _ENGINE_BY_TOKEN:
                    if key in low:
                        tokens.add(key)
    for key in _ENGINE_TOKEN_PRIORITY:
        if key in tokens and key in _ENGINE_BY_TOKEN:
            return _ENGINE_BY_TOKEN[key]
    return None


def wapiti_xss_targets(db: Session, run_id: str) -> list[tuple[str, str, str]]:
    """Pull (url, param, method) triples from wapiti's reflected-XSS findings for this run.
    The HTTP method comes from the wapiti observation's own `detail.method` (wapiti JSON
    reports GET/POST per vector) — used by the webvuln plan to probe POST forms with
    sstimap `-d` body data instead of a GET query string. De-duped by (url, param, method).
    Returns [] if the base URL can't be rebuilt from an http_probe finding."""
    out: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    # Resolve base once (scheme://host[:port]) from this run's http_probe findings.
    base = ""
    for probe_fid in db.execute(
        select(Finding.id).where(Finding.run_id == run_id,
                                 Finding.title.like("HTTP service:%"))
    ).scalars().all():
        pf = db.get(Finding, probe_fid)
        if pf is None:
            continue
        tm = re.search(r"HTTP service:\s*(https?://[^\s\[]+)", pf.title or "")
        if tm:
            base = tm.group(1).rstrip("/")
            break
    if not base:
        return out
    for fid in db.execute(select(Finding.id).where(Finding.run_id == run_id)).scalars().all():
        f = db.get(Finding, fid)
        if f is None:
            continue
        m = _WAPITI_XSS_TITLE_RE.search(f.title or "")
        if not m:
            continue
        path = m.group(1).strip()
        param = m.group(2).strip()
        if not param:
            continue
        # The HTTP method the vector was proven on — read from wapiti's own observation
        # detail (wapiti JSON reports {"method": "GET"|"POST", ...}). Default to GET if
        # the observation is missing; the webvuln plan can also enumerate both methods.
        method = "GET"
        for o in db.execute(
            select(FindingObservation).where(FindingObservation.finding_id == fid,
                                             FindingObservation.source_tool == "wapiti")
        ).scalars().all():
            mv = str((o.detail or {}).get("method", "")).strip().upper()
            if mv in ("GET", "POST"):
                method = mv
                break
        key = (base + path, param, method)
        if key in seen:
            continue
        seen.add(key)
        out.append(key)
    return out

def wapiti_sqli_targets(db: Session, run_id: str) -> list[tuple[str, str, str]]:
    """Pull (url, param, method) triples from wapiti's SQLi findings for this run.
    Mirrors `wapiti_xss_targets` — the webvuln plan uses it to propose one
    `sqli_detect` run per candidate (URL + pinned param + method). Wapiti's SQLi
    detector is nondeterministic run-to-run (per the webvuln-discovery-pipeline
    memory), which is exactly the gap `sqli_detect` closes with a deterministic
    sqlmap re-probe. Returns [] when the base URL can't be rebuilt."""
    out: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    base = ""
    for probe_fid in db.execute(
        select(Finding.id).where(Finding.run_id == run_id,
                                 Finding.title.like("HTTP service:%"))
    ).scalars().all():
        pf = db.get(Finding, probe_fid)
        if pf is None:
            continue
        tm = re.search(r"HTTP service:\s*(https?://[^\s\[]+)", pf.title or "")
        if tm:
            base = tm.group(1).rstrip("/")
            break
    if not base:
        return out
    for fid in db.execute(select(Finding.id).where(Finding.run_id == run_id)).scalars().all():
        f = db.get(Finding, fid)
        if f is None:
            continue
        m = _WAPITI_SQLI_TITLE_RE.search(f.title or "")
        if not m:
            continue
        path = m.group(1).strip()
        param = m.group(2).strip()
        if not param:
            continue
        method = "GET"
        for o in db.execute(
            select(FindingObservation).where(FindingObservation.finding_id == fid,
                                             FindingObservation.source_tool == "wapiti")
        ).scalars().all():
            mv = str((o.detail or {}).get("method", "")).strip().upper()
            if mv in ("GET", "POST"):
                method = mv
                break
        key = (base + path, param, method)
        if key in seen:
            continue
        seen.add(key)
        out.append(key)
    return out

# Tools that CONFIRM a vulnerability on-target by sending a payload and getting unambiguous
# proof — sstimap (actual template rendering of a math payload) and web_param_probe (its
# findings only exist when a documented signature matches, e.g. /etc/passwd content echoed
# back, a 302 to our canary host, a reflected SSH banner). A finding from one is real
# on-target proof, so validation marks it CONFIRMED directly (no reachability re-probe,
# which can't prove a vuln). nuclei/wapiti hits are NOT here: strong evidence but policy
# keeps them "candidate until a separate validation step" so they aren't auto-promoted.
_PROOF_SOURCE_TOOLS = {"sstimap", "web_param_probe", "dalfox", "idor_probe",
                       "sqli_detect", "stored_xss_probe",
                       "yaml_deserialization_probe", "dom_xss_probe",
                       "weak_cred_probe",
                       # xxe_probe confirms XXE by matching leaked file
                       # content in the response body — direct on-target
                       # proof, same tier as the other proof-source tools.
                       "xxe_probe",
                       # recon_agent body-pattern scanner emits findings
                       # for leaked hashes / AWS keys / private keys with
                       # detail.confirmed=True — a direct observation on
                       # the authed response body is proof-grade.
                       "recon_agent.body_scanner"}


def _is_proof_finding(db: Session, finding_id: str) -> bool:
    """A finding is proof-promotable only when a PROOF-SOURCE tool emitted an
    observation that EXPLICITLY carries ``detail.confirmed=True``. Being from a
    proof-source tool is NOT enough on its own — those tools also emit diagnostic
    "no vuln detected" observations (web_param_probe trace summaries, sstimap /
    sqli_detect / dalfox miss stubs). The earlier `or` here auto-promoted every
    one of those negatives, inflating a run's confirmed count without evidence.
    The `and` matches the comment above: *a finding from one is real on-target
    proof* — and real proof is what the normalizer tags as confirmed."""
    obs = db.execute(
        select(FindingObservation).where(FindingObservation.finding_id == finding_id)
    ).scalars().all()
    return any(
        o.source_tool in _PROOF_SOURCE_TOOLS and bool((o.detail or {}).get("confirmed"))
        for o in obs
    )


def _is_reachability_confirmable(db: Session, finding_id: str) -> bool:
    """True if this finding asserts service/port existence (confirmable by a reachability
    re-probe), False if it asserts a vulnerability (which reachability cannot prove)."""
    f = db.get(Finding, finding_id)
    if f is not None:
        title = f.title or ""
        if title.startswith("Open port") or title.startswith("HTTP service:"):
            return True
    obs = db.execute(
        select(FindingObservation).where(FindingObservation.finding_id == finding_id)
    ).scalars().all()
    return any(o.source_tool in _SERVICE_SOURCE_TOOLS for o in obs)


def validate_candidate(
    db: Session, scope: RunScope, harness: GovernedHarness, finding_id: str
) -> bool:
    """Independently re-check one candidate with a bounded re-probe of the SPECIFIC port
    the finding is about (not just the base host), so confirmation is anchored to the
    actual service. Confirmation requires the re-check to execute; otherwise the candidate
    stays inconclusive. Returns True if confirmed.

    Only service/port-existence findings are confirmable this way. An active-scanner
    *vulnerability* finding (wapiti/nuclei/nikto/…) is left as an unverified `candidate`
    rather than over-claimed as CONFIRMED on mere reachability — proving those needs an
    active re-verification step, not a liveness probe."""
    finding = db.get(Finding, finding_id)
    if finding is None:
        return False
    if _is_proof_finding(db, finding_id):
        # On-target proof already in hand (sstimap-confirmed SSTI, etc.) — promote directly.
        finding.status = FindingStatus.CONFIRMED.value
        db.flush()
        ledger.record_event(db, scope.run_id, "finding.confirmed", {"finding_id": finding_id})
        return True
    if not _is_reachability_confirmable(db, finding_id):
        return False  # vulnerability finding: stays candidate until actively re-verified
    args: dict = {"target": scope.target}
    port = _finding_port(db, finding_id)
    if port:
        args["port"] = port
    recheck = harness.run_action(
        db, ctx_for(scope, task_id=f"validate-{finding_id[:8]}", agent=AgentRole.VALIDATE,
                    tool_id="http_probe", args=args)
    )
    if recheck.executed:
        finding.status = FindingStatus.CONFIRMED.value
        db.flush()
        ledger.record_event(db, scope.run_id, "finding.confirmed", {"finding_id": finding_id})
        return True
    finding.status = FindingStatus.INCONCLUSIVE.value
    db.flush()
    ledger.record_event(db, scope.run_id, "finding.inconclusive", {"finding_id": finding_id})
    return False
