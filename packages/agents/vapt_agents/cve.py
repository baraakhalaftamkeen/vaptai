"""CVE lookup + enrichment (ported from V1 cve_engine.py into V2's governed model).

Two jobs:
  * severity_from_cvss / lookup_cve — resolve a CVE id to CVSS score, severity, a short
    description and references via the NIST NVD API (no API key), with a 24h on-disk
    cache. Network- and dependency-light (stdlib urllib) and OFFLINE-SAFE: any failure
    returns {} rather than raising, so a run degrades instead of breaking.
  * enrich_cve_findings — best-effort: for CVE findings this run produced (from the
    nmap `vulners` script), attach the NVD description/refs and normalise the severity
    from the authoritative CVSS score. Bounded so NVD rate limits can't stall a run.

The service→CVE MATCHING itself is done by the governed `nmap_vuln` tool (nmap -sV
--script vulners) and the `_vulners` normalizer — this module only resolves/enriches the
CVE ids that matching produced. Nothing here invents a CVE: ids come from tool output.
"""
from __future__ import annotations

import json
import os
import re
import urllib.request
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

_NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_NVD_CPE_API = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
# CISA Known Exploited Vulnerabilities — free, no API key, authoritative "exploited in
# the wild" catalog. A far stronger signal than "an exploit script exists locally", and
# it replaces the need to install a local Exploit-DB.
_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")


def _nvd_headers() -> dict:
    # An NVD API key (free) raises the rate limit from 5 to 50 requests / 30s, which the
    # CPE fallback benefits from. Optional — everything works keyless, just slower.
    h = {"User-Agent": "VAPT-AI/2.0"}
    key = os.environ.get("VAPT_NVD_API_KEY", "").strip()
    if key:
        h["apiKey"] = key
    return h


def _nvd_get(url: str, timeout: int) -> dict | None:
    req = urllib.request.Request(url, headers=_nvd_headers())
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (fixed host)
        return json.loads(resp.read().decode("utf-8", "replace"))


def _cache_path() -> str:
    return os.environ.get("VAPT_CVE_CACHE",
                          os.path.expanduser("~/.vapt_ai/cve_cache.json"))


def _kev_cache_path() -> str:
    return os.environ.get("VAPT_KEV_CACHE",
                          os.path.expanduser("~/.vapt_ai/kev_catalog.json"))


def severity_from_cvss(score: float | None) -> str:
    """CVSS v3 base score → severity band (NVD's own thresholds)."""
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "info"
    if s >= 9.0:
        return "critical"
    if s >= 7.0:
        return "high"
    if s >= 4.0:
        return "medium"
    if s > 0.0:
        return "low"
    return "info"


def _load_cache() -> dict:
    try:
        with open(_cache_path()) as f:
            return json.load(f)
    except Exception:
        return {}


def _save_cache(data: dict) -> None:
    try:
        os.makedirs(os.path.dirname(_cache_path()), exist_ok=True)
        with open(_cache_path(), "w") as f:
            json.dump(data, f)
    except Exception:
        pass


def lookup_cve(cve_id: str, *, timeout: int = 15, _fetch=None) -> dict:
    """Resolve one CVE from NIST NVD (cached 24h). Returns
    {cve_id, cvss, severity, description, references} or {} on any error/offline.
    `_fetch` is an injection point for tests (so no real HTTP in CI)."""
    cve_id = (cve_id or "").upper().strip()
    if not _CVE_RE.match(cve_id):
        return {}

    cache = _load_cache()
    hit = cache.get(cve_id)
    if hit:
        try:
            age = datetime.now(UTC) - datetime.fromisoformat(hit.get("cached_at"))
            if age < timedelta(hours=24):
                return {k: v for k, v in hit.items() if k != "cached_at"}
        except Exception:
            pass

    try:
        raw = _fetch(cve_id, timeout) if _fetch else _http_get_cve(cve_id, timeout)
    except Exception:
        return {}
    if not raw:
        return {}

    result = _parse_nvd(raw, cve_id)
    if result:
        cache[cve_id] = {**result, "cached_at": datetime.now(UTC).isoformat()}
        _save_cache(cache)
    return result


def _http_get_cve(cve_id: str, timeout: int) -> dict | None:
    return _nvd_get(f"{_NVD_API}?cveId={cve_id}", timeout)


def _parse_nvd(data: dict, cve_id: str) -> dict:
    vulns = (data or {}).get("vulnerabilities") or []
    if not vulns:
        return {}
    cve = vulns[0].get("cve", {}) if isinstance(vulns[0], dict) else {}
    metrics = cve.get("metrics", {}) or {}
    score, vector = None, ""
    for ver in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(ver) or []
        if arr:
            m = arr[0].get("cvssData", {}) or {}
            score = m.get("baseScore")
            vector = m.get("vectorString", "")
            break
    desc = ""
    for d in cve.get("descriptions", []) or []:
        if d.get("lang") == "en":
            desc = str(d.get("value", ""))[:400]
            break
    refs = [r.get("url", "") for r in (cve.get("references", []) or [])[:5] if r.get("url")]
    # References NVD tags as an exploit (a public-exploit signal without any local DB).
    exploit_refs = [
        r.get("url", "") for r in (cve.get("references", []) or [])
        if any("exploit" in str(t).lower() for t in (r.get("tags", []) or [])) and r.get("url")
    ]
    return {
        "cve_id": cve_id,
        "cvss": score,
        "vector": vector,
        "severity": severity_from_cvss(score),
        "description": desc,
        "references": refs,
        "exploit_refs": exploit_refs,
    }


# --------------------------------------------------------------------------- #
# Exploitation intelligence via public APIs (no local Exploit-DB install).
# --------------------------------------------------------------------------- #
def _http_get_kev(timeout: int) -> dict | None:
    req = urllib.request.Request(_KEV_URL, headers={"User-Agent": "VAPT-AI/2.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (fixed host)
        return json.loads(resp.read().decode("utf-8", "replace"))


def kev_cves(*, timeout: int = 20, _fetch=None) -> set[str]:
    """CISA KEV CVE ids (cached 24h). Offline-safe → empty set on any failure."""
    path = _kev_cache_path()
    try:
        with open(path) as f:
            cached = json.load(f)
        age = datetime.now(UTC) - datetime.fromisoformat(cached.get("cached_at"))
        if age < timedelta(hours=24):
            return set(cached.get("cves", []))
    except Exception:
        pass
    try:
        data = _fetch(timeout) if _fetch else _http_get_kev(timeout)
    except Exception:
        return set()
    cves = {str(v.get("cveID", "")).upper() for v in (data or {}).get("vulnerabilities", [])
            if v.get("cveID")}
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump({"cves": sorted(cves), "cached_at": datetime.now(UTC).isoformat()}, f)
    except Exception:
        pass
    return cves


def _feed_cache_path() -> str:
    return os.environ.get("VAPT_FEED_CACHE",
                          os.path.expanduser("~/.vapt_ai/cve_feed.json"))


# --------------------------------------------------------------------------- #
# NVD CPE fallback matcher: detected product+version -> CVEs, via NVD's own CPE
# dictionary + CVE-by-CPE query. Works when vulners.com is unreachable. Offline-safe.
# --------------------------------------------------------------------------- #
_VERSION_RE = re.compile(r"\d[\w.\-]*")


def _clean_version(version: str) -> str:
    """A CPE-usable version token from an nmap -sV version string (first numeric token)."""
    m = _VERSION_RE.search(str(version or ""))
    return m.group(0) if m else ""


def resolve_cpe(product: str, *, part: str = "a", timeout: int = 15, _fetch=None) -> dict | None:
    """Resolve a product/OS banner to an NVD CPE's {part, vendor, product} via the NVD CPE
    dictionary. `part` is 'a' (application) or 'o' (operating system). None on no match /
    offline."""
    product = str(product or "").strip()
    if not product:
        return None
    try:
        import urllib.parse
        url = f"{_NVD_CPE_API}?keywordSearch={urllib.parse.quote(product)}&resultsPerPage=20"
        data = _fetch(product, timeout) if _fetch else _nvd_get(url, timeout)
    except Exception:
        return None
    for p in (data or {}).get("products", []):
        name = str((p.get("cpe", {}) or {}).get("cpeName", ""))
        parts = name.split(":")
        # cpe:2.3:<part>:vendor:product:version:...  -> [2]=part [3]=vendor [4]=product
        if len(parts) >= 6 and parts[2] == part and parts[3] and parts[4]:
            return {"part": parts[2], "vendor": parts[3], "product": parts[4]}
    return None


def _os_is_vulnerable_component(cve_obj: dict, vendor: str, product: str) -> bool:
    """True only if this CVE lists the OS CPE (cpe:2.3:o:<vendor>:<product>) as a
    VULNERABLE component. NVD encodes 'third-party app X, when running on Windows' as an
    AND-node where the app CPE is vulnerable:true and the OS CPE is vulnerable:false (a
    'running on' platform qualifier). A virtualMatchString query matches BOTH, so without
    this gate the OS matcher pulls in every app that merely runs on the OS (curl, Java RMI,
    APC UPS, …). Keeping only CVEs where the OS CPE itself is the vulnerable component drops
    that noise and leaves the genuine Windows OS vulns (SMB/RDP RCEs, etc.)."""
    prefix = f"cpe:2.3:o:{vendor}:{product}:"
    for cfg in cve_obj.get("configurations") or []:
        for node in cfg.get("nodes") or []:
            for cm in node.get("cpeMatch") or []:
                if cm.get("vulnerable") and str(cm.get("criteria", "")).startswith(prefix):
                    return True
    return False


def os_cpe_cve_match(os_query: str, *, limit: int = 10, min_score: float = 9.0,
                     timeout: int = 15, _fetch_cpe=None, _fetch_cve=None) -> list[dict]:
    """OS-level CVE matching: resolve an OS name (e.g. 'Windows Server 2019') to its NVD OS
    CPE, then query NVD for the top CRITICAL CVEs affecting it. Each result is precision-
    gated by `_os_is_vulnerable_component` so only CVEs where the OS *itself* is vulnerable
    are kept — not third-party apps that merely list the OS as a 'running on' platform.
    Bounded (an OS has many CVEs) and offline-safe → []. Returns
    [{cve_id, cvss, severity, description}]."""
    cpe = resolve_cpe(os_query, part="o", timeout=timeout, _fetch=_fetch_cpe)
    if not cpe:
        return []
    vms = f"cpe:2.3:o:{cpe['vendor']}:{cpe['product']}:*:*:*:*:*:*:*:*"
    sev = "CRITICAL" if min_score >= 9.0 else "HIGH"
    try:
        import urllib.parse
        url = (f"{_NVD_API}?virtualMatchString={urllib.parse.quote(vms)}"
               f"&cvssV3Severity={sev}&resultsPerPage=60")
        data = _fetch_cve(vms, timeout) if _fetch_cve else _nvd_get(url, timeout)
    except Exception:
        return []
    out: list[dict] = []
    seen: set[str] = set()
    for v in (data or {}).get("vulnerabilities", []):
        cve_obj = (v.get("cve", {}) or {}) if isinstance(v, dict) else {}
        cid = str(cve_obj.get("id", ""))
        if not _CVE_RE.match(cid) or cid in seen:
            continue
        # Precision gate: the OS CPE must be the vulnerable component, not a platform
        # qualifier for some app running on it.
        if not _os_is_vulnerable_component(cve_obj, cpe["vendor"], cpe["product"]):
            continue
        parsed = _parse_nvd({"vulnerabilities": [v]}, cid)
        if not parsed or (parsed.get("cvss") or 0.0) < float(min_score):
            continue
        seen.add(cid)
        out.append({"cve_id": cid, "cvss": parsed.get("cvss"),
                    "severity": parsed.get("severity", "info"),
                    "description": parsed.get("description", "")})
    out.sort(key=lambda x: (x["cvss"] or 0.0), reverse=True)
    return out[:limit]


def cpe_cve_match(product: str, version: str, *, limit: int = 12, timeout: int = 15,
                  _fetch_cpe=None, _fetch_cve=None) -> list[dict]:
    """NVD CPE fallback: resolve product->CPE, then query NVD for CVEs affecting that exact
    product+version. Returns [{cve_id, cvss, severity, description}]; [] on no version, no
    CPE match, or offline. Each item is a real NVD CVE — nothing is invented."""
    ver = _clean_version(version)
    if not ver:
        return []   # a version is required — matching a whole product is too broad
    cpe = resolve_cpe(product, timeout=timeout, _fetch=_fetch_cpe)
    if not cpe:
        return []
    vms = f"cpe:2.3:{cpe['part']}:{cpe['vendor']}:{cpe['product']}:{ver}:*:*:*:*:*:*:*"
    try:
        import urllib.parse
        url = f"{_NVD_API}?virtualMatchString={urllib.parse.quote(vms)}&resultsPerPage=40"
        data = _fetch_cve(vms, timeout) if _fetch_cve else _nvd_get(url, timeout)
    except Exception:
        return []
    out: list[dict] = []
    seen: set[str] = set()
    for v in (data or {}).get("vulnerabilities", []):
        cid = str((v.get("cve", {}) or {}).get("id", "")) if isinstance(v, dict) else ""
        if not _CVE_RE.match(cid) or cid in seen:
            continue
        parsed = _parse_nvd({"vulnerabilities": [v]}, cid)
        if not parsed:
            continue
        seen.add(cid)
        out.append({
            "cve_id": cid,
            "cvss": parsed.get("cvss"),
            "severity": parsed.get("severity", "info"),
            "description": parsed.get("description", ""),
        })
        if len(out) >= limit:
            break
    out.sort(key=lambda x: (x["cvss"] or 0.0), reverse=True)
    return out


def cve_feed(*, days: int = 7, min_score: float = 7.0, keyword: str = "",
             limit: int = 20, timeout: int = 20, _fetch=None) -> list[dict]:
    """Recent high/critical CVEs from NIST NVD (ported from V1 get_cve_feed), cached 1h.
    Returns [{id, score, severity, published, description}] sorted by score desc. Fully
    offline-safe → [] on any failure. `_fetch(params, timeout)` is a test injection point."""
    days = max(1, min(int(days), 30))
    key = f"{days}:{min_score}:{keyword.strip().lower()}"
    path = _feed_cache_path()
    try:
        with open(path) as f:
            blob = json.load(f)
        if blob.get("key") == key:
            age = datetime.now(UTC) - datetime.fromisoformat(blob.get("cached_at"))
            if age < timedelta(hours=1):
                return blob.get("items", [])[:limit]
    except Exception:
        pass

    now = datetime.now(UTC)
    params = {
        "pubStartDate": (now - timedelta(days=days)).strftime("%Y-%m-%dT00:00:00.000"),
        "pubEndDate": now.strftime("%Y-%m-%dT23:59:59.999"),
        "cvssV3Severity": "CRITICAL" if min_score >= 9.0 else "HIGH",
        "resultsPerPage": 100,
    }
    if keyword.strip():
        params["keywordSearch"] = keyword.strip()
    try:
        data = _fetch(params, timeout) if _fetch else _http_get_feed(params, timeout)
    except Exception:
        return []

    items: list[dict] = []
    for v in (data or {}).get("vulnerabilities", []):
        cve = v.get("cve", {}) if isinstance(v, dict) else {}
        metrics = cve.get("metrics", {}) or {}
        score = None
        for ver in ("cvssMetricV31", "cvssMetricV30"):
            arr = metrics.get(ver) or []
            if arr:
                score = arr[0].get("cvssData", {}).get("baseScore")
                break
        if score is None or float(score) < float(min_score):
            continue
        desc = next((d.get("value", "") for d in cve.get("descriptions", []) or []
                     if d.get("lang") == "en"), "")[:220]
        items.append({
            "id": cve.get("id", ""),
            "score": float(score),
            "severity": severity_from_cvss(score),
            "published": str(cve.get("published", ""))[:10],
            "description": desc,
        })
    items.sort(key=lambda x: x["score"], reverse=True)
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump({"key": key, "items": items, "cached_at": now.isoformat()}, f)
    except Exception:
        pass
    return items[:limit]


def _http_get_feed(params: dict, timeout: int) -> dict | None:
    import urllib.parse
    return _nvd_get(f"{_NVD_API}?{urllib.parse.urlencode(params)}", timeout)


def is_exploited(cve_id: str, *, nvd_info: dict | None = None,
                 _fetch_kev=None, _fetch_nvd=None) -> dict:
    """Public-API exploitation signal for a CVE (no local Exploit-DB). Returns
    {'exploited': bool, 'basis': str}. 'basis' names the authoritative source:
    CISA KEV (actively exploited) outranks an NVD exploit-tagged reference."""
    cve_id = (cve_id or "").upper().strip()
    if not _CVE_RE.match(cve_id):
        return {"exploited": False, "basis": ""}
    if cve_id in kev_cves(_fetch=_fetch_kev):
        return {"exploited": True, "basis": "CISA KEV — actively exploited in the wild"}
    info = nvd_info if nvd_info is not None else lookup_cve(cve_id, _fetch=_fetch_nvd)
    if info.get("exploit_refs"):
        return {"exploited": True, "basis": "public exploit reference (NVD)"}
    return {"exploited": False, "basis": ""}


def enrich_cve_findings(db: Session, run_id: str, *, limit: int = 15, _fetch=None) -> int:
    """Best-effort NVD enrichment of this run's CVE findings (from nmap vulners). For each,
    attach the NVD description/refs and set severity from the authoritative CVSS score.
    Bounded by `limit` and fully offline-safe. Returns how many were enriched."""
    from vapt_persistence.models import Finding, FindingObservation

    enriched = 0
    findings = db.execute(select(Finding).where(Finding.run_id == run_id)).scalars().all()
    for f in findings:
        if enriched >= limit:
            break
        obs = db.execute(
            select(FindingObservation).where(FindingObservation.finding_id == f.id)
        ).scalars().all()
        cve_id = ""
        for o in obs:
            if o.source_tool == "nmap_vuln":
                cve_id = str((o.detail or {}).get("cve", "")).strip()
                if cve_id:
                    break
        if not cve_id or f.description:            # already enriched or not a CVE finding
            continue
        info = lookup_cve(cve_id, _fetch=_fetch)
        if not info:
            continue
        if info.get("severity") and info["severity"] != "info":
            f.severity = info["severity"]
        f.description = (info.get("description") or "")[:400]
        for o in obs:
            if o.source_tool == "nmap_vuln":
                o.detail = {**(o.detail or {}), "cvss": info.get("cvss"),
                            "references": info.get("references", [])}
        db.flush()
        enriched += 1
    return enriched
