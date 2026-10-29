"""Normalize raw tool output into candidate observations (plan §5, §6).

Tool output is untrusted data: we parse it into structured observations, label the
source tool, and never let embedded text redefine scope or policy. Parsers are
defensive — unknown/empty output yields an empty list, never an exception.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# Strip ANSI colour/escape sequences so tool output never leaks control codes into
# finding titles or evidence.
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _clean(text: str) -> str:
    return _ANSI.sub("", text).strip()


@dataclass
class Observation:
    source_tool: str
    title: str
    severity: str = "info"            # info|low|medium|high|critical
    detail: dict = field(default_factory=dict)


def _stdout(result_observations: list[dict]) -> str:
    parts = []
    for o in result_observations or []:
        if isinstance(o, dict) and "stdout" in o:
            parts.append(str(o["stdout"]))
    return "\n".join(parts)


def normalize(tool_id: str, result_observations: list[dict]) -> list[Observation]:
    text = _stdout(result_observations)
    if tool_id == "nmap_service_scan":
        return _nmap(text)
    if tool_id in ("http_probe",):
        return _httpx(text)
    if tool_id in ("nuclei_safe", "nuclei_intrusive"):
        return _nuclei(text)
    if tool_id == "tls_check":
        return _tls(text)
    if tool_id == "semgrep_scan":
        return _semgrep(text)
    if tool_id == "gitleaks_scan":
        return _gitleaks(text)
    if tool_id == "dep_audit":
        return _dep_audit(text)
    if tool_id == "zap_baseline":
        return _zap(text)
    if tool_id == "host_scripts":
        return _host_scripts(text)
    if tool_id == "nmap_vuln":
        return _vulners(text)
    if tool_id in ("win_vuln_scan", "win_vuln_aggressive"):
        return _win_vuln(text)
    if tool_id == "tenable_scan":
        return _intel(text, source="tenable", basis="Tenable.sc authenticated scan")
    if tool_id == "nessus_import":
        return _intel(text, source="nessus", basis="Nessus scan import")
    # Catalog tools with bespoke parsers (service-driven router + LLM-planned steps).
    if tool_id == "nikto":
        return _nikto(text)
    if tool_id == "wpscan":
        return _wpscan(text)
    if tool_id == "sslyze":
        return _sslyze(text)
    if tool_id == "whatweb":
        return _whatweb(text)
    if tool_id == "katana":
        return _katana(text)
    if tool_id == "shcheck":
        return _shcheck(text)
    if tool_id == "feroxbuster":
        return _ferox(text)
    if tool_id == "arjun":
        return _arjun(text)
    if tool_id == "vapt_http_fetch":
        return _http_fetch(text)
    if tool_id == "sqli_detect":
        obs = _sqli_detect(text)
        if not obs:
            # Same diagnostic pattern as sstimap/dalfox: on a miss, surface tails of
            # stdout and stderr so an operator can see WHY sqlmap didn't fire
            # (connection refused, 403 blocked, auth redirect) without ssh'ing to
            # the worker. The resulting observation is "info", NOT a candidate.
            stderr_tail = "\n".join(
                str(o.get("stderr", "")) for o in (result_observations or [])
                if isinstance(o, dict) and o.get("stderr")
            )[-1200:]
            return [Observation(
                "sqli_detect",
                "sqli_detect: no SQL injection detected",
                "info",
                {"stderr_tail": stderr_tail, "stdout_tail": (text or "")[-600:]},
            )]
        return obs
    if tool_id in ("sstimap", "ssti_detect"):
        obs = _sstimap(text)
        if not obs:
            # Diagnostic — same pattern as dalfox: when sstimap found nothing we surface
            # a short stdout/stderr tail so operators can see WHY (ambiguous output,
            # auth redirect, engine mismatch, timeout) without ssh'ing to the worker.
            stderr_tail = "\n".join(
                str(o.get("stderr", "")) for o in (result_observations or [])
                if isinstance(o, dict) and o.get("stderr")
            )[-1200:]
            return [Observation(
                "sstimap",
                f"{tool_id}: no SSTI detected",
                "info",
                {"stderr_tail": stderr_tail, "stdout_tail": (text or "")[-600:]},
            )]
        return obs
    if tool_id == "web_param_probe":
        return _web_param_probe(text)
    if tool_id == "idor_probe":
        return _idor_probe(text)
    if tool_id == "stored_xss_probe":
        return _stored_xss_probe(text)
    if tool_id == "csp_check":
        return _csp_check(text)
    if tool_id == "yaml_deserialization_probe":
        return _yaml_deser_probe(text)
    if tool_id == "weak_cred_probe":
        return _weak_cred_probe(text)
    if tool_id == "xxe_probe":
        return _xxe_probe(text)
    if tool_id == "dom_xss_probe":
        return _dom_xss_probe(text)
    if tool_id == "wafw00f":
        return _wafw00f_scan(text)
    if tool_id == "smbmap":
        return _smbmap(text)
    if tool_id == "cmseek":
        return _cmseek(text)
    if tool_id == "wapiti":
        return _wapiti(text)
    if tool_id == "dalfox":
        return _dalfox(text, result_observations)
    # Generic: if the tool produced any stdout, record one info observation.
    if text.strip():
        return [Observation(tool_id, f"{tool_id} output", "info", {"excerpt": text[:500]})]
    return []


def _first_json(text: str):
    """Parse the first JSON value in stdout. Tools may print logs around the JSON, so
    scan for the first '{' or '[' and decode from there. Returns None on failure."""
    import json as _json

    if not text:
        return None
    for i, ch in enumerate(text):
        if ch in "[{":
            try:
                return _json.loads(text[i:])
            except Exception:
                try:
                    dec = _json.JSONDecoder()
                    obj, _ = dec.raw_decode(text[i:])
                    return obj
                except Exception:
                    continue
    return None


_SEMGREP_SEV = {"ERROR": "high", "WARNING": "medium", "INFO": "info", "CRITICAL": "critical"}


def _semgrep(text: str) -> list[Observation]:
    data = _first_json(text)
    if not isinstance(data, dict):
        return []
    obs: list[Observation] = []
    for r in data.get("results", []) or []:
        if not isinstance(r, dict):
            continue
        extra = r.get("extra", {}) if isinstance(r.get("extra"), dict) else {}
        rule = str(r.get("check_id", "semgrep"))
        path = str(r.get("path", ""))
        line = (r.get("start", {}) or {}).get("line")
        sev = _SEMGREP_SEV.get(str(extra.get("severity", "")).upper(), "low")
        msg = str(extra.get("message", rule))[:300]
        obs.append(Observation(
            "semgrep", f"{rule} at {path}:{line}", sev,
            {"file": path, "line": line, "rule": rule, "message": msg},
        ))
    return obs


def _gitleaks(text: str) -> list[Observation]:
    data = _first_json(text)
    if not isinstance(data, list):
        return []
    obs: list[Observation] = []
    for r in data:
        if not isinstance(r, dict):
            continue
        rule = str(r.get("RuleID", "secret"))
        path = str(r.get("File", ""))
        line = r.get("StartLine")
        # Record the location and rule, NEVER the secret value itself.
        obs.append(Observation(
            "gitleaks", f"Secret ({rule}) in {path}:{line}", "high",
            {"file": path, "line": line, "rule": rule,
             "description": str(r.get("Description", ""))[:200]},
        ))
    return obs


_DEP_SEV = {"critical", "high", "medium", "low", "info"}


def _dep_audit(text: str) -> list[Observation]:
    data = _first_json(text)
    vulns = None
    if isinstance(data, dict):
        vulns = data.get("vulnerabilities") or data.get("vulns")
    elif isinstance(data, list):
        vulns = data
    if not isinstance(vulns, list):
        return []
    obs: list[Observation] = []
    for v in vulns:
        if not isinstance(v, dict):
            continue
        pkg = str(v.get("package", v.get("name", "dependency")))
        version = str(v.get("version", ""))
        vid = str(v.get("id", v.get("advisory", "")))
        sev = str(v.get("severity", "medium")).lower()
        if sev not in _DEP_SEV:
            sev = "medium"
        obs.append(Observation(
            "dep_audit", f"{pkg} {version}: {vid or 'vulnerable dependency'}", sev,
            {"package": pkg, "version": version, "advisory": vid,
             "fix_version": str(v.get("fix_version", ""))},
        ))
    return obs


def _nmap(text: str) -> list[Observation]:
    """Parse nmap -oX output. In nmap XML a port looks like:

        <port protocol="tcp" portid="80">
          <state state="open" reason="syn-ack"/>
          <service name="http" product="Microsoft IIS httpd" version="10.0"/>
        </port>

    i.e. portid and state live in SEPARATE elements — so we scan whole <port>…</port>
    blocks rather than trying to match portid and state in one run (the old regex never
    matched real output, silently dropping every open port)."""
    obs: list[Observation] = []
    seen: set[str] = set()

    for block in re.findall(r"<port\b[^>]*>.*?</port>", text, re.S):
        pid = re.search(r'portid="(\d+)"', block)
        state = re.search(r'<state\s+state="([a-z|]+)"', block)
        if not pid or not state or "open" not in state.group(1):
            continue
        port = pid.group(1)
        svc = re.search(r'<service\b[^>]*\bname="([^"]*)"', block)
        product = re.search(r'\bproduct="([^"]*)"', block)
        version = re.search(r'\bversion="([^"]*)"', block)
        name = svc.group(1) if svc else ""
        product_s = product.group(1) if (product and product.group(1)) else ""
        version_s = version.group(1) if (version and version.group(1)) else ""
        banner = " ".join(x for x in (product_s, version_s) if x).strip()

        label = f"Open port {port}" + (f" ({name})" if name else "")
        if banner:
            label += f" — {banner}"
        detail = {"port": port}
        if name:
            detail["service"] = name
        if banner:
            detail["product"] = banner          # human banner for the title/evidence
        if product_s:
            detail["product_name"] = product_s  # separate fields for NVD CPE matching
        if version_s:
            detail["version"] = version_s
        obs.append(Observation("nmap_service_scan", label, "info", detail))
        seen.add(port)

    # Plain-text fallback ("22/tcp open ssh"), e.g. if -oX was not used.
    for m in re.finditer(r"(\d+)/tcp\s+open\s+(\S+)", text):
        if m.group(1) in seen:
            continue
        obs.append(Observation(
            "nmap_service_scan", f"Open port {m.group(1)} ({m.group(2)})",
            "info", {"port": m.group(1), "service": m.group(2)},
        ))
    return obs


_HTTPX_BRACKETS_RE = re.compile(r"\[([^\]]*)\]")


def _httpx(text: str) -> list[Observation]:
    """httpx -silent prints one line per URL: `URL [status] [title] [server] [tech,tech,...]`.
    We keep the whole line (back-compat) but ALSO pull Server banner + tech list into the
    observation detail so a later phase (SSTI engine inference) can read them without
    re-parsing the free-form title."""
    obs: list[Observation] = []
    for raw in text.splitlines():
        line = _clean(raw)
        if not line:
            continue
        parts = _HTTPX_BRACKETS_RE.findall(line)
        detail: dict = {"line": line}
        # Position-free extraction: identify brackets by content shape.
        #   status: 3-digit number
        #   server: lowercase token with maybe `/version` (gunicorn/19.9.0, Werkzeug/3.0.1, …)
        #   tech:   comma-separated non-numeric list (Flask, Jinja, Python)
        for b in parts:
            s = b.strip()
            if not s:
                continue
            if "status" not in detail and re.fullmatch(r"\d{3}", s):
                detail["status"] = s
            elif "," in s and not s[0].isdigit():
                # Wappalyzer tech list — Flask, Werkzeug, Python, Jinja, Nginx, etc.
                detail["tech"] = [t.strip() for t in s.split(",") if t.strip()][:16]
            elif "/" in s and re.fullmatch(r"[A-Za-z][\w\-+.]*/[\w.\-+]*", s):
                detail["server"] = s
        obs.append(Observation("http_probe", f"HTTP service: {line[:120]}", "info", detail))
    return obs


_SEV = {"info": "info", "low": "low", "medium": "medium", "high": "high", "critical": "critical"}


def _nuclei(text: str) -> list[Observation]:
    obs: list[Observation] = []
    # nuclei -silent lines look like: [template-id] [protocol] [severity] url
    for m in re.finditer(r"\[([^\]]+)\]\s*\[[^\]]+\]\s*\[(info|low|medium|high|critical)\]\s*(\S+)", text):
        tmpl, sev, url = m.group(1), m.group(2), m.group(3)
        obs.append(
            Observation("nuclei", f"{tmpl} @ {url}", _SEV.get(sev, "info"), {"template": tmpl, "url": url})
        )
    return obs


def _zap(text: str) -> list[Observation]:
    """Parse OWASP ZAP baseline stdout into per-alert findings. Lines look like:
        WARN-NEW: Content Security Policy (CSP) Header Not Set [10038] x 3
        FAIL-NEW: Cross Site Scripting (Reflected) [40012] x 1
    FAIL alerts are the higher-confidence ones; WARN are advisory for a passive baseline."""
    obs: list[Observation] = []
    seen: set[str] = set()
    for m in re.finditer(r"^\s*(FAIL|WARN)(?:-NEW|-INPROG)?:\s*(.+?)\s*\[(\d+)\]",
                         _clean(text), re.MULTILINE):
        level, name, plugin = m.group(1), m.group(2).strip(), m.group(3)
        if plugin in seen:
            continue
        seen.add(plugin)
        sev = "medium" if level == "FAIL" else "low"
        obs.append(Observation("zap_baseline", f"ZAP: {name}", sev,
                               {"plugin_id": plugin, "level": level}))
    return obs


# NSE scripts whose output we turn into findings. Fixed, safe (discovery) set — never
# model-controllable (see registry _build_host_scripts).
def _host_scripts(text: str) -> list[Observation]:
    """Parse nmap NSE <script id output> elements for Windows service posture:
    SMB signing requirement, SMB OS/host info, RDP NTLM/NLA info, NetBIOS names."""
    obs: list[Observation] = []
    for m in re.finditer(r'<script id="([\w.-]+)"\s+output="([^"]*)"', text):
        sid = m.group(1)
        out = _unescape(m.group(2)).strip()
        low = out.lower()
        if sid in ("smb2-security-mode", "smb-security-mode"):
            if "not required" in low:
                obs.append(Observation("host_scripts",
                    "SMB message signing enabled but NOT required (445)", "medium",
                    {"script": sid, "detail": out[:200], "port": "445"}))
            else:
                obs.append(Observation("host_scripts", "SMB signing required (445)", "info",
                    {"script": sid, "detail": out[:200], "port": "445"}))
        elif sid == "smb-os-discovery":
            first = out.splitlines()[0].strip() if out else ""
            obs.append(Observation("host_scripts", f"SMB OS discovery: {first[:120]}", "info",
                {"script": sid, "detail": out[:300], "port": "445"}))
        elif sid == "rdp-ntlm-info":
            obs.append(Observation("host_scripts", "RDP NTLM/host info (3389)", "info",
                {"script": sid, "detail": out[:300], "port": "3389"}))
        elif sid == "nbstat":
            obs.append(Observation("host_scripts", "NetBIOS names (139)", "info",
                {"script": sid, "detail": out[:300], "port": "139"}))
        else:
            if out:
                obs.append(Observation("host_scripts", f"NSE {sid}", "info",
                    {"script": sid, "detail": out[:200]}))
    return obs


def _unescape(s: str) -> str:
    import html as _html

    return _clean(_html.unescape(s))


# A vulners script line pins a CVE id to a CVSS score (and an exploit flag), e.g.:
#   CVE-2021-41773   7.5   https://vulners.com/cve/CVE-2021-41773
#   CVE-2021-42013   9.8   https://vulners.com/cve/CVE-2021-42013   *EXPLOIT*
_CVE_LINE = re.compile(
    r"(CVE-\d{4}-\d{4,7})\s+(\d{1,2}(?:\.\d)?)(?:\s+(https?://\S+))?(\s*\*EXPLOIT\*)?",
    re.IGNORECASE,
)


def _cvss_band(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"


_WIN_VULN_TITLES = {
    "smb-vuln-ms17-010": "MS17-010 (EternalBlue)",
    "smb-vuln-ms08-067": "MS08-067 (Server Service RCE)",
    "rdp-vuln-ms12-020": "MS12-020 (RDP RCE/DoS)",
}


def _win_vuln(text: str) -> list[Observation]:
    """Parse nmap Windows vuln-check scripts. A script whose state is VULNERABLE (and not
    'NOT VULNERABLE') yields a CRITICAL finding carrying the CVE id(s) the script reports —
    a definitive on-target result, not a version guess."""
    obs: list[Observation] = []
    text = _unescape(text)
    for m in re.finditer(r'<script id="([\w.-]+)"\s+output="([^"]*)"', text):
        sid = m.group(1)
        out = m.group(2)
        low = out.lower()
        # VULNERABLE iff the output asserts it and does NOT say NOT VULNERABLE.
        if "vulnerable" not in low or "not vulnerable" in low:
            continue
        cves = sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", out, re.IGNORECASE)))
        name = _WIN_VULN_TITLES.get(sid, sid)
        cve_str = (" — " + ", ".join(c.upper() for c in cves)) if cves else ""
        obs.append(Observation(
            "win_vuln_scan", f"{name}: VULNERABLE{cve_str}", "critical",
            {"script": sid, "cves": [c.upper() for c in cves],
             "cve": cves[0].upper() if cves else "", "basis": "nmap vuln check on target"},
        ))
    return obs


def _intel(text: str, *, source: str, basis: str) -> list[Observation]:
    """Parse JSONL intel findings from an external authenticated scanner (Tenable.sc live
    API via `tenable_scan`, or a .nessus export via `nessus_import`). Each line is one
    finding in the shared intel shape. These come from an authorized authenticated scan, so
    they are real on-target evidence — the ingestion layer records them as confirmed and
    treats `exploit=true` the way CISA KEV is treated. Defensive: bad lines are skipped."""
    import json as _json

    obs: list[Observation] = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line[0] != "{":
            continue
        try:
            f = _json.loads(line)
        except Exception:
            continue
        if not isinstance(f, dict) or "_summary" in f or not f.get("ip"):
            continue
        sev = str(f.get("severity", "info")).lower()
        if sev not in ("info", "low", "medium", "high", "critical"):
            sev = "info"
        cve = str(f.get("cve", "")).strip().upper()
        plugin = _clean(str(f.get("plugin", ""))) or (cve or "finding")
        ip = str(f.get("ip", ""))
        port = str(f.get("port", ""))
        loc = f"{ip}:{port}" if port and port != "0" else ip
        cve_str = f" — {cve}" if cve else ""
        obs.append(Observation(
            source, f"{plugin}{cve_str} ({loc})", sev,
            {
                "cve": cve,
                "cvss": f.get("cvss"),
                "port": port,
                "protocol": str(f.get("protocol", "")),
                "exploit": bool(f.get("exploit")),
                "frameworks": _clean(str(f.get("frameworks", ""))),
                "solution": _clean(str(f.get("solution", "")))[:300],
                "os": _clean(str(f.get("os", ""))),
                "plugin": plugin,
                "source": source,
                "basis": basis,
            },
        ))
    return obs


def _vulners(text: str) -> list[Observation]:
    """Parse nmap -sV --script vulners output (service→CVE matching). Each CVE becomes a
    finding whose severity comes from its CVSS score; a known public exploit bumps it to
    at least high. Ports are tracked so a CVE is attributed to the service it was found on.
    De-duped per CVE (keeping the highest severity seen)."""
    obs: list[Observation] = []
    best: dict[str, Observation] = {}
    # Track the current port as we walk the XML (<port portid="..."> … vulners script).
    text = _unescape(text)
    port = ""
    for chunk in re.split(r'(<port\b[^>]*portid="(\d+)")', text):
        m_port = re.match(r'<port\b[^>]*portid="(\d+)"', chunk or "")
        if m_port:
            port = m_port.group(1)
            continue
        if chunk and chunk.isdigit():
            port = chunk
            continue
        for m in _CVE_LINE.finditer(chunk or ""):
            cve = m.group(1).upper()
            try:
                score = float(m.group(2))
            except ValueError:
                continue
            exploit = bool(m.group(4))
            sev = _cvss_band(score)
            if exploit and sev in ("info", "low", "medium"):
                sev = "high"
            title = f"{cve} (CVSS {score:g}" + (", public exploit" if exploit else "") + ")"
            detail = {"cve": cve, "cvss": score, "exploit": exploit}
            if port:
                detail["port"] = port
                title += f" on port {port}"
            prior = best.get(cve)
            rank = ["info", "low", "medium", "high", "critical"]
            if prior is None or rank.index(sev) > rank.index(prior.severity):
                best[cve] = Observation("nmap_vuln", title, sev, detail)
    obs.extend(best.values())
    return obs


def _tls(text: str) -> list[Observation]:
    obs: list[Observation] = []
    low = text.lower()
    if "sslv3" in low or "tlsv1.0" in low or "tls 1.0" in low:
        obs.append(Observation("tls_check", "Legacy TLS/SSL protocol offered", "medium", {}))
    if "expired" in low:
        obs.append(Observation("tls_check", "Expired certificate", "high", {}))
    return obs


# --------------------------------------------------------------------------- #
# Catalog-tool parsers (web + TLS). Defensive line/section scanners; bounded so a
# chatty tool can't flood the finding list. Severity is conservative — a scanner
# "+ " line is a lead, confirmed later by the validate phase.
# --------------------------------------------------------------------------- #
_NIKTO_MED = ("osvdb", "cve-", "vulnerab", "outdated", "xss", "sql inj", "traversal",
              "remote file", "injection", "disclosure", "default account")
_NIKTO_LOW = ("not present", "not set", "not defined", "directory indexing",
              "default file", "header", "cookie", "allowed http methods", "put ", "trace")
_NIKTO_SKIP = ("target ip", "target hostname", "target port", "target:", "start time",
               "end time", "host(s) tested", "requests:", "scan terminated", "ssl info",
               "server:", "retrieved", "nikto v", "+ 0 ", "no web server")


def _nikto(text: str) -> list[Observation]:
    obs: list[Observation] = []
    for raw in _clean(text).splitlines():
        line = raw.strip()
        if not line.startswith("+ "):
            continue
        body = line[2:].strip()
        low = body.lower()
        if not body or any(s in low for s in _NIKTO_SKIP):
            continue
        if any(k in low for k in _NIKTO_MED):
            sev = "medium"
        elif any(k in low for k in _NIKTO_LOW):
            sev = "low"
        else:
            sev = "info"
        cves = re.findall(r"CVE-\d{4}-\d{4,7}", body, re.IGNORECASE)
        detail = {"message": body[:300]}
        if cves:
            detail["cve"] = cves[0].upper()
        obs.append(Observation("nikto", f"Nikto: {body[:140]}", sev, detail))
        if len(obs) >= 30:
            break
    return obs


def _wpscan(text: str) -> list[Observation]:
    obs: list[Observation] = []
    cur_vuln: str | None = None
    for raw in _clean(text).splitlines():
        line = raw.strip()
        low = line.lower()
        if line.startswith("[!]") and "title:" in low:
            title = line.split(":", 1)[1].strip() if ":" in line else line[3:].strip()
            cur_vuln = title
            obs.append(Observation("wpscan", f"WordPress: {title[:140]}", "medium",
                                   {"message": title[:300]}))
        elif line.startswith("[!]") and "vulnerabilit" in low:
            continue  # count header line; individual titles follow
        elif line.startswith("[+]") and ("identified" in low or "version" in low):
            obs.append(Observation("wpscan", f"WordPress: {line[3:].strip()[:140]}", "info",
                                   {"message": line[3:].strip()[:200]}))
        if len(obs) >= 25:
            break
    _ = cur_vuln
    return obs


_SSLYZE_WEAK = ("ssl 2.0", "ssl 3.0", "tls 1.0", "tls 1.1")
_SSLYZE_BADCIPHER = ("rc4", "3des", "_des_", "export", "null", "anon", "md5")


def _sslyze(text: str) -> list[Observation]:
    obs: list[Observation] = []
    clean = _clean(text)
    low = clean.lower()
    # Walk " * <Protocol> Cipher Suites:" sections; flag a weak protocol whose section
    # shows the server accepted ciphers.
    sections = re.split(r"\n\s*\*\s+", clean)
    for sec in sections:
        head = sec.splitlines()[0].lower() if sec.strip() else ""
        proto = next((p for p in _SSLYZE_WEAK if p in head and "cipher suites" in head), None)
        if proto and "accepted" in sec.lower():
            obs.append(Observation("sslyze", f"Weak TLS/SSL protocol accepted: {proto.upper()}",
                                   "medium", {"protocol": proto.upper()}))
    seen = {o.detail.get("protocol") for o in obs}
    # Weak cipher families anywhere in an "accepted" context.
    for fam in _SSLYZE_BADCIPHER:
        if fam in low and "accepted" in low:
            tag = fam.strip("_").upper()
            if tag not in seen:
                seen.add(tag)
                obs.append(Observation("sslyze", f"Weak cipher suite offered: {tag}",
                                       "medium", {"cipher_family": tag}))
    if "certificate is not trusted" in low or "failed certificate validation" in low:
        obs.append(Observation("sslyze", "Certificate not trusted / failed validation", "medium", {}))
    if re.search(r"not valid after|expired", low):
        obs.append(Observation("sslyze", "Certificate expired / past validity", "high", {}))
    if "vulnerable to heartbleed" in low or ("heartbleed" in low and "not vulnerable" not in low):
        obs.append(Observation("sslyze", "Vulnerable to Heartbleed (CVE-2014-0160)", "high",
                               {"cve": "CVE-2014-0160"}))
    if "vulnerable to robot" in low:
        obs.append(Observation("sslyze", "Vulnerable to ROBOT attack", "medium", {}))
    return obs


def _whatweb(text: str) -> list[Observation]:
    """whatweb --quiet prints one line per URL: `URL [200 OK] Apache[2.4.49], PHP[7.4], ...`.
    Fold the detected technologies into one info fingerprint observation per URL."""
    _TECH = ("apache", "nginx", "iis", "openssl", "php", "wordpress", "joomla", "drupal",
             "jquery", "bootstrap", "tomcat", "jboss", "asp.net", "express", "laravel",
             "x-powered-by", "httpserver", "microsoftofficewebserver")
    obs: list[Observation] = []
    for raw in _clean(text).splitlines():
        line = raw.strip()
        if not line or "[" not in line:
            continue
        url = line.split(" ", 1)[0]
        techs = []
        for m in re.finditer(r"([A-Za-z][\w.\-]*)\[([^\]]+)\]", line):
            name = m.group(1)
            if name.lower() in _TECH:
                val = m.group(2).strip()
                techs.append(f"{name} {val}" if val and not val.startswith("http") else name)
        if techs:
            uniq = list(dict.fromkeys(techs))[:12]
            obs.append(Observation("whatweb", f"Web stack: {', '.join(uniq)[:160]}", "info",
                                   {"url": url[:200], "technologies": uniq}))
        if len(obs) >= 10:
            break
    return obs


def _katana(text: str) -> list[Observation]:
    """katana prints discovered URLs, one per line. Record a single info observation with the
    count and a bounded sample (endpoint surface for later testing)."""
    urls = [u.strip() for u in _clean(text).splitlines()
            if u.strip().lower().startswith(("http://", "https://"))]
    if not urls:
        return []
    uniq = list(dict.fromkeys(urls))
    return [Observation("katana", f"Crawl discovered {len(uniq)} endpoint(s)", "info",
                        {"count": len(uniq), "sample": uniq[:40]})]


_PARAM_NAME_RE = re.compile(r"[A-Za-z0-9_.\-\[\]]{1,64}$")


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_ARJUN_SCANNING_RE = re.compile(r"Scanning\s+\d+/\d+:\s*(\S+)")
_ARJUN_FOUND_RE = re.compile(r"Parameters?\s+found:\s*(.+)")


def _arjun(text: str) -> list[Observation]:
    """Parse arjun's console output for discovered HTTP parameters and turn each into a
    concrete parameterised seed URL (``.../search?q=1``), recorded in `detail.sample` so
    `webvuln_seed_urls` feeds them straight into the active scanners (wapiti --start,
    nuclei -dast). Without param discovery, injection points never linked from a crawlable
    page are never tested.

    We parse arjun's TEXT output, not JSON: arjun prints `[+] Parameters found: a, b` to
    stdout, but its `-oJ` JSON is written to the output file and does NOT reliably reach
    stdout (verified against arjun 2.2.7), so a JSON-only parser silently sees nothing even
    when arjun succeeded. We also recover the scanned URL from its `Scanning N/M: <url>` line
    (the normalizer only receives stdout, not the request args). A JSON object, if one does
    appear on stdout, is tried first as a bonus."""
    clean = _ANSI_RE.sub("", text)

    # Bonus: structured JSON if arjun's build happens to emit it to stdout.
    data = _first_json(clean)
    if isinstance(data, dict) and any(
        isinstance(v, dict) and v.get("params") for v in data.values()
    ):
        seeds: list[str] = []
        total = 0
        for url, info in data.items():
            if not (isinstance(url, str) and url.lower().startswith(("http://", "https://"))):
                continue
            params = [str(x) for x in (info.get("params") or []) if x] if isinstance(info, dict) else []
            total += len(params)
            for name in params:
                if _PARAM_NAME_RE.match(name):
                    seeds.append(f"{url}{'&' if '?' in url else '?'}{name}=1")
        if seeds:
            uniq = list(dict.fromkeys(seeds))
            return [Observation("arjun", f"Parameter discovery: {total} parameter(s) found",
                                "info", {"count": total, "sample": uniq[:25]})]

    # Primary path: parse the human-readable output.
    scanned = _ARJUN_SCANNING_RE.search(clean)
    url = scanned.group(1).strip() if scanned else ""
    if not url.lower().startswith(("http://", "https://")):
        url = ""
    params: list[str] = []
    for m in _ARJUN_FOUND_RE.finditer(clean):
        for name in re.split(r"[,\s]+", m.group(1).strip()):
            name = name.strip()
            if name and _PARAM_NAME_RE.match(name):
                params.append(name)
    params = list(dict.fromkeys(params))
    if not params or not url:
        return [Observation("arjun", "Parameter discovery: no hidden parameters found", "info",
                            {"excerpt": clean.strip()[-200:]})]
    seeds = [f"{url}{'&' if '?' in url else '?'}{name}=1" for name in params]
    return [Observation("arjun", f"Parameter discovery: {len(params)} parameter(s) found "
                        f"({', '.join(params[:8])})", "info",
                        {"count": len(params), "sample": seeds[:25]})]


# curl's `-w` trailing line, exactly as the builder sets it. The builder emits the
# literal `\n--- http_code:... content_type:... size:...\n` string via -w, so the
# normalizer parses from that marker regardless of what the body looked like.
_HTTP_FETCH_META_RE = re.compile(
    r"---\s+http_code:(\d{3})\s+content_type:([^\s]+)?\s+size:(\d+)",
)


def _http_fetch(text: str) -> list[Observation]:
    """Parse the output of a `vapt_http_fetch` call: body (truncated) + status +
    content-type + size. Always ONE observation, severity info — this tool is a
    primitive, not a vuln detector. Finding promotion happens downstream when the
    LLM or another tool consumes the body (e.g. the next planning iteration spots
    an API key in a fetched JS file)."""
    clean = text or ""
    m = _HTTP_FETCH_META_RE.search(clean)
    status = m.group(1) if m else ""
    ctype = m.group(2) if m else ""
    size = m.group(3) if m else ""
    # Body is everything BEFORE the --- meta line. Capped at 2000 chars so a 1MB JS
    # file doesn't blow the observation JSON column (the broker's filesize cap is
    # 1MB; we store a prefix only — the full body is already in the ledger excerpt).
    body = clean.split("\n--- http_code:", 1)[0] if m else clean
    body = body[:2000]
    title = f"vapt_http_fetch: {status or '???'}" + (f" {ctype}" if ctype else "")
    return [Observation(
        "vapt_http_fetch",
        title,
        "info",
        {"status": status, "content_type": ctype, "size": size, "body_excerpt": body},
    )]


_SQLI_HIT_RE = re.compile(
    r"sqlmap identified the following injection point", re.IGNORECASE,
)
# sqlmap prints a block per injection point starting with "Parameter: <name> (<METHOD>)",
# then "Type:", "Title:", "Payload:" per technique. We extract the first parameter name +
# technique Type to label the finding; multiple injection points on one URL collapse into
# one observation (same parameter counted once).
_SQLI_PARAM_RE = re.compile(
    r"Parameter:\s*([A-Za-z0-9_.\-\[\]]+)\s*\((GET|POST|COOKIE|HEADER)\)",
    re.IGNORECASE,
)
_SQLI_TYPE_RE = re.compile(r"Type:\s*([^\r\n]+)", re.IGNORECASE)
# A clean "nothing found" signal — sqlmap prints this on an exhausted probe set.
_SQLI_MISS_RE = re.compile(
    r"all tested parameters do not appear to be injectable", re.IGNORECASE,
)


def _sqli_detect(text: str) -> list[Observation]:
    """Parse sqlmap's console output from a `sqli_detect` run. A confirmed injection
    emits a proof-confirmed observation (`detail.confirmed=True` so the validator can
    promote the finding to CONFIRMED directly via `_PROOF_SOURCE_TOOLS`).

    This parser is intentionally conservative: the `sqli_detect` builder restricts
    sqlmap to --technique=BE + --level/--risk 1 + no exploitation flags, so the only
    output shape we EVER accept as proof is sqlmap's standard identified-injection
    banner followed by Parameter: + Type:. An ambiguous run (connection error, 403)
    returns [] — the caller surfaces a diagnostic observation."""
    clean = _ANSI.sub("", text or "")
    if _SQLI_MISS_RE.search(clean) and not _SQLI_HIT_RE.search(clean):
        return []
    if not _SQLI_HIT_RE.search(clean):
        return []
    params: list[tuple[str, str]] = []
    for m in _SQLI_PARAM_RE.finditer(clean):
        params.append((m.group(1).strip(), m.group(2).upper()))
    if not params:
        return []
    types = [m.group(1).strip() for m in _SQLI_TYPE_RE.finditer(clean)]
    param_names = sorted({p[0] for p in params})
    first_method = params[0][1]
    title = (f"sqli_detect: SQL injection confirmed on parameter '{param_names[0]}' "
             f"({first_method}" +
             (f"; technique: {types[0]}" if types else "") +
             ")")
    return [Observation(
        "sqli_detect",
        title,
        "high",
        {
            "confirmed": True,
            "method": first_method,
            "params": param_names,
            "techniques": types[:5],
            "stdout_tail": clean[-800:],
        },
    )]


_SSTI_HIT_RE = re.compile(r"SSTImap identified the following injection point", re.IGNORECASE)
_SSTI_ENGINE_RE = re.compile(r"Engine:\s*([A-Za-z0-9_.\-]+)", re.IGNORECASE)
_SSTI_LANG_RE = re.compile(r"Language:\s*([A-Za-z0-9_.\-:]+)", re.IGNORECASE)
_SSTI_PARAM_RE = re.compile(r"parameter\s*['\"]?([A-Za-z0-9_.\-\[\]]+)['\"]?\s+is injectable",
                            re.IGNORECASE)
_SSTI_MISS_RE = re.compile(r"Tested parameters appear to be not injectable", re.IGNORECASE)


def _sstimap(text: str) -> list[Observation]:
    """Parse sstimap output. A confirmed injection prints the banner
    `SSTImap identified the following injection point:` followed by one or more lines
    like `Engine: Jinja2`, `Language: python`, and the earlier `Testing if … parameter
    'X' is injectable`. We emit ONE high-severity confirmed-style observation per
    detected injection; nothing if sstimap finds nothing. This is real on-target proof
    — payloads were sent and the server RENDERED them — unlike wapiti's reflection-only
    XSS heuristic on a template-engine endpoint."""
    clean = _ANSI_RE.sub("", text)
    if _SSTI_MISS_RE.search(clean) and not _SSTI_HIT_RE.search(clean):
        return []    # explicit miss — nothing to report
    if not _SSTI_HIT_RE.search(clean):
        return []    # ambiguous (error/no-payload) — not a finding
    engine = ""
    m = _SSTI_ENGINE_RE.search(clean)
    if m:
        engine = m.group(1).strip()
    lang = ""
    m = _SSTI_LANG_RE.search(clean)
    if m:
        lang = m.group(1).strip()
    param = ""
    m = _SSTI_PARAM_RE.search(clean)
    if m:
        param = m.group(1).strip()
    bits = []
    if param:
        bits.append(f"param {param}")
    if engine:
        bits.append(f"engine {engine}")
    detail = {"confirmed": True}
    if param:
        detail["param"] = param
    if engine:
        detail["engine"] = engine
    if lang:
        detail["language"] = lang
    title = "SSTI confirmed" + (f" ({', '.join(bits)})" if bits else "")
    return [Observation("sstimap", title, "critical", detail)]


def _idor_probe(text: str) -> list[Observation]:
    """Parse the JSON record from `workers/bin/vapt-idor-probe`:
        {"findings": [{"type", "severity", "url", "param", "evidence", "confirmed"}],
         "trace":    [...]}
    A `confirmed=True` IDOR finding (user B accessed user A's object with a DIFFERENT
    response body) auto-promotes via the proof-promotion path. A confirmed=False one
    (same body — ambiguous shared template) stays as a medium candidate for the
    validate node to decide."""
    data = _first_json(text)
    if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
        return []
    out: list[Observation] = []
    for f in data["findings"]:
        if not isinstance(f, dict):
            continue
        url = str(f.get("url", "")).strip()[:400]
        param = str(f.get("param", "")).strip()
        evidence = str(f.get("evidence", "")).strip()[:400]
        sev = str(f.get("severity") or "high").strip().lower()
        if sev not in ("info", "low", "medium", "high", "critical"):
            sev = "high"
        verified = bool(f.get("confirmed"))
        ftype = str(f.get("type", "idor"))
        method = str(f.get("method", "")).strip()
        is_delete = ftype == "idor_delete"
        if is_delete:
            label = "Destructive IDOR"
            sev = "critical" if verified else sev
        else:
            label = "IDOR"
        title = f"{label} {'confirmed' if verified else 'candidate'}" + \
                (f" ({method} " if method else " (") + \
                (f"{param})" if param else ")")
        out.append(Observation(
            "idor_probe", title[:300], sev,
            {"url": url, "param": param, "evidence": evidence,
             "confirmed": verified, "method": method,
             "subtype": ftype},
        ))
        if len(out) >= 20:
            break
    # Diagnostic: when zero findings, surface the trace so operators see WHICH URLs
    # were tested and what status codes came back (helps diagnose "no IDOR found but
    # also no coverage" from "no IDOR because truly authz-correct").
    trace = data.get("trace")
    if not out and isinstance(trace, list) and trace:
        statuses = sorted({str(t.get("status", "")) for t in trace if isinstance(t, dict)})
        out.append(Observation(
            "idor_probe",
            f"idor_probe: no cross-tenant access detected "
            f"({len(trace)} requests, statuses={statuses})",
            "info",
            {"trace": trace[:40]},
        ))
    return out


_DALFOX_SEV = {"H": "high", "M": "medium", "L": "low"}


def _dalfox(text: str, raw_obs: list[dict] | None = None) -> list[Observation]:
    """Parse dalfox's `--format json` output. The emission is a JSON array; each entry has
    at least `type` ('V' verified / 'R' reflected / 'G' grep), `method`, `data` (the proof
    URL), `param`, `payload`, `cwe`, `severity` ('H'/'M'/'L'). A Verified ('V') hit is
    REAL on-target proof (dalfox executed the payload in a headless browser and observed
    the alert fire), so it maps to a `confirmed=True` observation that auto-promotes via
    the proof-promotion path. A Reflected ('R') hit is strong but unverified → candidate.
    Grep hits are already excluded by `--only-poc r,v` at the argv level.

    Non-JSON output or an empty array yields no findings. Defensive against malformed
    entries (dalfox will sometimes mix a trailing status line in; `_first_json` tolerates
    surrounding text)."""
    data = _first_json(text)
    if not isinstance(data, list):
        return []
    out: list[Observation] = []
    seen: set[tuple[str, str, str]] = set()
    for e in data:
        if not isinstance(e, dict):
            continue
        kind = str(e.get("type", "")).strip().upper()
        if kind not in ("V", "R"):
            continue
        url = str(e.get("data", "")).strip()[:400]
        param = str(e.get("param", "")).strip()
        payload = str(e.get("payload", "")).strip()[:200]
        method = str(e.get("method", "GET")).strip().upper()
        sev_raw = str(e.get("severity", "")).strip().upper()
        sev = _DALFOX_SEV.get(sev_raw, "medium")
        cwe = str(e.get("cwe", "")).strip()
        key = (kind, url, param)
        if key in seen:
            continue
        seen.add(key)
        verified = kind == "V"
        title = f"XSS {'confirmed' if verified else 'candidate'}" + \
                (f" (param {param})" if param else "")
        detail = {
            "kind": "verified" if verified else "reflected",
            "method": method,
            "url": url,
            "param": param,
            "payload": payload,
            "cwe": cwe,
            # Only the Verified tier is proof — dalfox has actually executed the payload
            # in a headless browser. Reflected is strong but could still be a false hit
            # in an auto-escaped sink; let the validate node decide.
            "confirmed": verified,
        }
        out.append(Observation("dalfox", title[:300], sev, detail))
        if len(out) >= 50:
            break
    # Diagnostic trace when dalfox found nothing — otherwise an operator seeing a 0.5s
    # dalfox invocation has no way to tell whether it exited on a 302 (unauthenticated,
    # followed to login page), on a schema reject, or really found no XSS. We surface
    # a short stderr sample + stdout tail so the "why" is visible without ssh'ing to the
    # worker log.
    if not out and raw_obs:
        stderr_parts = [str(o.get("stderr", "")) for o in raw_obs
                        if isinstance(o, dict) and o.get("stderr")]
        stderr_tail = "\n".join(stderr_parts)[-1200:]
        stdout_tail = (text or "")[-400:]
        out.append(Observation(
            "dalfox",
            "dalfox: no XSS reported",
            "info",
            {"stderr_tail": stderr_tail, "stdout_tail": stdout_tail},
        ))
    return out


_WEB_PROBE_TITLE = {
    "open_redirect":     "Open redirect confirmed",
    "path_traversal":    "Path traversal confirmed",
    "ssrf_localhost":    "SSRF (localhost) confirmed",
    "sensitive_content": "Sensitive data exposed",
    "xxe":               "XXE confirmed",
    "cmd_injection":     "OS command injection confirmed",
    "crlf":              "CRLF/header injection confirmed",
}
_WEB_PROBE_SEV_FALLBACK = {
    "open_redirect": "medium", "path_traversal": "high", "ssrf_localhost": "high",
    "sensitive_content": "high", "xxe": "high",
    "cmd_injection": "critical", "crlf": "medium",
}


def _stored_xss_probe(text: str) -> list[Observation]:
    """Parse the JSON record emitted by `workers/bin/vapt-stored-xss-probe`.
    One invocation may emit TWO findings: `stored_xss` (synchronous via GET-view
    match) and `blind_xss` (asynchronous via OAST callback). Both carry
    `confirmed=True` on hit; both route through `_PROOF_SOURCE_TOOLS` for
    auto-promotion. Blind-only hits (visible canary missed, OAST fired) are the
    whole reason the OAST layer exists — they indicate a backend render surface
    the synchronous GET couldn't reach (admin viewer, email digest, log preview).
    """
    data = _first_json(text or "")
    if not isinstance(data, dict):
        return []
    out: list[Observation] = []
    findings = data.get("findings") if isinstance(data.get("findings"), list) else []
    trace = data.get("trace") if isinstance(data.get("trace"), list) else []
    for f in findings:
        if not isinstance(f, dict):
            continue
        confirmed = bool(f.get("confirmed"))
        klass = str(f.get("type", "stored_xss")).lower()
        if klass not in ("stored_xss", "blind_xss"):
            klass = "stored_xss"
        sev = str(f.get("severity") or ("high" if confirmed else "info")).strip().lower()
        if sev not in ("info", "low", "medium", "high", "critical"):
            sev = "high" if confirmed else "info"
        if klass == "blind_xss":
            title = (f"Blind XSS confirmed via OAST at {f.get('url')} (param {f.get('param')})"
                     if confirmed
                     else f"stored_xss_probe: no OAST callback for blind probe ({f.get('url')})")
        else:
            title = (f"Stored XSS confirmed at {f.get('url')} (param {f.get('param')})"
                     if confirmed
                     else f"stored_xss_probe: canary not reflected ({f.get('url')})")
        detail = {
            "class": klass,
            "url": str(f.get("url", ""))[:300],
            "param": str(f.get("param", ""))[:64],
            "post_url": str(f.get("post_url", ""))[:300],
            "evidence": str(f.get("evidence", ""))[:300],
            "confirmed": confirmed,
            "trace": trace[:10],
        }
        if f.get("oast_label"):
            detail["oast_label"] = str(f["oast_label"])[:64]
        out.append(Observation("stored_xss_probe", title[:300], sev, detail))
    return out


def _csp_check(text: str) -> list[Observation]:
    """Parse the JSON record emitted by `workers/bin/vapt-csp-check`. Each
    weakness becomes ONE Observation; severity is carried straight from the
    probe. `csp_check` is NOT in `_PROOF_SOURCE_TOOLS` — a weak CSP is strong
    evidence but reporting it as "confirmed vulnerability" would misclassify a
    hardening finding. The orchestrator surfaces it in the report under
    "security headers" and the operator judges severity in context.
    """
    data = _first_json(text or "")
    if not isinstance(data, dict):
        return []
    out: list[Observation] = []
    findings = data.get("findings") if isinstance(data.get("findings"), list) else []
    trace = data.get("trace") if isinstance(data.get("trace"), list) else []
    for f in findings:
        if not isinstance(f, dict):
            continue
        klass = str(f.get("type", "csp_weakness")).strip() or "csp_weakness"
        sev = str(f.get("severity") or "medium").strip().lower()
        if sev not in ("info", "low", "medium", "high", "critical"):
            sev = "medium"
        directive = str(f.get("directive", ""))[:64]
        evidence = str(f.get("evidence", ""))[:300]
        enforced = bool(f.get("enforced"))
        title = f"CSP: {klass} ({directive})" if enforced else f"CSP [report-only]: {klass} ({directive})"
        out.append(Observation(
            "csp_check",
            title[:300],
            sev,
            {
                "class": klass,
                "url": str(f.get("url", ""))[:300],
                "directive": directive,
                "evidence": evidence,
                "enforced": enforced,
                "trace": trace[:5],
            },
        ))
    if not out and trace:
        # No weaknesses found but we did fetch — emit one info observation so the
        # report shows coverage, not silence.
        t0 = trace[0] if trace else {}
        out.append(Observation(
            "csp_check",
            f"CSP posture OK ({t0.get('url', '')})",
            "info",
            {"class": "csp_ok", "trace": trace[:5]},
        ))
    return out


def _dom_xss_probe(text: str) -> list[Observation]:
    """Parse the JSON record emitted by `workers/bin/vapt-dom-xss-probe`. Each
    confirmed source→sink taint flow is one Observation with `confirmed=True`,
    promoted via `_PROOF_SOURCE_TOOLS`."""
    data = _first_json(text or "")
    if not isinstance(data, dict):
        return []
    out: list[Observation] = []
    findings = data.get("findings") if isinstance(data.get("findings"), list) else []
    trace = data.get("trace") if isinstance(data.get("trace"), list) else []
    for f in findings:
        if not isinstance(f, dict):
            continue
        confirmed = bool(f.get("confirmed"))
        sev = str(f.get("severity") or ("high" if confirmed else "info")).strip().lower()
        if sev not in ("info", "low", "medium", "high", "critical"):
            sev = "high" if confirmed else "info"
        title = (f"DOM XSS confirmed at {f.get('url')} ({f.get('param')} → sink)"
                 if confirmed
                 else f"dom_xss_probe: no DOM sink flow ({f.get('url')})")
        out.append(Observation(
            "dom_xss_probe", title[:300], sev,
            {
                "class": "dom_xss",
                "url": str(f.get("url", ""))[:300],
                "param": str(f.get("param", ""))[:64],
                "evidence": str(f.get("evidence", ""))[:300],
                "confirmed": confirmed,
                "trace": trace[:10],
            },
        ))
    return out


def _weak_cred_probe(text: str) -> list[Observation]:
    """Parse the JSON record emitted by `workers/bin/vapt-weak-cred-probe`.
    A confirmed hit = `findings[].confirmed=True` with `type=weak_credentials`.
    Promotes to CRITICAL via `_PROOF_SOURCE_TOOLS` (weak_cred_probe added to
    that set). The trace is captured as an info observation so an operator
    reading the ledger can see WHICH pairs were tried, even when nothing
    hit (useful for tuning the default pair list on an app with a custom
    marker regex).
    """
    data = _first_json(text or "")
    if not isinstance(data, dict):
        return []
    out: list[Observation] = []
    findings = data.get("findings") if isinstance(data.get("findings"), list) else []
    trace = data.get("trace") if isinstance(data.get("trace"), list) else []
    for f in findings:
        if not isinstance(f, dict):
            continue
        confirmed = bool(f.get("confirmed"))
        sev = str(f.get("severity") or ("critical" if confirmed else "info")).strip().lower()
        if sev not in ("info", "low", "medium", "high", "critical"):
            sev = "critical" if confirmed else "info"
        user = str(f.get("user", ""))[:60]
        url = str(f.get("url", ""))[:300]
        title = (f"Weak credentials: default login works ({user!r}) at {url}"
                 if confirmed
                 else f"weak_cred_probe: no default credential hit ({url})")
        out.append(Observation(
            "weak_cred_probe",
            title[:300],
            sev,
            {
                "class": "weak_credentials",
                "url": url,
                "user": user,
                "evidence": str(f.get("evidence", ""))[:300],
                "confirmed": confirmed,
                # Redact passwords from the detail payload — the full
                # trace keeps them for in-session audit but we don't want
                # a finding record carrying the exact credential pair.
                "trace": [{k: v for k, v in (r or {}).items() if k != "pass"}
                          for r in trace[:12]],
            },
        ))
    # If no findings were produced but we have a trace, surface it as an
    # info observation so operators see the probe fired and classified
    # every pair as negative. Mirrors _web_param_probe's "trace on empty"
    # behaviour.
    if not findings and trace:
        out.append(Observation(
            "weak_cred_probe",
            "weak_cred_probe: 0 defaults succeeded (trace captured)",
            "info",
            {"class": "weak_credentials", "trace_count": len(trace),
             "trace_sample": [{k: v for k, v in (r or {}).items()
                               if k != "pass"} for r in trace[:5]]},
        ))
    return out


def _xxe_probe(text: str) -> list[Observation]:
    """Parse the JSON record emitted by `workers/bin/vapt-xxe-probe`.
    A confirmed hit = `findings[].confirmed=True` with `type=xxe`.
    Promotes to CRITICAL via `_PROOF_SOURCE_TOOLS` (xxe_probe added to that
    set). The trace captures every payload shape tried + response status +
    whether it matched, so an operator can tell "no XXE" from "wrong payload
    shape for this parser".
    """
    data = _first_json(text or "")
    if not isinstance(data, dict):
        return []
    out: list[Observation] = []
    findings = data.get("findings") if isinstance(data.get("findings"), list) else []
    trace = data.get("trace") if isinstance(data.get("trace"), list) else []
    for f in findings:
        if not isinstance(f, dict):
            continue
        confirmed = bool(f.get("confirmed"))
        sev = str(f.get("severity") or ("critical" if confirmed else "info")).strip().lower()
        if sev not in ("info", "low", "medium", "high", "critical"):
            sev = "critical" if confirmed else "info"
        url = str(f.get("url", ""))[:300]
        payload = str(f.get("payload", ""))[:60]
        title = (f"XXE confirmed ({payload}) at {url}"
                 if confirmed
                 else f"xxe_probe: no XXE detected ({url})")
        out.append(Observation(
            "xxe_probe",
            title[:300],
            sev,
            {
                "class": "xxe",
                "url": url,
                "payload": payload,
                "evidence": str(f.get("evidence", ""))[:400],
                "confirmed": confirmed,
                "trace": trace[:8],
            },
        ))
    # Diagnostic observation when every payload came back negative — mirrors
    # the "0 defaults succeeded" trace surfaced by _weak_cred_probe.
    if not findings and trace:
        out.append(Observation(
            "xxe_probe",
            "xxe_probe: no XXE detected (trace captured)",
            "info",
            {"class": "xxe", "trace_count": len(trace),
             "trace_sample": trace[:6]},
        ))
    return out


def _yaml_deser_probe(text: str) -> list[Observation]:
    """Parse the JSON record emitted by `workers/bin/vapt-yaml-deser-probe`.
    Hits are `confirmed=True` and the finding promotes automatically via
    `_PROOF_SOURCE_TOOLS` (yaml_deserialization_probe is added to that set).
    """
    data = _first_json(text or "")
    if not isinstance(data, dict):
        return []
    out: list[Observation] = []
    findings = data.get("findings") if isinstance(data.get("findings"), list) else []
    trace = data.get("trace") if isinstance(data.get("trace"), list) else []
    for f in findings:
        if not isinstance(f, dict):
            continue
        confirmed = bool(f.get("confirmed"))
        sev = str(f.get("severity") or ("critical" if confirmed else "info")).strip().lower()
        if sev not in ("info", "low", "medium", "high", "critical"):
            sev = "critical" if confirmed else "info"
        title = (f"YAML deserialization confirmed at {f.get('url')}"
                 if confirmed
                 else f"yaml_deser_probe: no deserialization observed ({f.get('url')})")
        out.append(Observation(
            "yaml_deserialization_probe",
            title[:300],
            sev,
            {
                "class": "yaml_deserialization",
                "url": str(f.get("url", ""))[:300],
                "evidence": str(f.get("evidence", ""))[:300],
                "confirmed": confirmed,
                "trace": trace[:10],
            },
        ))
    return out


def _web_param_probe(text: str) -> list[Observation]:
    """Parse the JSON record emitted by `workers/bin/vapt-web-probe`:
        {"findings": [{"type", "severity", "url", "param", "evidence", "confirmed"}],
         "trace":    [{"url", "status", "cls", "note"}, ...],
         "cookie_src": "redis"|"env"|"none",
         "budget_used": N}
    Each entry becomes ONE observation whose `detail.confirmed=True` auto-promotes the
    finding to CONFIRMED via the `validate_candidate` proof-path. The `trace` is
    surfaced as a single INFO observation (`web_param_probe.trace`) ONLY when the probe
    found nothing — operators see what the probe actually tried and why nothing matched,
    without the trace cluttering a run that produced real findings. Non-JSON output =
    no finding."""
    data = _first_json(text)
    if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
        return []
    out: list[Observation] = []
    for f in data["findings"]:
        if not isinstance(f, dict):
            continue
        cls = str(f.get("type", "")).strip()
        if cls not in _WEB_PROBE_TITLE:
            continue
        url = str(f.get("url", "")).strip()[:300]
        param = str(f.get("param", "")).strip()
        evidence = str(f.get("evidence", "")).strip()[:300]
        sev = str(f.get("severity") or _WEB_PROBE_SEV_FALLBACK[cls]).strip().lower()
        if sev not in ("info", "low", "medium", "high", "critical"):
            sev = _WEB_PROBE_SEV_FALLBACK[cls]
        title = _WEB_PROBE_TITLE[cls]
        if param:
            title += f" (param {param})"
        detail = {"class": cls, "url": url, "param": param, "evidence": evidence,
                  "confirmed": bool(f.get("confirmed"))}
        out.append(Observation("web_param_probe", title[:300], sev, detail))
        if len(out) >= 20:
            break
    # Diagnostic trace: emit ONE info observation summarizing what the probe did when it
    # didn't find anything. Operators can then see "I probed /search?q with 12 params and
    # got 200/200/200/… — no reflection", which turns a mystery coverage-gap into actionable
    # evidence.
    trace = data.get("trace")
    if not out and isinstance(trace, list) and trace:
        # Some trace entries have status=None (probe got a network error, DNS fail,
        # connection refused — no HTTP response at all). Python 3's sorted() cannot
        # compare None with int, so put None LAST via a sort key. Previously raised
        # TypeError on any OAST canary that didn't resolve (interactsh subdomain not
        # yet DNS-propagated).
        statuses = sorted(
            {t.get("status") for t in trace if isinstance(t, dict)},
            key=lambda x: (x is None, x if x is not None else 0),
        )
        classes = sorted({t.get("cls", "") for t in trace if isinstance(t, dict)})
        out.append(Observation(
            "web_param_probe",
            f"web_param_probe: no vuln signature matched ({len(trace)} probes, "
            f"statuses={statuses}, classes={classes})",
            "info",
            {"trace": trace[:40], "cookie_src": data.get("cookie_src"),
             "budget_used": data.get("budget_used")},
        ))
    return out


def _shcheck(text: str) -> list[Observation]:
    """shcheck reports missing/misconfigured HTTP security headers. Each missing header is a
    low-severity hardening finding."""
    obs: list[Observation] = []
    for raw in _clean(text).splitlines():
        m = re.search(r"missing (?:security )?header[:\s]+([A-Za-z\-]+)", raw, re.IGNORECASE)
        if m:
            hdr = m.group(1).strip()
            obs.append(Observation("shcheck", f"Missing security header: {hdr}", "low",
                                   {"header": hdr}))
        if len(obs) >= 15:
            break
    return obs


def _ferox(text: str) -> list[Observation]:
    """feroxbuster --silent prints discovered URLs (one per line). Record a single info
    observation with the count + a bounded sample (content-discovery surface)."""
    urls = []
    for raw in _clean(text).splitlines():
        m = re.search(r"https?://\S+", raw)
        if m:
            urls.append(m.group(0))
    if not urls:
        return []
    uniq = list(dict.fromkeys(urls))
    return [Observation("feroxbuster", f"Content discovery: {len(uniq)} path(s) found", "info",
                        {"count": len(uniq), "sample": uniq[:40]})]


def _wafw00f_scan(text: str) -> list[Observation]:
    """wafw00f reports whether a WAF/IDS fronts the site. 'is behind X' → WAF present;
    'No WAF' → explicitly none. Either way, one info observation (not a vuln, just posture)."""
    low = _clean(text).lower()
    if "is behind" in low:
        m = re.search(r"is behind\s+(.+?)(?:\s+waf|\s+\(|\.|\n|$)", low)
        name = (m.group(1).strip() if m else "a WAF")[:80]
        return [Observation("wafw00f", f"WAF/IDS detected: {name}", "info", {"waf": name})]
    if "no waf" in low or "not behind" in low:
        return [Observation("wafw00f", "No WAF/IDS detected", "info", {})]
    return []


def _cmseek(text: str) -> list[Observation]:
    """CMSeeK detects the CMS behind a site. Emit a finding ONLY when a CMS was actually
    identified; on a non-CMS target (e.g. plain IIS) cmseek exits 1 and we record nothing —
    not the generic 'cmseek output' excerpt the fallback would otherwise produce."""
    clean = _clean(text)
    low = clean.lower()
    if "could not detect" in low or "no cms" in low or "may not be" in low:
        return []
    m = re.search(r"cms(?:\s*id|\s*name)?\s*[:=]\s*([A-Za-z][\w.\- ]{1,30})", clean, re.IGNORECASE)
    if not m:
        return []
    name = m.group(1).strip().rstrip(".")
    return [Observation("cmseek", f"CMS detected: {name}", "info", {"cms": name})]


def _smbmap(text: str) -> list[Observation]:
    """smbmap lists SMB shares and the access the (null/authenticated) session has. An
    accessible share is notable: writable → medium, readable → low. NO ACCESS rows are
    dropped (not a finding)."""
    obs: list[Observation] = []
    for raw in _clean(text).splitlines():
        line = raw.strip()
        m = re.match(r"(\S+)\s+(READ ONLY|READ,\s*WRITE|WRITE ONLY|NO ACCESS)\b", line, re.IGNORECASE)
        if not m:
            continue
        share, perm = m.group(1), re.sub(r"\s+", " ", m.group(2).upper())
        if "NO ACCESS" in perm:
            continue
        sev = "medium" if "WRITE" in perm else "low"
        obs.append(Observation("smbmap", f"SMB share accessible: {share} ({perm})", sev,
                               {"share": share, "permissions": perm}))
        if len(obs) >= 20:
            break
    return obs


# wapiti vulnerability category -> severity. wapiti's categories are stable strings; the
# injection / high-impact classes map up, the config/info classes map down. Anything
# unrecognised is medium — it is still an ACTIVE-scanner confirmed web vuln, never info.
_WAPITI_SEV: tuple[tuple[tuple[str, ...], str], ...] = (
    (("sql injection", "command execution", "command injection", "path traversal",
      "file handling", "remote file inclusion", "local file inclusion", "xxe",
      "server side request forgery", "ssrf", "deserialization", "spring4shell",
      "log4shell", "ldap injection", "xpath injection"), "high"),
    (("cross site scripting", "xss", "cross-site request forgery", "csrf",
      "open redirect", "crlf", "sql", "injection"), "medium"),
    (("secure headers", "http methods", "cookie", "content security policy",
      "fingerprint", "backup file", "htaccess", "internal server error"), "low"),
)


def _wapiti_sev(category: str) -> str:
    c = category.lower()
    for needles, sev in _WAPITI_SEV:
        if any(n in c for n in needles):
            return sev
    return "medium"


def _wapiti(text: str) -> list[Observation]:
    """Parse wapiti's JSON report (`-f json`). Each entry under `vulnerabilities`
    (e.g. 'SQL Injection', 'Cross Site Scripting') becomes one Observation whose severity
    is derived from its category — so an active-scanner finding such as SQLi surfaces as a
    real high/medium finding instead of the single generic 'wapiti output' blob the fallback
    produced before. Defensive: non-JSON or empty output yields no findings, never raises.

    wapiti prints progress to stderr and the report to stdout, possibly with a banner line
    around it; _first_json tolerates surrounding text."""
    data = _first_json(text)
    if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), dict):
        return []
    out: list[Observation] = []
    seen: set[tuple] = set()
    for category, entries in data["vulnerabilities"].items():
        if not isinstance(entries, list):
            continue
        sev = _wapiti_sev(str(category))
        for e in entries:
            if not isinstance(e, dict):
                continue
            path = str(e.get("path") or e.get("url") or "/")
            param = str(e.get("parameter") or e.get("param") or "")
            method = str(e.get("method") or "GET")
            key = (str(category), method, path, param)
            if key in seen:
                continue
            seen.add(key)
            title = f"wapiti: {category} at {path}" + (f" (param: {param})" if param else "")
            # Parse the Host header out of http_request so the probe planner knows WHICH
            # web base this finding came from. On DineHub, wapiti ran against port 5000
            # (the Flask app) but the path "/fetch/logo" would otherwise get joined to
            # port 80 (IIS) in the probe plan — producing 404 on every probe. Keeping
            # host:port here lets `discovered_endpoint_urls` build the correct URL.
            http_req = str(e.get("http_request", ""))
            host_port = ""
            host_m = re.search(r"(?mi)^Host:\s*([^\r\n]+)", http_req)
            if host_m:
                host_port = host_m.group(1).strip()
            detail = {
                "category": str(category),
                "method": method,
                "path": path,
                "parameter": param,
                "info": str(e.get("info", ""))[:400],
                "level": e.get("level"),
                "http_request": http_req[:600],
                "host": host_port,  # "172.25.188.23:5000" when wapiti could read it
            }
            out.append(Observation("wapiti", title[:300], sev, detail))
            if len(out) >= 100:            # bound a pathological report
                return out
    return out
