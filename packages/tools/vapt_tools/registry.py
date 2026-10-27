"""Tool registry + safe argv builders (plan §7).

The model picks a tool_id and typed args. A trusted adapter builds an argv array with
shell execution disabled; free-form command strings are never exposed. Each spec maps
to a policy class so the registry and policy engine agree on risk.
"""
from __future__ import annotations

import ipaddress
import os
import re
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlparse

from vapt_domain.enums import AgentRole, PolicyClass

_HOST_RE = re.compile(r"^[a-zA-Z0-9.-]{1,253}$")


def _reject_option_like(value: str) -> None:
    if value.startswith("-"):
        raise ValueError(f"option-like value rejected: {value!r}")


def _web_login_cookie() -> str:
    """The authenticated-session Cookie value to inject into web tools' requests.
    Preferred source is the Redis slot keyed by VAPT_RUN_ID (TTL-bounded, cleared when
    the webvuln phase ends); the VAPT_WEB_LOGIN_COOKIE env is kept as a fallback so
    offline tests still work. We validate the shape so a stray newline or option-like
    prefix can't poison the argv."""
    import os as _os
    c = ""
    run_id = _os.environ.get("VAPT_RUN_ID", "").strip()
    if run_id:
        try:
            import redis as _redis
            _r = _redis.Redis.from_url(
                _os.environ.get("VAPT_REDIS_URL", "redis://localhost:6379/0"),
                socket_timeout=3,
            )
            raw = _r.get(f"vapt:webcookie:{run_id}")
            if raw:
                c = raw.decode() if isinstance(raw, bytes) else str(raw)
        except Exception:
            c = ""
    if not c:
        c = _os.environ.get("VAPT_WEB_LOGIN_COOKIE", "").strip()
    c = c.strip()
    if not c:
        return ""
    if any(ch in c for ch in ("\r", "\n", "\x00")):
        return ""
    if c.startswith("-"):
        return ""
    return c


def _web_login_credentials() -> tuple[str, str] | None:
    """Operator-supplied web credentials (user, password) for the current run.
    Pulled from the Redis JSON blob the API router stashed under VAPT_RUN_ID (same
    key schema as web_credentials.set_web_credentials: "vapt:webcreds:<run_id>" ->
    {"u": username, "p": password}). None if the operator didn't supply any. Used
    by wapiti's native --form-* login as a fallback when the Python-side session
    cookie didn't come through — wapiti then does its own POST to the login URL.
    Credentials never cross argv for the orchestrator's log/digest; this helper
    reads them only at tool-builder time."""
    import os as _os
    import json as _json
    run_id = _os.environ.get("VAPT_RUN_ID", "").strip()
    if not run_id:
        return None
    try:
        import redis as _redis
        _r = _redis.Redis.from_url(
            _os.environ.get("VAPT_REDIS_URL", "redis://localhost:6379/0"),
            socket_timeout=3,
        )
        raw = _r.get(f"vapt:webcreds:{run_id}")
        if not raw:
            return None
        d = _json.loads(raw if isinstance(raw, (bytes, str)) else str(raw))
        u = str(d.get("u", "")).strip()
        p = str(d.get("p", "")).strip()
        if not (u and p):
            return None
        # Reject anything that would poison argv (newlines, option-like prefix).
        if any(ch in u + p for ch in ("\r", "\n", "\x00")):
            return None
        if u.startswith("-") or p.startswith("-"):
            return None
        return (u, p)
    except Exception:
        return None


def _valid_host(host: str) -> str:
    _reject_option_like(host)
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    if not _HOST_RE.match(host):
        raise ValueError(f"invalid host/target: {host!r}")
    return host


@dataclass
class ToolSpec:
    id: str
    version: str
    policy_class: PolicyClass
    allowed_agents: list[AgentRole]
    supported_modes: list[str]
    build_argv: Callable[[dict], list[str]]
    timeout_s: int = 120
    description: str = ""
    # Exit codes that mean "ran successfully". Some scanners use a non-zero exit to
    # signal that they FOUND something (e.g. zap-baseline.py: 1=FAIL, 2=WARN) rather
    # than to signal an error — for those, the extra codes belong here so a run with
    # findings isn't mistaken for a failed run and silently dropped.
    ok_exit_codes: tuple[int, ...] = (0,)
    # "network" tools act on an in-scope host/URL (scope = domains/CIDRs).
    # "local" tools act on the engagement's own uploaded source bundle in the run
    # workspace; their scope is the bundle, not a host, so the harness treats them as
    # in-scope-by-workspace rather than checking domain/CIDR membership.
    target_kind: str = "network"


def _build_httpx(args: dict) -> list[str]:
    # ProjectDiscovery's httpx. Its binary name collides with the Python `httpx`
    # library's CLI, which may shadow it on PATH (e.g. inside an activated venv), so the
    # binary is overridable: set VAPT_HTTPX_BIN to the ProjectDiscovery httpx path.
    binary = os.environ.get("VAPT_HTTPX_BIN", "httpx")
    target = _valid_host(str(args["target"]))
    # Optional explicit port (for probing a service nmap discovered on a non-standard
    # port). Validated as digits only, then appended host:port — never shell-interpolated.
    port = args.get("port")
    if port is not None and str(port) != "":
        p = str(port)
        if not re.fullmatch(r"\d{1,5}", p) or not 0 < int(p) < 65536:
            raise ValueError(f"invalid port: {port!r}")
        target = f"{target}:{p}"
    # -no-color keeps ANSI escapes out of the captured output (they'd otherwise end up
    # in finding titles).
    # Capture status + title + Server header + Wappalyzer tech-detect. Server banner and the
    # tech list are the inputs the webvuln phase uses later to pick the right SSTI engine
    # (e.g. Werkzeug / Flask → Jinja2) without hardcoding; absent them, SSTI falls back to
    # sstimap's full engine probe.
    argv = [binary, "-silent", "-no-color", "-status-code", "-title",
            "-server", "-tech-detect", "-u", target]
    if args.get("follow_redirects"):
        argv.append("-follow-redirects")
    return argv


def _build_dns(args: dict) -> list[str]:
    # P0 passive local DNS resolution; does not authorize probing.
    # Binary overridable (ProjectDiscovery dnsx) so the worker can point at an explicit
    # path regardless of what's on PATH — same pattern as httpx.
    binary = os.environ.get("VAPT_DNSX_BIN", "dnsx")
    target = _valid_host(str(args["target"]))
    return [binary, "-silent", "-a", "-resp", "-d", target]


def _bounded_ports(args: dict) -> str:
    """Validate a ports spec: digits, commas and single hyphens only (e.g. 80,443,8000-8100)."""
    ports = str(args.get("ports", "80,443"))
    if not re.fullmatch(r"\d{1,5}(?:-\d{1,5})?(?:,\d{1,5}(?:-\d{1,5})?)*", ports):
        raise ValueError(f"invalid ports spec: {ports!r}")
    return ports


def _build_nmap(args: dict) -> list[str]:
    # P1 bounded service discovery WITH version detection (-sV), so each open service
    # reports its software + version (e.g. "Microsoft IIS httpd 10.0"), not just the
    # default port name. -sV only probes ports found open, so the cost scales with the
    # number of services, not the port range. Fixed timing, TCP connect (non-privileged).
    target = _valid_host(str(args["target"]))
    ports = _bounded_ports(args)
    return ["nmap", "-sT", "-sV", "-Pn", "-T3", "-p", ports, "-oX", "-", target]


# Fixed, SAFE NSE discovery scripts for Windows service posture. Not model-controllable:
# the scan agent chooses the tool + ports, never the scripts, so no intrusive/exploit
# category can be smuggled in.
_NSE_SCRIPTS = "smb2-security-mode,smb-security-mode,smb-os-discovery,rdp-ntlm-info,nbstat"


def _build_host_scripts(args: dict) -> list[str]:
    # Bounded NSE host scripting on discovered Windows service ports (safe discovery
    # category only). Fixed timing, TCP connect, no privileged scan types.
    target = _valid_host(str(args["target"]))
    ports = _bounded_ports(args)
    return ["nmap", "-sT", "-Pn", "-T3", "-p", ports, "--script", _NSE_SCRIPTS, "-oX", "-", target]


# Windows vulnerability DETECTION scripts — safe checks only (they fingerprint the vuln,
# they do NOT exploit or risk crashing the host). smb-vuln-ms17-010 (EternalBlue) is the
# canonical safe one. Crash-risky scripts (smb-vuln-ms08-067, rdp-vuln-ms12-020, DoS
# checks) are intentionally EXCLUDED — silently crashing a target is not acceptable even
# with approval; they'd need a separate, explicitly-aggressive profile.
_WIN_VULN_SCRIPTS = "smb-vuln-ms17-010"

# Aggressive Windows vuln checks that CAN crash the target (DoS/intrusive category). Only
# runs when the engagement authorized P2 intrusive actions AND a human approves it — the
# operator explicitly accepts the crash risk. Never automatic.
_WIN_VULN_AGGRESSIVE_SCRIPTS = "smb-vuln-ms08-067,rdp-vuln-ms12-020"


def _build_win_vuln(args: dict) -> list[str]:
    target = _valid_host(str(args["target"]))
    ports = _bounded_ports(args)
    return ["nmap", "-sT", "-Pn", "-T3", "-p", ports, "--script", _WIN_VULN_SCRIPTS, "-oX", "-", target]


def _build_win_vuln_aggressive(args: dict) -> list[str]:
    target = _valid_host(str(args["target"]))
    ports = _bounded_ports(args)
    return ["nmap", "-sT", "-Pn", "-T3", "-p", ports,
            "--script", _WIN_VULN_AGGRESSIVE_SCRIPTS, "-oX", "-", target]


def _build_nmap_vuln(args: dict) -> list[str]:
    # Service→CVE matching: version detection (-sV) + the nmap `vulners` script, which
    # maps detected service versions to known CVEs with CVSS scores. Bounded ports, fixed
    # timing, TCP connect (non-privileged). Version detection is low-impact (P1).
    target = _valid_host(str(args["target"]))
    ports = _bounded_ports(args)
    return ["nmap", "-sT", "-sV", "-Pn", "-T3", "-p", ports,
            "--script", "vulners", "-oX", "-", target]


def _build_nuclei(args: dict) -> list[str]:
    # Severity-bounded template scan. Default profile is non-intrusive (info/low/medium);
    # the intrusive profile is classified P2 via a separate spec below.
    target = _valid_host(str(args["target"]))
    sev = str(args.get("severity", "info,low,medium"))
    if not re.fullmatch(r"(info|low|medium|high|critical)(?:,(info|low|medium|high|critical))*", sev):
        raise ValueError(f"invalid severity set: {sev!r}")
    # Optional scheme/port so an active (P2) scan can target a web app on a non-standard
    # port (e.g. http://host:5000) instead of a hardcoded https/443. Backward compatible:
    # with neither supplied it stays https://<target>, exactly as before.
    scheme = "http" if str(args.get("scheme", "")).lower() == "http" else "https"
    url = f"{scheme}://{target}"
    port = args.get("port")
    if port is not None and str(port) != "":
        p = str(port)
        if not re.fullmatch(r"\d{1,5}", p) or not 0 < int(p) < 65536:
            raise ValueError(f"invalid port: {port!r}")
        url = f"{scheme}://{target}:{p}"
    argv = ["nuclei", "-silent", "-severity", sev]
    _c = _web_login_cookie()
    if _c:
        argv += ["-H", f"Cookie: {_c}"]
    argv += ["-u", url]
    return argv


def _build_nuclei_dast(args: dict) -> list[str]:
    """Nuclei DAST fuzzing. Unlike the template scan, this fuzzes the QUERY PARAMETERS of the
    URLs it is given — so it only finds injection (XSS/LFI/SSRF/open-redirect/SSTI/XXE) on
    parameters it can see. webvuln hands it `seeds`: the parameterised URLs that discovery
    (katana/feroxbuster/arjun) surfaced; each becomes a `-u` target so one run fuzzes the whole
    discovered param surface. With no seeds it falls back to fuzzing the base URL. argv-only +
    validated, same contract as every other builder."""
    binary = os.environ.get("VAPT_NUCLEI_BIN", "nuclei")
    target = _valid_host(str(args["target"]))
    sev = str(args.get("severity", "low,medium,high,critical"))
    if not re.fullmatch(r"(info|low|medium|high|critical)(?:,(info|low|medium|high|critical))*", sev):
        raise ValueError(f"invalid severity set: {sev!r}")
    scheme = "http" if str(args.get("scheme", "")).lower() == "http" else "https"
    base = f"{scheme}://{target}"
    port = args.get("port")
    if port is not None and str(port) != "":
        p = str(port)
        if not re.fullmatch(r"\d{1,5}", p) or not 0 < int(p) < 65536:
            raise ValueError(f"invalid port: {port!r}")
        base = f"{scheme}://{target}:{p}"
    # Only in-scope http(s) seed URLs for THIS host; reject option-like tokens. Bounded so the
    # argv (and the scan) stays sane on a large discovered surface.
    targets: list[str] = []
    for s in (args.get("seeds") or []):
        s = str(s).strip()
        if not s.lower().startswith(("http://", "https://")):
            continue
        _reject_option_like(s)
        if urlparse(s).hostname != target:
            continue
        if s not in targets:
            targets.append(s)
        if len(targets) >= 25:
            break
    # -dast enables fuzzing templates in current nuclei (the old -fuzz flag is
    # deprecated and -fuzzing-templates is NOT a valid flag — it caused exit code 2
    # on DineHub runs). -dast alone runs the full fuzzing library on seed URLs
    # (SQLi/XSS/SSTI/LFI/SSRF/open-redirect/header injection).
    argv = [binary, "-dast", "-silent", "-severity", sev]
    _c = _web_login_cookie()
    if _c:
        argv += ["-H", f"Cookie: {_c}"]
    for u in (targets or [base]):
        argv += ["-u", u]
    return argv


def _build_wapiti(args: dict) -> list[str]:
    """Active web-app scan. Built-in (not a plain catalog template) so webvuln can hand it
    the endpoints the bare-root crawl would never reach: `seeds` (extra --start entry-point
    URLs, e.g. unlinked routes discovered by the crawl or supplied by the operator) plus an
    optional crawl `depth` and `modules` set. Scheme/port aware; JSON report on stdout so the
    findings are parsed. argv-only + validated, same contract as every other builder."""
    target = _valid_host(str(args["target"]))
    scheme = "http" if str(args.get("scheme", "")).lower() == "http" else "https"
    url = f"{scheme}://{target}"
    port = args.get("port")
    if port is not None and str(port) != "":
        p = str(port)
        if not re.fullmatch(r"\d{1,5}", p) or not 0 < int(p) < 65536:
            raise ValueError(f"invalid port: {port!r}")
        url = f"{scheme}://{target}:{p}"
    argv = ["wapiti", "-u", url, "--flush-session", "-f", "json", "-o", "/dev/stdout"]
    # Explicit module set — wapiti3's "used by default" is narrow (exec/file/sql/xss/
    # ssrf/upload/redirect/ssl/permanentxss) and silently SKIPS high-value classes we
    # need: csrf, xxe, crlf, timesql, backup, takeover. The caller can override via
    # `modules` arg; otherwise we force the expanded set. brute_login_form and
    # shellshock intentionally excluded (brute: account lockouts; shellshock: ancient).
    # Verified against wapiti 3.3.2 --list-modules — invalid names here crash wapiti
    # with exit=2 and NO findings get reported (regression on 2026-10-21).
    modules = str(args.get("modules", "")).strip() or (
        "exec,file,permanentxss,redirect,sql,ssrf,upload,xss,ssl,"
        "csrf,xxe,crlf,backup,timesql,takeover,wapp,methods"
    )
    if not re.fullmatch(r"[a-z0-9_]+(?:,[a-z0-9_]+)*", modules):
        raise ValueError(f"invalid wapiti modules: {modules!r}")
    argv += ["-m", modules]
    # Optional crawl depth (1-2 digits).
    depth = args.get("depth")
    if depth is not None and str(depth) != "":
        if not re.fullmatch(r"\d{1,2}", str(depth)):
            raise ValueError(f"invalid depth: {depth!r}")
        argv += ["-d", str(depth)]
    # Seed extra entry-point URLs. Each must be an in-scope http(s) URL for THIS base host;
    # anything option-like or off-host is rejected (the caller also pre-filters by host).
    for s in (args.get("seeds") or []):
        s = str(s).strip()
        if not s.lower().startswith(("http://", "https://")):
            continue
        _reject_option_like(s)
        if urlparse(s).hostname != target:
            continue
        argv += ["--start", s]
    # Hard runtime caps. Prior fully-authenticated runs on DineHub hit the 10-minute
    # subprocess timeout AT port=5000 even with --max-scan-time 300 set — the auth-crawl
    # had surfaced 34 endpoints, each module (17 of them) attacks every endpoint, and
    # one slow module could hang past the overall cap. Two caps work together:
    #   --max-scan-time  — overall wall-clock ceiling for the whole run
    #   --max-attack-time — per-module ceiling (so a stuck module can't eat the budget)
    # The ToolSpec's subprocess timeout is 600s; we aim for self-exit well under that.
    # Operator can override via args["max_scan_time"] / args["max_attack_time"].
    _max_scan = args.get("max_scan_time", 240)
    if _max_scan is not None:
        _ms = str(_max_scan).strip()
        if not re.fullmatch(r"\d{1,5}", _ms) or int(_ms) < 30:
            raise ValueError(f"invalid max_scan_time: {_max_scan!r}")
        argv += ["--max-scan-time", _ms]
    _max_attack = args.get("max_attack_time", 60)
    if _max_attack is not None:
        _ma = str(_max_attack).strip()
        if not re.fullmatch(r"\d{1,5}", _ma) or int(_ma) < 10:
            raise ValueError(f"invalid max_attack_time: {_max_attack!r}")
        argv += ["--max-attack-time", _ma]
    # Authenticated scan: inject session cookie if the webvuln node obtained one.
    _c = _web_login_cookie()
    if _c:
        argv += ["-H", f"Cookie: {_c}"]
    # Native wapiti form-login fallback: when the operator supplied creds + a login_url
    # was discovered during probe/webvuln, pass them to wapiti so it self-authenticates
    # even when the Python-side session cookie above is missing. BUT only when we DON'T
    # already have a cookie — passing BOTH the cookie AND --form-* makes wapiti re-login
    # mid-scan and discover far more routes than the cookie alone would, which is what
    # pushed the port-5000 run past 10 minutes last time. Cookie-only = fast, auth-only
    # = fallback. Wapiti 3.3.2 flags: --form-url + --form-user/--form-password; wapiti
    # auto-detects form fields the same way web_login does. Credentials come from the
    # Redis slot only, never from argv at plan time (which would leak into digest/ledger).
    _login_url = str(args.get("login_url") or "").strip()
    if _login_url and _login_url.lower().startswith(("http://", "https://")) and not _c:
        _reject_option_like(_login_url)
        if urlparse(_login_url).hostname == target:
            _creds = _web_login_credentials()
            if _creds:
                _user, _pw = _creds
                argv += ["--form-url", _login_url,
                         "--form-user", _user,
                         "--form-password", _pw]

    return argv


def _build_arjun(args: dict) -> list[str]:
    """arjun parameter discovery. Takes an explicit endpoint `url` (an in-scope route such as
    http://host:5000/search) so params are found WHERE they live, not just on the site root.
    Falls back to scheme://host[:port] when no url is given. _arjun parses the discovered params
    (from arjun's console output) into parameterised seed URLs for the active scanners. argv-only.

    NOTE: no -oJ — arjun's JSON output does not reliably reach stdout (verified vs 2.2.7); the
    normalizer parses arjun's "Parameters found:" text line instead."""
    binary = os.environ.get("VAPT_ARJUN_BIN", "arjun")
    target = _valid_host(str(args["target"]))
    url = str(args.get("url", "")).strip()
    if url:
        if not url.lower().startswith(("http://", "https://")):
            raise ValueError(f"arjun url must be http(s): {url!r}")
        _reject_option_like(url)
        if urlparse(url).hostname != target:
            raise ValueError(f"arjun url off-scope: {url!r}")
    else:
        scheme = "http" if str(args.get("scheme", "")).lower() == "http" else "https"
        url = f"{scheme}://{target}"
        port = args.get("port")
        if port is not None and str(port) != "":
            p = str(port)
            if not re.fullmatch(r"\d{1,5}", p) or not 0 < int(p) < 65536:
                raise ValueError(f"invalid port: {port!r}")
            url = f"{scheme}://{target}:{p}"
    argv = [binary, "-u", url]
    _c = _web_login_cookie()
    if _c:
        argv += ["--headers", f"Cookie: {_c}"]
    return argv


# sqlmap flags that MUST NEVER appear in a sqli_detect argv. This isn't a safety
# feature of the builder (the builder constructs the argv from a fixed template and
# never accepts a raw flag string); it is a review checklist for anyone editing the
# function below. If a flag that writes to the target, dumps data, executes code, or
# escalates to a shell appears here, the invariant is broken.
_SQLI_DETECT_FORBIDDEN = (
    "--os-shell", "--os-cmd", "--os-pwn", "--os-smbrelay", "--os-bof",
    "--eval", "--sql-shell", "--sql-query",
    "--dump", "--dump-all", "--dbs", "--tables", "--columns", "--schema", "--search",
    "--passwords", "--privileges", "--roles", "--current-user", "--current-db",
    "--file-read", "--file-write", "--file-dest",
    "--udf-inject", "--shared-lib", "--reg-add", "--reg-del",
)


# Headers the LLM may pass through vapt-http-fetch. Whitelist, not blacklist — a safe
# header set we can defend. Content-Type / Accept are needed for API probes;
# X-Forwarded-For / X-Original-URL cover the SSRF-via-header class; a single wildcard
# X-* is permitted so the LLM can set custom test headers without opening every stock
# header (Authorization/Cookie/Host are deliberately NOT in the list — those come from
# the engagement's own cookie slot and the URL host, respectively).
_HTTP_FETCH_HEADER_RE = re.compile(
    r"^(?:Accept|Accept-Encoding|Accept-Language|Content-Type|Referer|"
    r"X-Forwarded-For|X-Forwarded-Host|X-Original-URL|X-Rewrite-URL|"
    r"X-[A-Za-z0-9][A-Za-z0-9\-]{0,32})$"
)


def _build_http_fetch(args: dict) -> list[str]:
    """Bounded curl wrapper the LLM webvuln planner can propose. One request per call,
    scope-checked URL, hardcoded safe flags. The LLM can ask for GET or POST with a body
    and a short list of whitelisted headers; everything else is refused at build time.

    What this builder NEVER emits (defense against prompt-injected argv shaping):
      -o/--output, -K/--config, --no-fail-with-body, -E/--cert, -k/--insecure,
      --proxy, -u/--user, --netrc, --netrc-file, --resolve, --location-trusted,
      --upload-file, --interface, --unix-socket, --connect-to

    args:
      target  — in-scope host (REQUIRED).
      url     — full http(s) URL for the fetch (REQUIRED, must match target host).
      method  — "get" (default) or "post".
      data    — optional POST body ("k=v[&k=v...]"), validated.
      headers — optional list of "Header-Name: value" strings; each name must match
                `_HTTP_FETCH_HEADER_RE`, each value is checked for CRLF/NUL.

    The session cookie from `_web_login_cookie()` is injected automatically — same
    behavior as every other web tool in the registry. The output has a trailing
    `--- http_code:... content_type:... size:...` line that the normalizer parses.
    """
    binary = os.environ.get("VAPT_CURL_BIN", "curl")
    target = _valid_host(str(args["target"]))
    url = str(args.get("url", "")).strip()
    if not url.lower().startswith(("http://", "https://")):
        raise ValueError(f"vapt-http-fetch needs a full http(s) url: {url!r}")
    _reject_option_like(url)
    if urlparse(url).hostname != target:
        raise ValueError(f"vapt-http-fetch url off-scope: {url!r}")

    method = str(args.get("method", "get")).strip().lower()
    if method not in ("get", "post"):
        raise ValueError(f"invalid vapt-http-fetch method: {method!r}")

    # Hardcoded safe flags. --max-time: 10s wall-clock per call. --max-filesize: 1MB
    # body cap so the normalizer never ingests megabytes. --no-progress-meter: no
    # progress noise on stdout. -A: fixed User-Agent so target logs can attribute the
    # scan. -w: appended format line the normalizer parses for status/content-type.
    argv = [
        binary, "-sS", "--max-time", "10", "--max-filesize", "1048576",
        "--no-progress-meter",
        "-A", "vapt-http-fetch/1.0",
        "-X", method.upper(),
        "-w", "\\n--- http_code:%{http_code} content_type:%{content_type} "
              "size:%{size_download}\\n",
    ]

    # Optional body — same k=v[&k=v]* validator as sqli_detect, no arbitrary payloads.
    data = str(args.get("data", "")).strip()
    if data:
        _reject_option_like(data)
        if not re.fullmatch(
            r"[A-Za-z0-9_.\-\[\]]+=[^&\s]+(?:&[A-Za-z0-9_.\-\[\]]+=[^&\s]+)*", data
        ):
            raise ValueError(f"invalid vapt-http-fetch data: {data!r}")
        argv += ["--data-raw", data]
    if method == "post" and not data:
        raise ValueError("vapt-http-fetch method=post requires `data`")

    # Whitelisted headers. Each must be "Name: value" with Name matching the regex and
    # value free of CRLF / NUL (which would otherwise terminate the HTTP request line
    # or inject new headers).
    raw_headers = args.get("headers") or []
    if not isinstance(raw_headers, list):
        raise ValueError("vapt-http-fetch headers must be a list of strings")
    for h in raw_headers:
        if not isinstance(h, str):
            raise ValueError("vapt-http-fetch header entries must be strings")
        _reject_option_like(h)
        if ":" not in h:
            raise ValueError(f"vapt-http-fetch header missing ':': {h!r}")
        name, _, value = h.partition(":")
        name = name.strip()
        value = value.strip()
        if not _HTTP_FETCH_HEADER_RE.fullmatch(name):
            raise ValueError(f"vapt-http-fetch header name not allowed: {name!r}")
        if any(ch in value for ch in ("\r", "\n", "\x00")):
            raise ValueError(f"vapt-http-fetch header value has CR/LF/NUL: {name!r}")
        if len(value) > 1024:
            raise ValueError(f"vapt-http-fetch header value too long: {name!r}")
        argv += ["-H", f"{name}: {value}"]

    _c = _web_login_cookie()
    if _c:
        argv += ["-H", f"Cookie: {_c}"]

    # URL goes last so an operator reading the argv in the ledger immediately sees
    # WHICH URL got hit for a given call.
    argv.append(url)
    return argv


def _build_sqli_detect(args: dict) -> list[str]:
    """sqlmap wrapped as a BOUNDED, non-destructive DETECTION tool — same pattern as
    `ssti_detect` is to `sstimap`. Sends payloads, so P2_INTRUSIVE and SCAN/VALIDATE
    agents only (NEVER the ATTACK agent, which runs full `sqlmap` from the catalog as a
    separate id). Confirms a wapiti SQLi candidate on-target without any exploitation.

    args:
      target — in-scope host (REQUIRED, scope-checked).
      url    — full http(s) URL for the vulnerable endpoint (REQUIRED).
      param  — optional pinned parameter name (uses sqlmap `-p`); dramatically faster
               when wapiti/arjun already named the vector.
      data   — optional POST body ("k=v[&k=v...]"), validated.
      method — "get" (default) or "post" — if "post", requires `data`.
      technique — restricted alphabet "BET"-subset; default "BE" (boolean + error).
                  'S' (stacked) and 'U' (union) and 'T' (time) are permitted on explicit
                  request but default off: stacked can WRITE to the DB, union can crash
                  a misconfigured UNION path, time-based blows the subprocess budget.

    What this builder NEVER emits (see `_SQLI_DETECT_FORBIDDEN`): --os-shell, --os-cmd,
    --eval, --dump, --dump-all, --dbs, --tables, --columns, --schema, --passwords,
    --privileges, --sql-shell, --sql-query, --file-read, --file-write, --udf-inject.
    These are catalog `sqlmap` territory (ATTACK agent only, human-gated playbook).

    Normalizer: `_sqli_detect` in normalize.py parses sqlmap's console output for
    "sqlmap identified the following injection point(s)" and emits a proof-confirmed
    observation (`detail.confirmed = True`), promoting the finding to CONFIRMED via
    `_PROOF_SOURCE_TOOLS`.
    """
    binary = os.environ.get("VAPT_SQLMAP_BIN", "sqlmap")
    target = _valid_host(str(args["target"]))
    url = str(args.get("url", "")).strip()
    if not url.lower().startswith(("http://", "https://")):
        raise ValueError(f"sqli_detect needs a full http(s) url: {url!r}")
    _reject_option_like(url)
    if urlparse(url).hostname != target:
        raise ValueError(f"sqli_detect url off-scope: {url!r}")

    # Technique set — restricted alphabet. Default BE (boolean + error): fast,
    # in-band, no stacked writes, no time-based delays that would blow the timeout.
    technique = str(args.get("technique", "BE")).strip().upper()
    if not re.fullmatch(r"[BEUST]{1,5}", technique):
        raise ValueError(f"invalid sqli_detect technique: {technique!r}")

    # Level + risk — bounded to [1,3]. Default 1/1 stays conservative on arbitrary
    # endpoints (an unknown route might be UPDATE/DELETE backend where risk >= 3's
    # OR-based payloads could corrupt data). The webvuln orchestrator overrides to
    # level=2 risk=3 ONLY on auth endpoints (login/register), where the backend is
    # a SELECT and OR-based payloads bypass auth without modifying rows.
    try:
        level = int(args.get("level", 1))
    except (TypeError, ValueError) as e:
        raise ValueError(f"invalid sqli_detect level: {args.get('level')!r}") from e
    if not 1 <= level <= 3:
        raise ValueError(f"sqli_detect level must be in [1,3]: {level}")
    try:
        risk = int(args.get("risk", 1))
    except (TypeError, ValueError) as e:
        raise ValueError(f"invalid sqli_detect risk: {args.get('risk')!r}") from e
    if not 1 <= risk <= 3:
        raise ValueError(f"sqli_detect risk must be in [1,3]: {risk}")

    method = str(args.get("method", "")).strip().lower()
    if method and method not in ("get", "post"):
        raise ValueError(f"invalid sqli_detect method: {method!r}")

    # --batch: non-interactive; --flush-session: deterministic fresh session;
    # --level/--risk 1: minimum payload scope; --threads 1: single-threaded (gentle
    # on a dev-server target); --timeout/--retries: bounded; --random-agent: avoid
    # trivial sqlmap UA blocking; --disable-coloring: no ANSI in captured stdout;
    # --output-dir /tmp/vapt-sqlmap: isolated workspace (sqlmap INSISTS on one and
    # creates ~/.local/share/sqlmap by default — we don't want that in the worker's
    # home dir).
    import tempfile as _tempfile
    out_dir = _tempfile.mkdtemp(prefix="vapt-sqlmap-")
    argv = [
        binary, "-u", url,
        "--batch", "--flush-session",
        "--technique", technique,
        "--level", str(level), "--risk", str(risk),
        "--threads", "1",
        "--timeout", "10", "--retries", "1",
        "--random-agent",
        "--disable-coloring",
        "--output-dir", out_dir,
    ]

    # Pinned parameter — speeds detection by 10x+ when the vector is already known.
    param = str(args.get("param", "")).strip()
    if param:
        _reject_option_like(param)
        if not re.fullmatch(r"[A-Za-z0-9_.\-\[\]]{1,64}", param):
            raise ValueError(f"invalid sqli_detect param: {param!r}")
        argv += ["-p", param]

    data = str(args.get("data", "")).strip()
    if data:
        _reject_option_like(data)
        if not re.fullmatch(
            r"[A-Za-z0-9_.\-\[\]]+=[^&\s]+(?:&[A-Za-z0-9_.\-\[\]]+=[^&\s]+)*", data
        ):
            raise ValueError(f"invalid sqli_detect data: {data!r}")
        argv += ["--data", data]

    if method == "post" and not data:
        raise ValueError("sqli_detect method=post requires `data`")

    _c = _web_login_cookie()
    if _c:
        argv += ["--cookie", _c]

    # Belt-and-braces: assert no forbidden flag crept in. A failing assert here is a
    # bug in this function, caught at tool-build time rather than at runtime.
    for forbidden in _SQLI_DETECT_FORBIDDEN:
        assert forbidden not in argv, f"sqli_detect must never emit {forbidden}"
    return argv


def _build_sstimap(args: dict) -> list[str]:
    """sstimap SSTI detection against a specific in-scope URL — DETECTION ONLY: no --os-cmd,
    no --os-shell, no --eval, no --upload (deliberately NOT exposed). Confirms a template-
    injection candidate (e.g. wapiti's "Reflected XSS" on /admin/announcement is really a
    Jinja/Twig/ERB rendering vector; sstimap proves that by executing a math-expression
    payload and matching the rendered result). P2 intrusive → still human-gated.

    args:
      target  — in-scope host (scope check).
      url     — full http(s) URL for the vulnerable endpoint. Query params are tested; a POST
                body can be supplied via `data` ("name=value&...").
      data    — optional POST body (passed to sstimap -d). Validated as `k=v[&k=v...]`.
    """
    binary = os.environ.get("VAPT_SSTIMAP_BIN", "sstimap")
    target = _valid_host(str(args["target"]))
    url = str(args.get("url", "")).strip()
    if not url.lower().startswith(("http://", "https://")):
        raise ValueError(f"sstimap needs a full http(s) url: {url!r}")
    _reject_option_like(url)
    if urlparse(url).hostname != target:
        raise ValueError(f"sstimap url off-scope: {url!r}")
    # Group C — multi-param SSTI sweep. --level=1 only tests the ONE param the
    # payload lands on; --level=2 iterates every form/query parameter in turn.
    # DineHub /admin/announcement had the SSTI in `content`, not the first
    # discovered field `name` — level 1 missed it entirely. Level 2 is cheap
    # for a sstimap-detect pass (bounded candidate list + math-expression
    # payload per param) and the common case where the vuln field is just
    # NOT the first one justifies raising the default.
    _lvl = str(args.get("level", "2")).strip()
    if not re.fullmatch(r"[1-5]", _lvl):
        _lvl = "2"
    argv = [binary, "-u", url, "--level", _lvl]
    # Optional engine hint — restricts sstimap to one plugin so it finishes fast on a slow
    # dev server. Validated against sstimap's own plugin names (lowercase ASCII, max 32 ch);
    # the caller only supplies this when `phases.infer_template_engine` returned a mapping
    # from CAPTURED tech data (no hardcoding — nothing to pass means full-engine probe).
    engine = str(args.get("engine", "")).strip()
    if engine:
        _reject_option_like(engine)
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,31}", engine):
            raise ValueError(f"sstimap engine must be an identifier: {engine!r}")
        argv += ["-e", engine]
    data = str(args.get("data", "")).strip()
    if data:
        _reject_option_like(data)
        if not re.fullmatch(r"[A-Za-z0-9_.\-\[\]]+=[^&\s]+(?:&[A-Za-z0-9_.\-\[\]]+=[^&\s]+)*", data):
            raise ValueError(f"sstimap data must be k=v[&k=v...]: {data!r}")
        argv += ["-d", data]
    # Authenticated detection via the webvuln session cookie (same mechanism as the other
    # web tools). sstimap uses `-C name=value` (single value, not a cookie file).
    _c = _web_login_cookie()
    if _c:
        argv += ["-C", _c]
    return argv


def _build_zap_baseline(args: dict) -> list[str]:
    # Passive baseline scan only. The active scan is a separate P2 spec.
    # Overridable: a ZAP install (or a docker wrapper) exposing zap-baseline.py.
    binary = os.environ.get("VAPT_ZAP_BASELINE_BIN", "zap-baseline.py")
    target = _valid_host(str(args["target"]))
    return [binary, "-t", f"https://{target}", "-I"]


def _build_testssl(args: dict) -> list[str]:
    binary = os.environ.get("VAPT_TESTSSL_BIN", "testssl.sh")
    target = _valid_host(str(args["target"]))
    return [binary, "--quiet", "--color", "0", f"https://{target}"]


def _valid_source_path(value: str) -> str:
    """Validate a path that the PLATFORM supplies to a local analyzer (the extracted
    bundle dir). Not a model-supplied value — the planner never produces source paths —
    so this guards against option injection and null bytes, and permits an absolute path
    (the extraction root is absolute). Execution is argv-only (shell=False)."""
    _reject_option_like(value)
    if not value or "\x00" in value:
        raise ValueError("invalid source path")
    return value


def _build_semgrep(args: dict) -> list[str]:
    # Static analysis of local source. Reads files only; no network target impact (P0).
    path = _valid_source_path(str(args["path"]))
    config = str(args.get("config", "auto"))
    _reject_option_like(config)
    return ["semgrep", "--json", "--quiet", "--disable-version-check", "--config", config, path]


def _build_gitleaks(args: dict) -> list[str]:
    # Secret scanning of local source. JSON to stdout so the broker captures it.
    path = _valid_source_path(str(args["path"]))
    return [
        "gitleaks", "detect", "--no-git", "--report-format", "json",
        "--report-path", "/dev/stdout", "--exit-code", "0", "--source", path,
    ]


def _build_dep_audit(args: dict) -> list[str]:
    # Dependency/advisory audit via a platform shim that emits normalized JSON.
    path = _valid_source_path(str(args["path"]))
    return ["vapt-dep-audit", path]


_CVE_ARG_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def _build_searchsploit(args: dict) -> list[str]:
    # P0 offline Exploit-DB search (local DB, never touches the host -> target_kind=local).
    # JSON output for stable parsing. Accepts a CVE id (--cve) or a bounded keyword query.
    binary = os.environ.get("VAPT_SEARCHSPLOIT_BIN", "searchsploit")
    cve = str(args.get("cve", "")).strip()
    if cve:
        if not _CVE_ARG_RE.fullmatch(cve):
            raise ValueError(f"invalid cve: {cve!r}")
        return [binary, "--cve", cve.upper(), "-j"]
    query = str(args.get("query", "")).strip()
    _reject_option_like(query)
    if not re.fullmatch(r"[A-Za-z0-9 ._/+-]{1,100}", query):
        raise ValueError("invalid searchsploit query")
    return [binary, "-j", query]


def _build_nuclei_cve(args: dict) -> list[str]:
    # P1 targeted template check: does the CVE's nuclei template actually fire on the host?
    binary = os.environ.get("VAPT_NUCLEI_BIN", "nuclei")
    target = _valid_host(str(args["target"]))
    cve = str(args.get("cve", "")).strip()
    if not _CVE_ARG_RE.fullmatch(cve):
        raise ValueError(f"invalid cve: {cve!r}")
    scheme = "http" if str(args.get("scheme", "")).lower() == "http" else "https"
    url = f"{scheme}://{target}"
    port = args.get("port")
    if port is not None and str(port) != "":
        p = str(port)
        if not re.fullmatch(r"\d{1,5}", p) or not 0 < int(p) < 65536:
            raise ValueError(f"invalid port: {port!r}")
        url = f"{scheme}://{target}:{p}"
    return [binary, "-u", url, "-id", cve.lower(), "-silent", "-jsonl"]


def _build_nessus_import(args: dict) -> list[str]:
    # P0: parse an already-exported .nessus file from the run workspace. No scanning.
    binary = os.environ.get("VAPT_NESSUS_BIN", "vapt-nessus-import")
    path = str(args["path"])
    _reject_option_like(path)
    if ".." in path or path.startswith("/"):
        raise ValueError("nessus import path must be a relative workspace path")
    return [binary, path]


def _build_tenable(args: dict) -> list[str]:
    # P0 passive: READ-ONLY Tenable.sc intel for one in-scope host (no scanning). The
    # Tenable.sc URL + API keys come from the environment inside the shim, never argv.
    binary = os.environ.get("VAPT_TENABLE_BIN", "vapt-tenable")
    target = _valid_host(str(args["target"]))
    return [binary, "--ip", target]


_WEB_PROBE_CLASSES_RE = re.compile(
    r"[a-z_]+(?:,[a-z_]+)*", re.ASCII,
)

# Default binary location for the shipped `vapt-web-probe` script. The broker's
# `tool_available()` check calls `shutil.which(argv[0])`, so an unqualified "vapt-web-probe"
# fails whenever `workers/bin/` isn't on PATH — which it usually isn't. Resolving to the
# absolute path on disk (co-located with the registry source) means the probe runs out of
# the box; VAPT_WEB_PROBE_BIN still overrides for operators who ship it elsewhere.
_SHIPPED_WEB_PROBE_BIN = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))),
    "workers", "bin", "vapt-web-probe",
)
_SHIPPED_IDOR_PROBE_BIN = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))),
    "workers", "bin", "vapt-idor-probe",
)
_SHIPPED_STORED_XSS_PROBE_BIN = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))),
    "workers", "bin", "vapt-stored-xss-probe",
)
_SHIPPED_CSP_CHECK_BIN = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))),
    "workers", "bin", "vapt-csp-check",
)
_SHIPPED_YAML_DESER_PROBE_BIN = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))),
    "workers", "bin", "vapt-yaml-deser-probe",
)
_SHIPPED_DOM_XSS_PROBE_BIN = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))),
    "workers", "bin", "vapt-dom-xss-probe",
)
_SHIPPED_RECON_FETCH_BIN = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))),
    "workers", "bin", "vapt-recon-fetch",
)


def _build_csp_check(args: dict) -> list[str]:
    """Argv for the CSP posture evaluator. GET one in-scope URL, parse the
    Content-Security-Policy + Report-Only headers, apply weakness rules
    (unsafe-inline, unsafe-eval, wildcards, missing strict-dynamic / Trusted
    Types / frame-ancestors / object-src 'none'). argv-only.

    args:
      target — in-scope host (REQUIRED, scope-checked).
      url    — full http(s) URL to fetch (REQUIRED, must match target host).
    """
    binary = os.environ.get("VAPT_CSP_CHECK_BIN", _SHIPPED_CSP_CHECK_BIN)
    target = _valid_host(str(args["target"]))
    url = str(args.get("url", "")).strip()
    # When the caller supplied only `target` (e.g. the top-level planner picked this
    # tool from the SCAN catalog but didn't know which URL to probe), fall back to
    # the base URL on port 80 — same convention `nuclei_safe` and `wafw00f` use.
    # The webvuln dispatcher overrides this with the specific port/scheme URL for
    # each discovered web base, so the full /per-base/ pass still happens later.
    if not url:
        scheme = "http" if str(args.get("scheme", "")).lower() != "https" else "https"
        port = str(args.get("port", "")).strip()
        if port and not re.fullmatch(r"\d{1,5}", port):
            raise ValueError(f"invalid port: {port!r}")
        url = f"{scheme}://{target}" + (f":{port}" if port else "") + "/"
    if not url.lower().startswith(("http://", "https://")):
        raise ValueError(f"csp_check needs full http(s) url: {url!r}")
    _reject_option_like(url)
    if urlparse(url).hostname != target:
        raise ValueError(f"csp_check url off-scope: {url!r}")
    return [binary, "--target", target, "--url", url]


def _build_stored_xss_probe(args: dict) -> list[str]:
    """Argv for the deterministic stored-XSS probe. POSTs a unique canary payload
    to the submit endpoint, GETs the view URL, confirms persistence by matching
    the canary in the view body. Dalfox's blind spot (POST-only inspection) is
    exactly this flow — stored XSS lives on review/comment/profile endpoints that
    render the stored content on a DIFFERENT page.

    args:
      target    — in-scope host (REQUIRED, scope-checked).
      post_url  — full http(s) URL that stores the content (REQUIRED).
      view_url  — full http(s) URL that renders stored content (REQUIRED).
      param     — form parameter name that carries user text (REQUIRED).
      data      — optional extra k=v[&k=v] body fields (CSRF tokens, hidden ids).

    Session cookie is injected via the subprocess env (`VAPT_WEB_LOGIN_COOKIE`),
    same as every other authenticated-web tool; the shim reads it from env +
    Redis per the standard pattern. argv is argv-only, shell=False.
    """
    binary = os.environ.get("VAPT_STORED_XSS_PROBE_BIN", _SHIPPED_STORED_XSS_PROBE_BIN)
    target = _valid_host(str(args["target"]))

    post_url = str(args.get("post_url", "")).strip()
    if not post_url.lower().startswith(("http://", "https://")):
        raise ValueError(f"stored_xss_probe needs full http(s) post_url: {post_url!r}")
    _reject_option_like(post_url)
    if urlparse(post_url).hostname != target:
        raise ValueError(f"stored_xss_probe post_url off-scope: {post_url!r}")

    view_url = str(args.get("view_url", "")).strip()
    if not view_url.lower().startswith(("http://", "https://")):
        raise ValueError(f"stored_xss_probe needs full http(s) view_url: {view_url!r}")
    _reject_option_like(view_url)
    if urlparse(view_url).hostname != target:
        raise ValueError(f"stored_xss_probe view_url off-scope: {view_url!r}")

    param = str(args.get("param", "")).strip()
    if not param:
        raise ValueError("stored_xss_probe needs `param` (the form field name)")
    _reject_option_like(param)
    if not re.fullmatch(r"[A-Za-z0-9_.\-\[\]]{1,64}", param):
        raise ValueError(f"invalid stored_xss_probe param: {param!r}")

    argv = [binary, "--target", target,
            "--post-url", post_url, "--view-url", view_url,
            "--param", param]

    data = str(args.get("data", "")).strip()
    if data:
        _reject_option_like(data)
        if not re.fullmatch(
            r"[A-Za-z0-9_.\-\[\]]+=[^&\s]+(?:&[A-Za-z0-9_.\-\[\]]+=[^&\s]+)*", data
        ):
            raise ValueError(f"invalid stored_xss_probe data: {data!r}")
        argv += ["--data", data]
    return argv


def _build_yaml_deser_probe(args: dict) -> list[str]:
    """Argv for the deterministic YAML-deserialization probe.

    POSTs a yaml.load-targeted payload (``!!python/object/apply:time.sleep [5]``)
    to an endpoint that accepts YAML. If the response delays by ~5s TWICE,
    the loader deserialized the tag — confirmed unsafe yaml.load usage, which
    is a textbook RCE primitive on PyYAML-backed apps.

    args:
      target — in-scope host (REQUIRED, scope-checked).
      url    — full http(s) URL that accepts YAML (REQUIRED).
      field  — optional form-field name (default: "yaml") for form-encoded
               submissions; ignored when the server accepts raw YAML body.

    Payload uses time.sleep + os.getcwd ONLY (read-only, side-effect-free).
    NEVER emits os.system, subprocess.*, file-write tags, or shell meta —
    the probe is bounded to confirming deserialization, never exploitation.
    """
    binary = os.environ.get("VAPT_YAML_DESER_PROBE_BIN", _SHIPPED_YAML_DESER_PROBE_BIN)
    target = _valid_host(str(args["target"]))
    url = str(args.get("url", "")).strip()
    if not url.lower().startswith(("http://", "https://")):
        raise ValueError(f"yaml_deser_probe needs full http(s) url: {url!r}")
    _reject_option_like(url)
    if urlparse(url).hostname != target:
        raise ValueError(f"yaml_deser_probe url off-scope: {url!r}")
    argv = [binary, "--target", target, "--url", url]
    field = str(args.get("field", "")).strip()
    if field:
        _reject_option_like(field)
        if not re.fullmatch(r"[A-Za-z0-9_.\-\[\]]{1,64}", field):
            raise ValueError(f"invalid yaml_deser_probe field: {field!r}")
        argv += ["--field", field]
    return argv


def _build_recon_fetch(args: dict) -> list[str]:
    """Authenticated recon fetch — a single LLM-callable primitive for the Stage-3
    recon loop. GET or POST one in-scope URL with the admin session cookie, return
    structured JSON (status, content_type, allow, body(8KB), parsed forms, hrefs).
    Lets the LLM explore the authenticated surface the way an operator would —
    pull a page, read the form fields, decide the next probe — without parsing
    HTML itself.

    args:
      target  — in-scope host (REQUIRED, scope-checked).
      url     — full http(s) URL on the target (REQUIRED).
      method  — "get" (default) or "post".
      data    — optional POST body ("k=v[&k=v...]") — same validator as http_fetch.

    Argv-only, shell=False. Session cookie injected automatically via env
    (VAPT_WEB_LOGIN_COOKIE) or the per-run Redis slot.
    """
    binary = os.environ.get("VAPT_RECON_FETCH_BIN", _SHIPPED_RECON_FETCH_BIN)
    target = _valid_host(str(args["target"]))
    url = str(args.get("url", "")).strip()
    if not url.lower().startswith(("http://", "https://")):
        raise ValueError(f"vapt-recon-fetch needs full http(s) url: {url!r}")
    _reject_option_like(url)
    if urlparse(url).hostname != target:
        raise ValueError(f"vapt-recon-fetch url off-scope: {url!r}")
    method = str(args.get("method", "get")).strip().lower()
    if method not in ("get", "post"):
        raise ValueError(f"invalid recon-fetch method: {method!r}")
    argv = [binary, "--target", target, "--url", url, "--method", method]
    data = str(args.get("data", "")).strip()
    if data:
        _reject_option_like(data)
        if not re.fullmatch(
            r"[A-Za-z0-9_.\-\[\]]+=[^&\s]+(?:&[A-Za-z0-9_.\-\[\]]+=[^&\s]+)*",
            data,
        ):
            raise ValueError(f"invalid recon-fetch data: {data!r}")
        argv += ["--data", data]
    return argv


def _build_dom_xss_probe(args: dict) -> list[str]:
    """Argv for the deterministic DOM-XSS probe (static JS taint analysis).

    Detects DOM-based XSS where a client-controlled source (location.hash/search,
    document.URL/referrer/cookie, window.name, …) flows into a dangerous sink
    (innerHTML, document.write, eval, …) in page JavaScript. Catches fragment
    (`#…`) sinks that NEVER reach the server and that dalfox's param-mining
    misses. Read-only: fetches pages + same-origin scripts, never sends payloads.

    args:
      target — in-scope host (REQUIRED, scope-checked).
      urls   — comma-separated in-scope page URLs to analyse (REQUIRED).
    """
    binary = os.environ.get("VAPT_DOM_XSS_PROBE_BIN", _SHIPPED_DOM_XSS_PROBE_BIN)
    target = _valid_host(str(args["target"]))
    urls_raw = str(args.get("urls", "")).strip()
    if not urls_raw:
        raise ValueError("dom_xss_probe needs comma-separated urls")
    _reject_option_like(urls_raw)
    kept: list[str] = []
    for u in urls_raw.split(","):
        u = u.strip()
        if not u.lower().startswith(("http://", "https://")):
            continue
        if urlparse(u).hostname != target:
            continue
        if u not in kept:
            kept.append(u)
        if len(kept) >= 30:
            break
    if not kept:
        raise ValueError("dom_xss_probe: no in-scope urls to analyse")
    return [binary, "--target", target, "--urls", ",".join(kept)]


def _build_idor_probe(args: dict) -> list[str]:
    """Argv for the deterministic IDOR (Insecure Direct Object Reference) probe.

    Needs TWO authenticated sessions (operator supplies two credential sets at run
    creation on an auto-approve run). The probe loads both cookies from Redis under
    `vapt:webcookie:<run_id>:A` and `:B`, requests each discovered URL as both users,
    and flags cross-tenant access (user B accessing user A's `/order/42`).

    args:
      target — in-scope host (REQUIRED).
      urls   — comma-separated list of in-scope http(s) URLs with numeric IDs (REQUIRED).

    The probe's internal filter keeps only URLs matching `/\\d{1,10}` AND the target host;
    off-scope / non-ID URLs are discarded, so an over-eager caller can't DoS the target.
    """
    binary = os.environ.get("VAPT_IDOR_PROBE_BIN", _SHIPPED_IDOR_PROBE_BIN)
    target = _valid_host(str(args["target"]))
    urls_raw = str(args.get("urls", "")).strip()
    if not urls_raw:
        raise ValueError("idor_probe needs comma-separated urls")
    _reject_option_like(urls_raw)
    # The v3 probe accepts THREE kinds of in-scope URL and does its own filtering:
    #   - object URLs with an id/token (numeric /order/42, hex /order?id=<32hex>, uuid)
    #   - listing pages (/orders, /account, /invoices …) it harvests for ownership
    #   - numeric URLs for the enumeration fallback
    # Token = long hex (>=16) OR uuid OR 1-10 digits. We keep a validation gate so
    # a bad LLM proposal can't feed arbitrary off-pattern URLs, but it is broad.
    _tok = (r"(?:[0-9a-f]{16,}"
            r"|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
            r"|\d{1,10})")
    _obj_re = re.compile(
        r"/(?:order|orders|invoice|invoices|receipt|receipts|booking|bookings|"
        r"ticket|tickets|reservation|reservations|payment|payments|transaction|"
        r"transactions|document|documents|report|reports|message|messages)"
        r"(?:/track)?/" + _tok + r"(?:[/?]|$)"
        r"|[?&](?:id|oid|uid|pid|order|order_id|orderid|invoice|invoice_id"
        r"|receipt|receipt_id|booking|booking_id|ticket|ticket_id|user|user_id"
        r"|userid|account|account_id|item|item_id|object|object_id|ref|num"
        r"|token|uuid|guid)=" + _tok + r"(?:&|$)"
        r"|/\d{1,10}(?:/|\?|$)",   # bare numeric path id (e.g. /user/7/pw) — legacy
        re.IGNORECASE,
    )
    _listing_re = re.compile(
        r"/(?:orders|order/history|account/orders|my-orders|invoices|receipts|"
        r"bookings|tickets|reservations|account|dashboard|history|transactions)/?$",
        re.IGNORECASE,
    )
    kept: list[str] = []
    for u in urls_raw.split(","):
        u = u.strip()
        if not u.lower().startswith(("http://", "https://")):
            continue
        p = urlparse(u)
        if p.hostname != target:
            continue
        if not (_obj_re.search(u) or _listing_re.search(p.path or "")):
            continue
        if u not in kept:
            kept.append(u)
        if len(kept) >= 40:  # per-invocation cap
            break
    if not kept:
        raise ValueError("idor_probe: no in-scope object/listing urls to probe")
    return [binary, "--target", target, "--urls", ",".join(kept)]


def _build_web_param_probe(args: dict) -> list[str]:
    """Argv for the deterministic web probe. The script is shipped at `workers/bin/
    vapt-web-probe` and the binary is env-overridable like every other tool.

    args:
      target  — in-scope host (scope check); REQUIRED.
      url     — full http(s) URL on the target (REQUIRED).
      param   — optional pinned param name (A-Za-z0-9 _.-[]), for a signal from arjun/wapiti.
      classes — optional comma-separated subset (default = all).
    """
    binary = os.environ.get("VAPT_WEB_PROBE_BIN", _SHIPPED_WEB_PROBE_BIN)
    target = _valid_host(str(args["target"]))
    url = str(args.get("url", "")).strip()
    if not url.lower().startswith(("http://", "https://")):
        raise ValueError(f"web_param_probe needs a full http(s) url: {url!r}")
    _reject_option_like(url)
    if urlparse(url).hostname != target:
        raise ValueError(f"web_param_probe url off-scope: {url!r}")
    argv = [binary, "--target", target, "--url", url]
    param = str(args.get("param", "")).strip()
    if param:
        _reject_option_like(param)
        if not re.fullmatch(r"[A-Za-z0-9_.\-\[\]]{1,64}", param):
            raise ValueError(f"invalid param name: {param!r}")
        argv += ["--param", param]
    classes = str(args.get("classes", "")).strip()
    if classes:
        _reject_option_like(classes)
        if not _WEB_PROBE_CLASSES_RE.fullmatch(classes):
            raise ValueError(f"invalid classes list: {classes!r}")
        argv += ["--classes", classes]
    # HTTP method for parameterised probes (ssti, sqli, xss). POST sends params in the
    # body (urlencoded by default; application/json when `content_type` is set) so
    # register/feedback/comment-style sinks that only accept POST get real coverage.
    method = str(args.get("method", "")).strip().lower()
    if method:
        if method not in ("get", "post"):
            raise ValueError(f"invalid method: {method!r}")
        argv += ["--method", method]
    content_type = str(args.get("content_type", "")).strip().lower()
    if content_type:
        if content_type not in ("application/x-www-form-urlencoded", "application/json"):
            raise ValueError(f"invalid content_type: {content_type!r}")
        argv += ["--data-content-type", content_type]
    if args.get("insecure"):
        argv.append("--insecure")
    return argv


def _build_dalfox(args: dict) -> list[str]:
    """dalfox XSS fuzzer against a specific in-scope URL. Detects reflected XSS with filter
    bypasses that wapiti misses AND DOM XSS via a headless browser (dalfox launches Chrome
    for DOM analysis — this is the gap we have today, as our other tools only see the
    server-rendered response). P2 intrusive → human-gated at execution.

    args:
      target  — in-scope host (scope check).
      url     — full http(s) URL for the endpoint to fuzz. Query params/body sinks are
                tested; GET only here (POST would need body data we don't carry forward).
      param   — optional pinned parameter name (uses dalfox `-p`) when the planner has one
                from arjun/wapiti.

    Dalfox output is parsed by _dalfox in normalize.py from its `--format json` emission.
    Scope: argv-only (shell=False), url validated for in-host match, no option-like tokens.
    """
    binary = os.environ.get("VAPT_DALFOX_BIN",
                            os.path.expanduser("~/go/bin/dalfox"))
    target = _valid_host(str(args["target"]))
    url = str(args.get("url", "")).strip()
    if not url.lower().startswith(("http://", "https://")):
        raise ValueError(f"dalfox needs a full http(s) url: {url!r}")
    _reject_option_like(url)
    if urlparse(url).hostname != target:
        raise ValueError(f"dalfox url off-scope: {url!r}")
    argv = [binary, "url", url, "--format", "json", "--no-color",
            # NOTE: `--silence` was removed in v1.1 — in dalfox 2.13.0 it suppresses the
            # per-request progress AND can suppress JSON output on fast exits (verified
            # against the 0.5s unexplained exits observed on DineHub). The banner lines
            # dalfox prints with silence off are tolerable noise; `_first_json` tolerates
            # surrounding text.
            # Keep output focused: PoCs for verified + reflected hits only. Dalfox's "grep"
            # tier is lower-signal noise (regex matches in response bodies) and would
            # overload the normalizer with ambiguous observations.
            "--only-poc", "r,v",
            # Follow redirects — DineHub routes return 302 to /auth/login on a logged-out
            # session; the login-cookie path below makes it unnecessary, but following them
            # also catches reflected sinks in the redirect target.
            "--follow-redirects",
            # Cap request worker count so dalfox can't swamp the throttle-managed target.
            "--worker", "8",
            "--timeout", "15"]
    # Optional pinned param from upstream (arjun/wapiti) — dalfox's `-p` restricts scanning
    # to that parameter, finishing much faster when we already know where to look.
    param = str(args.get("param", "")).strip()
    if param:
        _reject_option_like(param)
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_\-\[\]]{0,63}", param):
            raise ValueError(f"dalfox param must be an identifier: {param!r}")
        argv += ["-p", param]
    # POST body support for stored-XSS sinks (/feedback, /review, /auth/register,
    # /admin/announcement etc.). Without -X POST + -d <body>, dalfox always GETs the
    # URL and misses stored XSS entirely — the planner now emits a POST variant for
    # discovered form endpoints and this builder has to carry it through.
    method = str(args.get("method") or "").strip().lower()
    if method:
        if method not in ("get", "post"):
            raise ValueError(f"invalid dalfox method: {method!r}")
        if method == "post":
            argv += ["-X", "POST"]
    data = str(args.get("data") or "").strip()
    if data:
        if any(ch in data for ch in ("\r", "\n", "\x00")):
            raise ValueError("dalfox data contains control characters")
        _reject_option_like(data)
        if len(data) > 4096:
            raise ValueError("dalfox data too long")
        argv += ["-d", data]
    _c = _web_login_cookie()
    if _c:
        # Dual-track the cookie:
        #   1. -C puts it on the raw HTTP requests dalfox makes directly
        #   2. --cookie-from-raw loads it into the HEADLESS CHROME cookie jar so the
        #      DOM-mining / verified-XSS passes carry the authenticated session too.
        # Without (2), dalfox's Chrome pass on an auth-only route (DineHub admin) hits a
        # 302 → login and finishes in ~2s with "no XSS" — the symptom we saw on prior runs.
        argv += ["-C", _c]
        # Build a minimal raw HTTP request file that dalfox parses to extract cookies.
        # Lives in /tmp with 0600 perms; dalfox reads it synchronously then subprocess
        # exits, so we clean it up after exec in the broker (see _cleanup_dalfox_tempfile).
        import tempfile as _tempfile
        host = urlparse(url).hostname or target
        raw_req = (
            f"GET {urlparse(url).path or '/'} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Cookie: {_c}\r\n"
            f"User-Agent: vapt-dalfox/1.0\r\n\r\n"
        )
        fd, tmp_path = _tempfile.mkstemp(prefix="vapt-dalfox-", suffix=".req")
        try:
            os.write(fd, raw_req.encode())
        finally:
            os.close(fd)
        os.chmod(tmp_path, 0o600)
        argv += ["--cookie-from-raw", tmp_path]
    return argv


def _build_burp_request(args: dict) -> list[str]:
    # P1: issue a single approved request through the Burp proxy (read/request only).
    # Binary overridable so the worker can point at the repo's shim (workers/bin/vapt-burp)
    # or an installed copy.
    binary = os.environ.get("VAPT_BURP_BIN", "vapt-burp")
    target = _valid_host(str(args["target"]))
    scheme = "http" if str(args.get("scheme", "")).lower() == "http" else "https"
    argv = [binary, "request", "--url", f"{scheme}://{target}"]
    port = args.get("port")
    if port is not None and str(port) != "":
        p = str(port)
        if not re.fullmatch(r"\d{1,5}", p) or not 0 < int(p) < 65536:
            raise ValueError(f"invalid port: {port!r}")
        argv = [binary, "request", "--url", f"{scheme}://{target}:{p}"]
    return argv


def _build_poc_screenshot(args: dict) -> list[str]:
    # P2: capture a single screenshot as PoC evidence via a platform shim (BAR-30).
    target = _valid_host(str(args["target"]))
    return ["vapt-poc-screenshot", "--url", f"https://{target}"]


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}

    def register(self, spec: ToolSpec) -> None:
        self._tools[spec.id] = spec

    def get(self, tool_id: str) -> ToolSpec:
        if tool_id not in self._tools:
            raise KeyError(f"unknown tool: {tool_id}")
        return self._tools[tool_id]

    def all(self) -> list[ToolSpec]:
        return list(self._tools.values())


REGISTRY = ToolRegistry()

# First safe adapter (Week 1 exit gate needs exactly one safe tool).
REGISTRY.register(
    ToolSpec(
        id="dns_resolve",
        version="1.0",
        policy_class=PolicyClass.P0_PASSIVE,
        allowed_agents=[AgentRole.RECON],
        supported_modes=["black_box", "gray_box", "white_box"],
        build_argv=_build_dns,
        timeout_s=30,
        description="Passive DNS resolution of an approved domain.",
    )
)
REGISTRY.register(
    ToolSpec(
        id="http_probe",
        version="1.0",
        policy_class=PolicyClass.P1_LOW_IMPACT,
        allowed_agents=[AgentRole.RECON, AgentRole.SCAN, AgentRole.VALIDATE],
        supported_modes=["black_box", "gray_box", "white_box"],
        build_argv=_build_httpx,
        timeout_s=60,
        description="Bounded HTTP probe: status code + title for an approved URL.",
    )
)

# --------------------------------------------------------------------------- #
# Week 3: web & network adapter families. Each maps a profile to a policy class;
# the harness + policy engine gate them. Binaries are invoked argv-only, never a shell.
# --------------------------------------------------------------------------- #
REGISTRY.register(
    ToolSpec(
        id="nmap_service_scan",
        version="1.0",
        policy_class=PolicyClass.P1_LOW_IMPACT,
        allowed_agents=[AgentRole.RECON, AgentRole.SCAN, AgentRole.VALIDATE],
        supported_modes=["black_box", "gray_box", "white_box"],
        build_argv=_build_nmap,
        timeout_s=600,
        description="Bounded TCP connect service discovery (fixed timing, approved ports).",
    )
)
REGISTRY.register(
    ToolSpec(
        id="searchsploit",
        version="1.0",
        policy_class=PolicyClass.P0_PASSIVE,
        allowed_agents=[AgentRole.SCAN, AgentRole.VALIDATE],
        supported_modes=["black_box", "gray_box", "white_box"],
        build_argv=_build_searchsploit,
        timeout_s=60,
        target_kind="local",
        description="Offline Exploit-DB (searchsploit) lookup for a CVE / keyword — "
                    "public-exploit availability, no host contact.",
    )
)
REGISTRY.register(
    ToolSpec(
        id="nuclei_cve",
        version="1.0",
        policy_class=PolicyClass.P1_LOW_IMPACT,
        allowed_agents=[AgentRole.SCAN, AgentRole.VALIDATE],
        supported_modes=["black_box", "gray_box", "white_box"],
        build_argv=_build_nuclei_cve,
        timeout_s=180,
        description="Run the nuclei template for one specific CVE against the host to "
                    "confirm the version-matched CVE actually fires.",
    )
)
REGISTRY.register(
    ToolSpec(
        id="nmap_vuln",
        version="1.0",
        policy_class=PolicyClass.P1_LOW_IMPACT,
        allowed_agents=[AgentRole.SCAN, AgentRole.VALIDATE],
        supported_modes=["black_box", "gray_box", "white_box"],
        build_argv=_build_nmap_vuln,
        timeout_s=900,
        description="Service→CVE matching: nmap -sV + vulners maps detected service "
                    "versions to known CVEs with CVSS scores.",
    )
)
REGISTRY.register(
    ToolSpec(
        id="win_vuln_scan",
        version="1.0",
        policy_class=PolicyClass.P1_LOW_IMPACT,
        allowed_agents=[AgentRole.SCAN, AgentRole.VALIDATE],
        supported_modes=["black_box", "gray_box", "white_box"],
        build_argv=_build_win_vuln,
        timeout_s=300,
        description="Safe Windows vulnerability DETECTION (nmap smb-vuln-ms17-010 / "
                    "EternalBlue) — checks, never exploits or crashes.",
    )
)
REGISTRY.register(
    ToolSpec(
        id="win_vuln_aggressive",
        version="1.0",
        policy_class=PolicyClass.P2_INTRUSIVE,
        allowed_agents=[AgentRole.SCAN, AgentRole.VALIDATE],
        supported_modes=["black_box", "gray_box", "white_box"],
        build_argv=_build_win_vuln_aggressive,
        timeout_s=300,
        description="Aggressive Windows vuln checks that CAN crash the host "
                    "(smb-vuln-ms08-067, rdp-vuln-ms12-020) — intrusive, always human-gated.",
    )
)
REGISTRY.register(
    ToolSpec(
        id="host_scripts",
        version="1.0",
        policy_class=PolicyClass.P1_LOW_IMPACT,
        allowed_agents=[AgentRole.RECON, AgentRole.SCAN, AgentRole.VALIDATE],
        supported_modes=["black_box", "gray_box", "white_box"],
        build_argv=_build_host_scripts,
        timeout_s=300,
        description="Bounded nmap NSE discovery scripts on Windows service ports "
                    "(SMB signing, SMB OS, RDP info, NetBIOS) — safe category only.",
    )
)
REGISTRY.register(
    ToolSpec(
        id="nuclei_safe",
        version="1.0",
        policy_class=PolicyClass.P1_LOW_IMPACT,
        allowed_agents=[AgentRole.SCAN, AgentRole.VALIDATE],
        supported_modes=["black_box", "gray_box", "white_box"],
        build_argv=_build_nuclei,
        timeout_s=600,
        description="Reviewed non-intrusive Nuclei templates (info/low/medium).",
    )
)
REGISTRY.register(
    ToolSpec(
        id="nuclei_intrusive",
        version="1.0",
        policy_class=PolicyClass.P2_INTRUSIVE,
        allowed_agents=[AgentRole.SCAN, AgentRole.VALIDATE],
        supported_modes=["black_box", "gray_box", "white_box"],
        build_argv=_build_nuclei,
        timeout_s=600,
        description="Intrusive Nuclei templates (high/critical) — requires approval.",
    )
)
REGISTRY.register(
    ToolSpec(
        id="nuclei_dast",
        version="1.0",
        policy_class=PolicyClass.P2_INTRUSIVE,
        allowed_agents=[AgentRole.SCAN, AgentRole.VALIDATE],
        supported_modes=["black_box", "gray_box", "white_box"],
        build_argv=_build_nuclei_dast,
        timeout_s=900,
        description="Nuclei DAST fuzzing of discovered parameters (XSS/LFI/SSRF/redirect/"
                    "SSTI/XXE on query params) — sends payloads, requires approval.",
    )
)
# arjun is also in the catalog, but the catalog template can only ever hit the site ROOT
# (scheme://host[:port], no path) — where there are no parameters to find. We register a
# built-in that accepts an explicit in-scope endpoint `url`, so param discovery can be pointed
# at each DISCOVERED route (/search, /order, …) where the real parameters live.
REGISTRY.register(
    ToolSpec(
        id="arjun",
        version="1.1",
        policy_class=PolicyClass.P1_LOW_IMPACT,
        allowed_agents=[AgentRole.RECON, AgentRole.SCAN],
        supported_modes=["black_box", "gray_box", "white_box"],
        build_argv=_build_arjun,
        timeout_s=90,  # 90s is 6x the manual-run time; a hang past that = wedged target
        description="HTTP hidden-parameter discovery for a specific endpoint URL.",
    )
)
# NOTE: the catalog `sstimap` stays ATTACK-agent-only (that invariant is tested). This
# `ssti_detect` is a SEPARATE, non-destructive DETECTION variant the governed web phase may
# use: it takes an explicit URL + optional POST data and ONLY detects SSTI (no --os-cmd,
# no --os-shell, no --eval). Still P2 → human-gated at execution. Used to CONFIRM a
# wapiti reflected-XSS on /admin/* as an actual SSTI (template rendering, not plain echo).
REGISTRY.register(
    ToolSpec(
        id="csp_check",
        version="1.0",
        # P1 — one bounded GET, no payloads. The TLS-check / security-headers
        # equivalent for CSP specifically. SCAN + VALIDATE agents.
        policy_class=PolicyClass.P1_LOW_IMPACT,
        allowed_agents=[AgentRole.SCAN, AgentRole.VALIDATE],
        supported_modes=["black_box", "gray_box", "white_box"],
        build_argv=_build_csp_check,
        # 15s — the shim is one bounded GET (requests `timeout=10` on both connect
        # and read), header parse, and JSON emit. Real cost is <1s. 15× headroom
        # keeps us immune to transient slowness; dropping from 30→15 halves the
        # worst-case stall if a request DOES hang unexpectedly.
        timeout_s=15,
        description="CSP posture evaluator — fetches a URL, parses Content-Security-Policy, "
                    "flags unsafe-inline/eval, wildcards, missing strict-dynamic, missing "
                    "Trusted Types, missing frame-ancestors, object-src issues.",
    )
)
REGISTRY.register(
    ToolSpec(
        id="stored_xss_probe",
        version="1.0",
        policy_class=PolicyClass.P2_INTRUSIVE,
        allowed_agents=[AgentRole.SCAN, AgentRole.VALIDATE],
        supported_modes=["black_box", "gray_box", "white_box"],
        build_argv=_build_stored_xss_probe,
        # 120s budget: POST (≤10s) + GET (≤10s) + OAST poll (8 × 1s) + process overhead.
        # The OAST poll is the newest cost (blind-XSS detection) — bumped from 60s to
        # give the backend render path time to fire the callback.
        timeout_s=120,
        description="Stored + blind XSS probe — POSTs a dual canary (visible + OAST), "
                    "GETs the view URL, polls interactsh for backend-render callbacks. "
                    "Closes dalfox's blind spot on both the data path and the render path. "
                    "Requires approval.",
    )
)
REGISTRY.register(
    ToolSpec(
        id="recon_fetch",
        version="1.0",
        # P1 — one bounded authenticated GET/POST, no payloads, body truncated
        # to 8 KB in output. The safest primitive we expose to the LLM-driven
        # recon loop: lets the model inspect what's actually on a page (form
        # fields, hrefs, Content-Type, Allow header) before proposing targeted
        # probes, rather than guessing from endpoint URLs alone.
        policy_class=PolicyClass.P1_LOW_IMPACT,
        allowed_agents=[AgentRole.SCAN, AgentRole.VALIDATE],
        supported_modes=["black_box", "gray_box", "white_box"],
        build_argv=_build_recon_fetch,
        timeout_s=20,
        description="Authenticated recon fetch — GET/POST one in-scope URL with the "
                    "admin session cookie, return {status, content_type, allow, body, "
                    "forms, hrefs} as JSON. The LLM uses this to explore the "
                    "authenticated surface and derive targeted probes from real form "
                    "shapes (field names, methods, Content-Types).",
    )
)
REGISTRY.register(
    ToolSpec(
        id="dom_xss_probe",
        version="1.0",
        # P1 — read-only static analysis: fetches pages + same-origin scripts,
        # sends NO payloads. The safest way to confirm fragment/DOM sinks that
        # payload fuzzers and server-side scanners structurally cannot see.
        policy_class=PolicyClass.P1_LOW_IMPACT,
        allowed_agents=[AgentRole.SCAN, AgentRole.VALIDATE],
        supported_modes=["black_box", "gray_box", "white_box"],
        build_argv=_build_dom_xss_probe,
        # 60s: up to 30 pages × (1 page GET + a few same-origin script GETs),
        # each bounded at 10s. Real cost is a few seconds on a small app.
        timeout_s=60,
        description="DOM-XSS probe — static JS taint analysis. Flags a client-"
                    "controlled source (location.hash/search, document.URL/referrer/"
                    "cookie, window.name) flowing into a sink (innerHTML, document.write, "
                    "eval, …). Catches fragment DOM XSS that dalfox and server-side "
                    "scanners miss.",
    )
)
REGISTRY.register(
    ToolSpec(
        id="yaml_deserialization_probe",
        version="1.0",
        # P2 — the probe sends a payload that TRIGGERS deserialization. The
        # trigger is bounded (time.sleep + os.getcwd; never os.system or file
        # ops), but it still runs code on target, so SCAN+VALIDATE only,
        # human-gated by default.
        policy_class=PolicyClass.P2_INTRUSIVE,
        allowed_agents=[AgentRole.SCAN, AgentRole.VALIDATE],
        supported_modes=["black_box", "gray_box", "white_box"],
        build_argv=_build_yaml_deser_probe,
        # 60s budget: 3 baseline (~1s) + 2 sleep (~10s each) + 1 getcwd (~1s)
        # + process overhead. Leaves headroom for a slow target.
        timeout_s=60,
        description="YAML deserialization probe — POSTs a !!python/object/apply:"
                    "time.sleep tag to a yaml-accepting endpoint. If the response "
                    "delays ≥5s twice, the loader is unsafe (yaml.load without "
                    "SafeLoader). Confirms the primitive without exploiting it.",
    )
)
REGISTRY.register(
    ToolSpec(
        id="vapt_http_fetch",
        version="1.0",
        policy_class=PolicyClass.P2_INTRUSIVE,
        allowed_agents=[AgentRole.SCAN, AgentRole.VALIDATE],
        supported_modes=["black_box", "gray_box", "white_box"],
        build_argv=_build_http_fetch,
        timeout_s=30,
        description="Bounded curl fetch for ONE in-scope URL — hardcoded safe flags, "
                    "whitelisted headers, 1MB body cap, 10s wall-clock. Approval required.",
    )
)
REGISTRY.register(
    ToolSpec(
        id="sqli_detect",
        version="1.0",
        policy_class=PolicyClass.P2_INTRUSIVE,
        allowed_agents=[AgentRole.SCAN, AgentRole.VALIDATE],
        supported_modes=["black_box", "gray_box", "white_box"],
        build_argv=_build_sqli_detect,
        # 5 minutes. Bounded by --technique=BE + --level 1 + --risk 1 + --threads 1 +
        # --timeout 10 --retries 1. A fully-pinned param run usually completes in
        # 15-45s; the budget covers the full-param-sweep case (-p absent) on a slow
        # dev server with 5-10 candidate params.
        timeout_s=300,
        description="SQLi detection on a specific URL/param — bounded sqlmap, NEVER "
                    "--os-shell/--dump/--eval. Sends payloads, requires approval.",
    )
)
REGISTRY.register(
    ToolSpec(
        id="ssti_detect",
        version="1.0",
        policy_class=PolicyClass.P2_INTRUSIVE,
        allowed_agents=[AgentRole.SCAN, AgentRole.VALIDATE],
        supported_modes=["black_box", "gray_box", "white_box"],
        build_argv=_build_sstimap,
        timeout_s=600,  # worst case: POST + full engine probe (25+ plugins). With an engine hint from httpx tech-detect this finishes in ~30s; the big budget only costs time on truly-blind runs
        description="SSTI detection against a specific URL/param — non-destructive, no "
                    "command execution. Sends payloads, requires approval.",
    )
)
# wapiti is also listed in the catalog (keeps it in the SCAN/VALIDATE agent manifests), but we
# register a built-in here so webvuln can seed unlinked endpoints + tune the crawl; catalog
# `_load()` skips any id already built-in, so this spec is the one that's used.
REGISTRY.register(
    ToolSpec(
        id="wapiti",
        version="1.0",
        policy_class=PolicyClass.P2_INTRUSIVE,
        allowed_agents=[AgentRole.SCAN, AgentRole.VALIDATE],
        supported_modes=["black_box", "gray_box", "white_box"],
        build_argv=_build_wapiti,
        # 7-minute subprocess kill-switch. Wapiti's own --max-scan-time (240s) and
        # --max-attack-time (60s/module) should make it self-exit well before this,
        # but if a wapiti bug or stuck socket pins the process, this cap keeps the
        # webvuln phase moving. 420 = enough headroom for the 240s self-cap + 180s
        # of post-attack report serialization that wapiti occasionally does.
        timeout_s=420,
        description="Active web vulnerability scanner — sends payloads (gated). Seeds discovered/"
                    "provided endpoints so unlinked routes are tested too.",
    )
)
REGISTRY.register(
    ToolSpec(
        id="zap_baseline",
        version="1.0",
        policy_class=PolicyClass.P1_LOW_IMPACT,
        allowed_agents=[AgentRole.SCAN, AgentRole.VALIDATE],
        supported_modes=["black_box", "gray_box", "white_box"],
        build_argv=_build_zap_baseline,
        timeout_s=600,
        ok_exit_codes=(0, 1, 2),  # zap-baseline: 1=FAIL present, 2=WARN present (not errors)
        description="OWASP ZAP passive baseline scan (no active attacks).",
    )
)
REGISTRY.register(
    ToolSpec(
        id="tls_check",
        version="1.0",
        policy_class=PolicyClass.P1_LOW_IMPACT,
        allowed_agents=[AgentRole.SCAN, AgentRole.VALIDATE],
        supported_modes=["black_box", "gray_box", "white_box"],
        build_argv=_build_testssl,
        timeout_s=300,
        description="TLS configuration check (testssl.sh) on an approved host.",
    )
)
REGISTRY.register(
    ToolSpec(
        id="nessus_import",
        version="1.0",
        policy_class=PolicyClass.P0_PASSIVE,
        allowed_agents=[AgentRole.SCAN, AgentRole.VALIDATE],
        supported_modes=["black_box", "gray_box", "white_box"],
        build_argv=_build_nessus_import,
        timeout_s=120,
        target_kind="local",
        description="Parse an exported .nessus file from the run workspace (no scanning).",
    )
)
REGISTRY.register(
    ToolSpec(
        id="tenable_scan",
        version="1.0",
        policy_class=PolicyClass.P0_PASSIVE,     # read-only consumption of authorized data
        allowed_agents=[AgentRole.SCAN, AgentRole.VALIDATE],
        supported_modes=["black_box", "gray_box", "white_box"],
        build_argv=_build_tenable,
        timeout_s=150,
        target_kind="network",                   # queried per in-scope host (scope-checked)
        description="Read-only Tenable.sc intel for an in-scope host (no scanning).",
    )
)

# --------------------------------------------------------------------------- #
# Week 4: white-box source static analysis. All operate on the engagement's own
# uploaded source bundle (target_kind="local"); argv-only, no shell. Android/APK
# static analysis is excluded from V2.
# --------------------------------------------------------------------------- #
REGISTRY.register(
    ToolSpec(
        id="semgrep_scan",
        version="1.0",
        policy_class=PolicyClass.P0_PASSIVE,
        allowed_agents=[AgentRole.SCAN, AgentRole.VALIDATE],
        supported_modes=["white_box", "gray_box"],
        build_argv=_build_semgrep,
        timeout_s=900,
        target_kind="local",
        description="Semgrep static analysis of the uploaded source (local read only).",
    )
)
REGISTRY.register(
    ToolSpec(
        id="gitleaks_scan",
        version="1.0",
        policy_class=PolicyClass.P0_PASSIVE,
        allowed_agents=[AgentRole.SCAN, AgentRole.VALIDATE],
        supported_modes=["white_box", "gray_box"],
        build_argv=_build_gitleaks,
        timeout_s=600,
        target_kind="local",
        description="Gitleaks secret scanning of the uploaded source (local read only).",
    )
)
REGISTRY.register(
    ToolSpec(
        id="dep_audit",
        version="1.0",
        policy_class=PolicyClass.P1_LOW_IMPACT,
        allowed_agents=[AgentRole.SCAN, AgentRole.VALIDATE],
        supported_modes=["white_box", "gray_box"],
        build_argv=_build_dep_audit,
        timeout_s=600,
        target_kind="local",
        description="Dependency/advisory audit of the uploaded source (may fetch advisories).",
    )
)
# Deterministic web-parameter probe (open redirect / path traversal / localhost SSRF /
# sensitive-content exposure / XXE on XML intake endpoints). Non-destructive — only sends
# GET + one targeted POST — but it DOES send payloads, so P2 intrusive and human-gated.
# Ships as `workers/bin/vapt-web-probe`; the normalizer parses its JSON findings into
# proof-confirmed observations (via `_PROOF_SOURCE_TOOLS`) when a signature actually matches.
REGISTRY.register(
    ToolSpec(
        id="web_param_probe",
        version="1.0",
        policy_class=PolicyClass.P2_INTRUSIVE,
        allowed_agents=[AgentRole.SCAN, AgentRole.VALIDATE],
        supported_modes=["black_box", "gray_box", "white_box"],
        build_argv=_build_web_param_probe,
        timeout_s=90,
        description="Deterministic web-param probe (open redirect / LFI / SSRF-local / "
                    "sensitive-content / XXE) on a specific URL — sends payloads, requires approval.",
    )
)
# idor_probe: deterministic Insecure Direct Object Reference check. Needs TWO
# authenticated sessions (operator supplies two credential sets at run creation).
# Rewrites numeric IDs across accounts and compares responses — a 200 with different
# body on user B for user A's object is authz leak. Normalizer parses JSON output
# into proof-confirmed observations when `confirmed=True`.
REGISTRY.register(
    ToolSpec(
        id="idor_probe",
        version="1.0",
        policy_class=PolicyClass.P2_INTRUSIVE,
        allowed_agents=[AgentRole.SCAN, AgentRole.VALIDATE],
        supported_modes=["black_box", "gray_box", "white_box"],
        build_argv=_build_idor_probe,
        timeout_s=240,
        description="Deterministic IDOR probe — two accounts, numeric-ID path rewriting, "
                    "cross-tenant diff detection. Requires approval.",
    )
)
# dalfox: XSS fuzzer (reflected + DOM via headless Chrome). Covers the DOM-XSS gap our
# other tools can't see — their observations are server-side-rendered HTML, so a sink in
# `document.innerHTML = location.hash.slice(1)` only surfaces here. The normalizer parses
# dalfox's `--format json` output and promotes a Verified (`V`) hit as a proof-confirmed
# finding (same mechanism as sstimap).
REGISTRY.register(
    ToolSpec(
        id="dalfox",
        version="1.0",
        policy_class=PolicyClass.P2_INTRUSIVE,
        allowed_agents=[AgentRole.SCAN, AgentRole.VALIDATE],
        supported_modes=["black_box", "gray_box", "white_box"],
        build_argv=_build_dalfox,
        timeout_s=600,
        description="XSS fuzzer (reflected + DOM via headless Chrome) against a specific "
                    "URL — sends payloads, requires approval.",
    )
)
REGISTRY.register(
    ToolSpec(
        id="burp_request",
        version="1.0",
        policy_class=PolicyClass.P1_LOW_IMPACT,
        # ATTACK only: a PoC request that must always pass the human gate. Allowing the
        # scan/validate agents would let it run auto-approved (signed P1) and ungated.
        allowed_agents=[AgentRole.ATTACK],
        supported_modes=["black_box", "gray_box", "white_box"],
        build_argv=_build_burp_request,
        timeout_s=120,
        description="Issue one approved request via the Burp proxy (read/request only, "
                    "ATTACK agent, always human-gated).",
    )
)
REGISTRY.register(
    ToolSpec(
        id="poc_screenshot",
        version="1.0",
        policy_class=PolicyClass.P2_INTRUSIVE,
        allowed_agents=[AgentRole.ATTACK],
        supported_modes=["black_box", "gray_box", "white_box"],
        build_argv=_build_poc_screenshot,
        timeout_s=120,
        description="Capture one screenshot of a confirmed issue as PoC evidence (approved only).",
    )
)
