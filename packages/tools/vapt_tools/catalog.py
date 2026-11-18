"""Declarative pentest-tool catalog — expands the governed tool set across all five phases.

Each row becomes a governed `ToolSpec`: an env-overridable binary, a token-based argv
template, a policy class, the agents allowed to use it, and a target kind. Governance is the
safety-critical part and is encoded here, not left to the model:

  * passive OSINT / recon ............. P0  (auto)
  * active recon / scan / vuln ........ P1  (auto only under a signed profile, else approval)
  * payload-sending / brute / spray ... P2  (ALWAYS human-approved)
  * exploitation & post-exploitation .. P2, ATTACK agent only (always human-gated)
  * MITM poisoning / relay / C2 ....... P3  (registered but policy-DENIED — catalogued, never
                                            auto-runs; enabling it is a deliberate later change)

A tool whose binary isn't installed simply no-ops: the broker records an honest coverage gap
instead of a result, so loading the whole catalog is safe. Catalog tools use the generic
observation normalizer (one info finding with an output excerpt) unless a bespoke parser is
added later. Binary override: `VAPT_<ID>_BIN` (id upper-cased, '-'→'_').

This is DATA: add a tool by adding a row. Nothing here authorizes an action; the policy
engine + harness + human approval still gate every call exactly as for the built-in tools.
"""
from __future__ import annotations

import os
import shutil
import subprocess

from vapt_domain.enums import AgentRole, PolicyClass

from .registry import REGISTRY, ToolSpec, _domain_credentials, _valid_host

_P0, _P1, _P2, _P3 = (PolicyClass.P0_PASSIVE, PolicyClass.P1_LOW_IMPACT,
                      PolicyClass.P2_INTRUSIVE, PolicyClass.P3_EXCLUDED)
_RE, _SC, _VA, _AT, _AN = (AgentRole.RECON, AgentRole.SCAN, AgentRole.VALIDATE,
                           AgentRole.ATTACK, AgentRole.ANALYSIS)
_MODES = ["black_box", "gray_box", "white_box"]

_WORDLIST_DEFAULT = "/usr/share/seclists/Discovery/Web-Content/common.txt"

_WORKERS_BIN = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))),
    "workers", "bin",
)


def _resolve_domain_dc(domain: str, dns_server: str) -> str | None:
    """Resolve an AD domain to its DC IP using a specific DNS server.

    In multi-domain AD forests the engagement target may be a parent-domain DC
    while the credentials belong to a child domain served by a different DC.
    Querying the parent DC's DNS for the child domain name returns the child
    DC's IP, which we can then substitute into ``-dc-ip`` so impacket tools
    talk to the right server.
    """
    try:
        proc = subprocess.run(
            ["dig", "+short", domain, f"@{dns_server}"],
            capture_output=True, text=True, timeout=5,
            stdin=subprocess.DEVNULL,
        )
        for line in proc.stdout.strip().split("\n"):
            ip = line.strip()
            if ip and not ip.startswith(";"):
                return ip
    except Exception:
        pass
    return None


def _port(args: dict) -> str:
    p = str(args.get("port", "")).strip()
    return p if (p.isdigit() and 0 < int(p) < 65536) else ""


def _url(args: dict) -> str:
    host = _valid_host(str(args["target"]))
    scheme = "https" if str(args.get("scheme", "")).lower() == "https" else "http"
    pr = _port(args)
    return f"{scheme}://{host}" + (f":{pr}" if pr else "")


def _resolve(tok: str, args: dict):
    if tok in ("{target}", "{domain}"):
        return _valid_host(str(args["target"]))
    if tok == "{url}":
        return _url(args)
    if tok == "{port}":
        return _port(args) or None
    if tok == "{ports}":
        return str(args.get("ports", "")).strip() or None
    if tok == "{wordlist}":
        return os.environ.get("VAPT_WORDLIST", _WORDLIST_DEFAULT)
    if tok == "{base_urls}":
        # Comma-joined list of in-scope web base URLs. The caller passes
        # args["base_urls"] as a list OR a comma-separated string; we
        # normalize to a single comma string that the js_endpoint_miner
        # (and future multi-base tools) parse out.
        bu = args.get("base_urls")
        if isinstance(bu, list):
            return ",".join(str(x).strip() for x in bu if str(x).strip())
        return str(bu or "").strip() or None
    if tok == "{username_field}":
        # Form field name for weak_cred_probe. Defaults to "username".
        # Explicit empty string ('') from the orchestrator means "password-
        # only form" (phpLiteAdmin shape). But _mk_build drops empty-string
        # resolved values, which would also drop the preceding --username-
        # field flag and desync argparse. So we return a sentinel string
        # for the password-only case; the probe treats it as "no username".
        v = args.get("username_field")
        if v is None:
            return "username"
        if str(v) == "":
            return "__PASSWORD_ONLY__"
        return str(v)
    if tok == "{password_field}":
        v = args.get("password_field")
        return str(v) if v else "password"
    if tok == "{extra_fields}":
        # Hidden/required fields the login form expects on every submit
        # (e.g. phpLiteAdmin's `login=Log+In&remember=`). Caller passes
        # args["extra_fields"] as a k=v,k2=v2 string. If no extras, return
        # the sentinel "__NONE__" (not empty) so _mk_build still appends
        # the flag+value pair and argparse doesn't desync. The probe
        # treats __NONE__ as "no extras".
        s = str(args.get("extra_fields") or "").strip()
        return s if s else "__NONE__"
    if tok == "{method}":
        # HTTP method (xxe_probe uses post/get). Default: post.
        return str(args.get("method") or "post").lower()
    if tok == "{param}":
        # Query-string / form-field name (xxe_probe optional). Empty is
        # a legit "use the probe's default" case; return "__NONE__" so
        # _mk_build appends the flag without desyncing argparse — the
        # xxe_probe wrapper treats __NONE__ as no override.
        v = str(args.get("param") or "").strip()
        return v if v else "__NONE__"
    if "{target}" in tok:
        host = _valid_host(str(args["target"]))
        return tok.replace("{target}", host) if host else None
    return tok  # literal


# Catalog HTTP(S) tools that accept an auth session cookie via a `-H Cookie: ...` flag
# (or an equivalent). When the webvuln node has obtained a session cookie it exposes it
# through VAPT_WEB_LOGIN_COOKIE; _mk_build appends the right flag for the current run so
# the SAME tools used for discovery (katana crawl, feroxbuster content discovery) can now
# reach POST-LOGIN routes (/order, /admin/*, /receipt/download, …). Flag per tool, since
# each has its own spelling (katana `-H`, nuclei `-H`, feroxbuster `-H`, arjun `--headers`).
_COOKIE_HEADER_FLAG = {
    "katana": "-H",
    "feroxbuster": "-H",
    "nikto": "-H",
    "whatweb": "-c",       # whatweb uses -c "Cookie: ..."
    "wafw00f": None,       # no built-in cookie flag; left unauthenticated
    "cmseek": None,
    "shcheck": None,
    "arjun": "--headers",  # arjun built-in overrides this; keep consistent for the catalog path
}


# Network tools that accept domain credentials for authenticated AD scans.
_DOMAIN_CRED_ARGS: dict[str, object] = {
    "smbmap":              lambda d, u, p: ["-u", u, "-p", p, "-d", d],
    "enum4linux_ng":       lambda d, u, p: ["-u", f"{d}\\{u}", "-p", p],
    "smbclient_list":      lambda d, u, p: ["-U", f"{d}\\{u}%{p}"],
    "ldapsearch_base":     lambda d, u, p: ["-D", f"{u}@{d}", "-w", p],
    "netexec_smb":         lambda d, u, p: ["-u", u, "-p", p, "-d", d],
    "impacket_secretsdump": lambda d, u, p: [f"{d}/{u}:{p}@"],
    "bloodyad":            lambda d, u, p: ["-u", f"{u}@{d}", "-p", p],
    "certipy_find":        lambda d, u, p: ["-u", f"{u}@{d}", "-p", p],
    "impacket_getuserspns": lambda d, u, p: [f"{d}/{u}:{p}"],
    "impacket_getnpusers":  lambda d, u, p: [f"{d}/{u}:{p}"],
    "impacket_finddelegation": lambda d, u, p: [f"{d}/{u}:{p}"],
    "impacket_getadusers":  lambda d, u, p: [f"{d}/{u}:{p}"],
    "impacket_lookupsid":   lambda d, u, p: [f"{d}/{u}:{p}"],
    "impacket_mssqlenum":   lambda d, u, p: [f"{d}/{u}:{p}"],
    "ad_enum":              lambda d, u, p: [f"{d}/{u}:{p}"],
    "bloodhound_python":    lambda d, u, p: ["-u", f"{u}@{d}", "-p", p, "-d", d],
    "dig_axfr":             lambda d, u, p: [d, "AXFR"],
    "coercer_scan":         lambda d, u, p: ["-u", u, "-p", p, "-d", d],
    "nxc_petitpotam":       lambda d, u, p: ["-u", u, "-p", p, "-d", d],
    "nxc_printerbug":       lambda d, u, p: ["-u", u, "-p", p, "-d", d],
    "nxc_shadowcoerce":     lambda d, u, p: ["-u", u, "-p", p, "-d", d],
    "nxc_dfscoerce":        lambda d, u, p: ["-u", u, "-p", p, "-d", d],
    "certipy_req":          lambda d, u, p: ["-u", f"{u}@{d}", "-p", p],
    "impacket_getst":       lambda d, u, p: [f"{d}/{u}:{p}"],
    "impacket_gettgt":      lambda d, u, p: [f"{d}/{u}:{p}"],
    "impacket_ticketer":    lambda d, u, p: [],
    "impacket_psexec":      lambda d, u, p: [f"{d}/{u}:{p}@"],
    "impacket_wmiexec":     lambda d, u, p: [f"{d}/{u}:{p}@"],
    "impacket_smbexec":     lambda d, u, p: [f"{d}/{u}:{p}@"],
    "impacket_atexec":      lambda d, u, p: [f"{d}/{u}:{p}@"],
    "impacket_dcomexec":    lambda d, u, p: [f"{d}/{u}:{p}@"],
    "impacket_rbcd":        lambda d, u, p: [f"{d}/{u}:{p}"],
    "nxc_laps":             lambda d, u, p: ["-u", u, "-p", p, "-d", d],
    "nxc_gmsa":             lambda d, u, p: ["-u", u, "-p", p, "-d", d],
    "impacket_ntlmrelayx":  lambda d, u, p: [],
    "nxc_trusts":           lambda d, u, p: ["-u", u, "-p", p, "-d", d],
}
_DOMAIN_STRIP_FLAGS: dict[str, set[str]] = {
    "smbclient_list": {"-N"},
}


def _mk_build(tool_id: str, bins: list[str], template: list[str]):
    env_key = "VAPT_" + tool_id.upper().replace("-", "_") + "_BIN"
    flag = _COOKIE_HEADER_FLAG.get(tool_id)
    domain_cred_builder = _DOMAIN_CRED_ARGS.get(tool_id)

    def _resolve_bin() -> str:
        override = os.environ.get(env_key)
        if override:
            return override
        for b in bins:
            if b.startswith("vapt-"):
                shipped = os.path.join(_WORKERS_BIN, b)
                if os.path.isfile(shipped):
                    return shipped
            if shutil.which(b):
                return b
        return bins[0]

    def build(args: dict) -> list[str]:
        argv = [_resolve_bin()]
        for tok in template:
            v = _resolve(tok, args)
            if v is not None:
                argv.append(v)
        # Authenticated-scanning cookie — appended at argv build time, not plan time, so a
        # single plan item adapts to "unauth before login" vs "authed after login".
        if flag:
            cookie = os.environ.get("VAPT_WEB_LOGIN_COOKIE", "").strip()
            if cookie and not cookie.startswith("-") \
               and all(c not in cookie for c in ("\r", "\n", "\x00")):
                argv += [flag, f"Cookie: {cookie}"]
        # Domain credentials (network AD targets) — appended at argv build time so they
        # never appear in the plan/digest/ledger. Also accepts creds passed via args by
        # the tool router (domain_user, domain_pass, domain keys).
        if domain_cred_builder:
            dc = None
            if args.get("domain_user") and args.get("domain_pass") and args.get("domain"):
                dc = (args["domain"], args["domain_user"], args["domain_pass"])
            if not dc:
                dc = _domain_credentials()
            if dc:
                dom, user, pw = dc
                strip = _DOMAIN_STRIP_FLAGS.get(tool_id, set())
                if strip:
                    argv = [a for a in argv if a not in strip]
                argv += domain_cred_builder(dom, user, pw)
                # Cross-domain DC resolution: in a multi-domain AD forest the
                # engagement target may be a parent DC while the creds belong
                # to a child domain on a different DC.  Resolve the cred domain
                # via DNS (using the target as nameserver) and swap -dc-ip when
                # the domain maps to a different IP.
                target_ip = str(args.get("target", ""))
                if "-dc-ip" in argv and target_ip:
                    resolved = _resolve_domain_dc(dom, target_ip)
                    if resolved and resolved != target_ip:
                        try:
                            idx = argv.index("-dc-ip")
                            if idx + 1 < len(argv):
                                argv[idx + 1] = resolved
                        except ValueError:
                            pass
            else:
                import sys as _sys
                print(f"[catalog-diag] {tool_id}: no domain creds — "
                      f"args_keys={sorted(args.keys())} "
                      f"domain_user={bool(args.get('domain_user'))} "
                      f"domain_pass={bool(args.get('domain_pass'))} "
                      f"domain={bool(args.get('domain'))} "
                      f"redis_fallback=None",
                      file=_sys.stderr)
        return argv
    return build


# (id, [binaries], argv-template, policy, [agents], target_kind[, ok_exit_codes])
CATALOG: list[tuple] = [
    # --- 1. Recon & asset discovery ---------------------------------------------------
    ("subfinder",   ["subfinder"],   ["-silent", "-d", "{domain}"],                 _P0, [_RE, _SC], "network"),
    ("amass_passive", ["amass"],      ["enum", "-passive", "-d", "{domain}"],        _P0, [_RE, _SC], "network"),
    ("assetfinder", ["assetfinder"],  ["--subs-only", "{domain}"],                   _P0, [_RE, _SC], "network"),
    ("sublist3r",   ["sublist3r"],    ["-n", "-d", "{domain}"],                      _P0, [_RE, _SC], "network"),
    ("theharvester", ["theHarvester", "theharvester"], ["-d", "{domain}", "-b", "bing,crtsh,duckduckgo"], _P0, [_RE], "network"),
    ("whois_lookup", ["whois"],       ["{domain}"],                                  _P0, [_RE], "network"),
    ("dnsrecon",    ["dnsrecon"],     ["-d", "{domain}"],                            _P1, [_RE, _SC], "network"),
    ("waybackurls", ["waybackurls"],  ["{domain}"],                                  _P0, [_RE, _SC], "network"),
    ("gau",         ["gau"],          ["--subs", "{domain}"],                        _P0, [_RE, _SC], "network"),
    # waybacklister: Wayback archive + ACTIVE directory-listing probe. Different
    # value class from waybackurls/gau: not just URL enumeration — detects which
    # of those historical paths still return a live "Index of /" page. P1 because
    # it sends live GETs to probe exposure. Domain targets only (upstream wrapper
    # rejects IPs; Wayback has no data for raw IP endpoints).
    ("waybacklister", ["vapt-waybacklister"],
                      ["--domain", "{domain}", "--threads", "10"],
                      _P1, [_RE, _SC], "network"),
    # js_endpoint_miner: mines served .js files for /path-shaped strings
    # and probes /openapi.json / /swagger.json / /actuator/mappings for API
    # specs. P1 passive — just reads what the server already serves. Catches
    # UNLINKED endpoints that bundled JS references but no HTML page links to
    # (the common pattern for `/api/v1/*` routes in modern SPAs). Argv-only
    # wrapper under workers/bin; auto-fed into discovered_endpoint_urls via
    # the engagement normalizer.
    ("js_endpoint_miner", ["vapt-js-endpoint-miner"],
                          ["--target", "{target}",
                           "--base-urls", "{base_urls}",
                           "--max-js", "20"],
                          _P1, [_RE, _SC], "network"),
    ("katana",      ["katana"],       ["-silent", "-u", "{url}", "-d", "5", "-jc", "-kf", "all"], _P1, [_RE, _SC], "network"),  # -d 5: crawl deeper than default 3; -jc: parse JS for endpoints (finds app/API routes like /api/debug, /order not present as plain links); -kf all: robots.txt + sitemap.xml
    ("whatweb",     ["whatweb"],      ["--quiet", "--no-errors", "{url}"],           _P1, [_RE, _SC], "network"),
    ("wafw00f",     ["wafw00f"],      ["{url}"],                                     _P1, [_RE, _SC], "network"),

    # --- 2. Scanning & enumeration ----------------------------------------------------
    ("naabu",       ["naabu"],        ["-silent", "-host", "{target}"],              _P1, [_SC], "network"),
    ("masscan",     ["masscan"],      ["-p1-1000", "--rate", "1000", "{target}"],    _P2, [_SC], "network"),  # high-rate → gated
    ("gobuster_dir", ["gobuster"],    ["dir", "-q", "-u", "{url}", "-w", "{wordlist}"], _P1, [_SC], "network"),
    ("ffuf",        ["ffuf"],         ["-s", "-u", "{url}/FUZZ", "-w", "{wordlist}"], _P1, [_SC], "network"),
    ("feroxbuster", ["feroxbuster"],  ["--silent", "-k", "-n", "-u", "{url}", "-w", "{wordlist}"], _P1, [_SC], "network"),  # --silent+-q conflict → exit 2; -n bounds recursion
    ("dirsearch",   ["dirsearch"],    ["-q", "-u", "{url}"],                         _P1, [_SC], "network"),
    ("arjun",       ["arjun"],        ["-u", "{url}"],                               _P1, [_SC], "network"),  # overridden by the built-in spec (per-endpoint url); kept so the id stays in the SCAN manifest
    ("smbmap",      ["smbmap"],       ["-H", "{target}", "--no-write-check", "--depth", "1", "--timeout", "30"], _P1, [_SC, _AN], "network", (0,), 45),
    ("enum4linux_ng", ["enum4linux-ng", "enum4linux"], ["-A", "{target}"],          _P1, [_SC, _AN], "network"),
    ("smbclient_list", ["smbclient"], ["-L", "{target}", "-N"],                      _P1, [_SC, _AN], "network", (0, 1)),
    ("ldapsearch_base", ["ldapsearch"], ["-x", "-H", "ldap://{target}", "-s", "base", "-b", ""], _P1, [_SC, _AN], "network"),
    ("impacket_getuserspns", ["GetUserSPNs.py", "impacket-GetUserSPNs", "vapt-getuserspns"], ["-dc-ip", "{target}", "-request"], _P1, [_SC, _AN], "network"),
    ("impacket_getnpusers", ["GetNPUsers.py", "impacket-GetNPUsers", "vapt-getnpusers"], ["-dc-ip", "{target}"], _P1, [_SC, _AN], "network"),
    ("impacket_finddelegation", ["findDelegation.py", "impacket-findDelegation"], ["-dc-ip", "{target}"], _P1, [_SC, _AN], "network"),
    ("impacket_getadusers", ["GetADUsers.py", "impacket-GetADUsers"], ["-all", "-dc-ip", "{target}"], _P1, [_SC, _AN], "network"),
    ("impacket_lookupsid", ["vapt-lookupsid"],  ["-dc-ip", "{target}"],              _P1, [_SC, _AN], "network"),
    ("impacket_rpcdump", ["rpcdump.py", "impacket-rpcdump"], ["{target}"],           _P1, [_SC, _AN], "network"),
    ("rpcclient_enum", ["rpcclient"],   ["-U", "", "-N", "{target}", "-c", "enumdomusers;enumdomgroups;querydominfo;getdompwinfo;lsaenumsid"], _P1, [_SC, _AN], "network", (0, 1)),
    ("nxc_smb_signing", ["nxc", "netexec"], ["smb", "{target}"],                     _P1, [_SC, _AN], "network"),
    ("impacket_mssqlenum", ["vapt-mssqlenum"], ["-target-ip", "{target}"],           _P1, [_SC, _AN], "network"),
    ("ad_enum", ["vapt-ad-enum"],       ["-dc-ip", "{target}"],                       _P1, [_SC, _AN], "network"),
    ("bloodhound_python", ["bloodhound-python", "bloodhound"], ["-ns", "{target}", "-c", "All"], _P1, [_SC, _AN], "network"),
    ("bloodhound_analyzer", ["vapt-bloodhound-analyzer"], ["."],                     _P1, [_SC, _VA, _AN], "network"),
    ("certipy_analyzer", ["vapt-certipy-analyzer"], ["."],                           _P1, [_SC, _VA, _AN], "network"),
    ("dig_axfr",    ["dig"],          ["@{target}"],                                 _P1, [_SC, _AN], "network"),
    ("cewl",        ["cewl"],         ["-d", "1", "{url}"],                          _P1, [_SC], "network"),
    ("onesixtyone", ["onesixtyone"],  ["{target}"],                                  _P2, [_SC], "network"),  # SNMP community brute → gated
    ("smtp_user_enum", ["smtp-user-enum"], ["-M", "VRFY", "-U", "{wordlist}", "-t", "{target}"], _P2, [_SC], "network"),

    # --- 3. Vulnerability assessment --------------------------------------------------
    ("nikto",       ["nikto"],        ["-ask", "no", "-nointeractive", "-maxtime", "180", "-host", "{url}"], _P1, [_SC, _VA, _AN], "network", (0, 1)),  # self-cap at 3m (nikto on IIS can run until the tool timeout otherwise)
    ("wpscan",      ["wpscan"],       ["--url", "{url}", "--no-banner", "--format", "cli-no-color"], _P1, [_SC, _VA], "network", (0, 1, 4, 5)),
    ("joomscan",    ["joomscan"],     ["--url", "{url}"],                            _P1, [_SC, _VA], "network"),
    ("droopescan",  ["droopescan"],   ["scan", "drupal", "-u", "{url}"],             _P1, [_SC, _VA], "network"),
    ("cmseek",      ["cmseek", "CMSeeK"], ["-u", "{url}", "--follow-redirect"],      _P1, [_SC, _VA], "network", (0, 1)),  # exit 1 = no CMS detected, not a failure
    ("graphql_cop", ["graphql-cop"],  ["-t", "{url}"],                               _P1, [_SC, _VA], "network"),
    ("shcheck",     ["shcheck", "shcheck.py"], ["{url}"],                            _P1, [_SC, _VA], "network"),
    ("humble",      ["humble", "humble.py"], ["-u", "{url}", "-b"],                  _P1, [_SC, _VA], "network"),
    ("sslyze",      ["sslyze"],       ["{target}"],                                  _P1, [_SC, _VA], "network"),
    ("ssh_audit",   ["ssh-audit"],    ["{target}"],                                  _P1, [_SC, _VA], "network", (0, 1, 2, 3)),
    ("subzy",       ["subzy"],        ["run", "--target", "{domain}"],              _P1, [_SC, _VA], "network"),
    ("swaks_relay", ["swaks"],        ["--server", "{target}", "--quit-after", "RCPT", "--to", "test@example.com", "--from", "probe@example.com"], _P1, [_SC, _VA], "network"),
    ("corsy",       ["corsy", "corsy.py"], ["-u", "{url}"],                         _P1, [_SC, _VA], "network"),
    ("wapiti",      ["wapiti"],       ["-u", "{url}", "--flush-session", "-f", "json", "-o", "/dev/stdout"], _P2, [_SC, _VA], "network"),  # sends payloads → gated; emit the JSON report on stdout so findings are parsed (not just logged)
    ("xsstrike",    ["xsstrike", "XSStrike"], ["-u", "{url}"],                       _P2, [_VA, _AT], "network"),
    ("xsrfprobe",   ["xsrfprobe"],    ["-u", "{url}"],                               _P2, [_VA, _AT], "network"),

    # --- 4. Exploitation (all P2, ATTACK-only, human-gated) ---------------------------
    ("sqlmap",      ["sqlmap"],       ["-u", "{url}", "--batch", "--level", "1", "--risk", "1"], _P2, [_AT], "network"),
    ("ghauri",      ["ghauri"],       ["-u", "{url}", "--batch"],                    _P2, [_AT], "network"),
    ("commix",      ["commix"],       ["-u", "{url}", "--batch"],                    _P2, [_AT], "network"),
    ("sstimap",     ["sstimap", "sstimap.py"], ["-u", "{url}"],                      _P2, [_AT], "network"),
    # weak_cred_probe: tries ~16 common default credential pairs against a known
    # login form. P2 (sends auth attempts), SCAN/ATTACK. Catches the classic
    # phpLiteAdmin admin/admin, Tomcat tomcat/tomcat, generic admin/password
    # defaults. Argv-only wrapper under workers/bin. Bounded (16 pairs max,
    # one request each, 150s total budget), no shell, no brute-force sweep.
    ("weak_cred_probe", ["vapt-weak-cred-probe"],
                        ["--target", "{target}", "--url", "{url}",
                         "--username-field", "{username_field}",
                         "--password-field", "{password_field}",
                         "--extra-fields", "{extra_fields}"],
                        _P2, [_SC, _AT], "network"),
    # xxe_probe: sends 6 XXE payload shapes (file:// SYSTEM entity, parameter-
    # entity blind, PHP base64 filter, SOAP envelope) to an XML-intake endpoint.
    # Read-only payloads (no system() tags). argv-only, bounded, P2.
    ("xxe_probe",   ["vapt-xxe-probe"],
                    ["--target", "{target}", "--url", "{url}",
                     "--method", "{method}", "--param", "{param}",
                     "--extra-fields", "{extra_fields}"],
                    _P2, [_SC, _VA], "network"),
    ("dotdotpwn",   ["dotdotpwn"],    ["-m", "http", "-h", "{target}", "-q"],        _P2, [_AT], "network"),
    ("fuxploider",  ["fuxploider"],   ["-u", "{url}", "--not-regex", "nonexistent"], _P2, [_AT], "network"),
    ("nosqlmap",    ["nosqlmap", "NoSQLMap"], ["--url", "{url}"],                    _P2, [_AT], "network"),
    ("hydra",       ["hydra"],        ["-L", "{wordlist}", "-P", "{wordlist}", "-f", "{target}"], _P2, [_AT], "network"),
    ("medusa",      ["medusa"],       ["-U", "{wordlist}", "-P", "{wordlist}", "-h", "{target}"], _P2, [_AT], "network"),
    # P3 — registered but policy-denied (MITM / C2): catalogued, never auto-runs
    # (but WILL run under auto-approve since policy now downgrades P3→REQUIRE_APPROVAL).
    ("responder",   ["responder", "Responder.py"], ["-I", "eth0"],                  _P3, [_AT], "network"),
    ("mitm6",       ["mitm6"],        ["-d", "{domain}"],                            _P3, [_AT], "network"),
    ("bettercap",   ["bettercap"],    [],                                            _P3, [_AT], "network"),
    ("ettercap",    ["ettercap"],     ["-T", "-q"],                                  _P3, [_AT], "network"),
    ("beef",        ["beef"],         [],                                            _P3, [_AT], "local"),
    ("sliver",      ["sliver-server", "sliver"], [],                                 _P3, [_AT], "local"),

    # --- 5. Post-exploitation (P2 ATTACK-only; relay/C2 → P3) -------------------------
    ("netexec_smb", ["nxc", "netexec"], ["smb", "{target}"],                        _P2, [_AT], "network"),
    ("impacket_secretsdump", ["impacket-secretsdump", "secretsdump.py"], ["{target}"], _P2, [_AT], "network"),
    ("lsassy",      ["lsassy"],       ["{target}"],                                  _P2, [_AT], "network"),
    ("bloodyad",    ["bloodyAD", "bloodyad"], ["--host", "{target}", "get", "search"], _P2, [_AT], "network"),
    ("certipy_find", ["certipy", "certipy-ad"], ["find", "-target", "{target}"],     _P1, [_SC, _AT, _AN], "network"),
    ("chisel",      ["chisel"],       ["client"],                                    _P2, [_AT], "network"),
    ("ligolo_proxy", ["ligolo-proxy"], ["-selfcert"],                               _P2, [_AT], "local"),
    ("krbrelayx",   ["krbrelayx", "krbrelayx.py"], [],                               _P3, [_AT], "network"),

    # --- 6. Hash cracking (offline, local-only) ----------------------------------------
    ("hashcat_kerberoast", ["hashcat"], ["-m", "13100", "-a", "0", "--potfile-disable",
                                         "--force", "{target}", "{wordlist}"],
                           _P0, [_AT, _AN], "local", (0, 1), 300),
    ("hashcat_asrep",      ["hashcat"], ["-m", "18200", "-a", "0", "--potfile-disable",
                                         "--force", "{target}", "{wordlist}"],
                           _P0, [_AT, _AN], "local", (0, 1), 300),
    ("john_kerberoast",    ["john"],    ["--format=krb5tgs", "--wordlist={wordlist}", "{target}"],
                           _P0, [_AT, _AN], "local", (0, 1), 300),
    ("john_asrep",         ["john"],    ["--format=krb5asrep", "--wordlist={wordlist}", "{target}"],
                           _P0, [_AT, _AN], "local", (0, 1), 300),

    # --- 7. Coercion checks (authentication coercion / relay trigger) ------------------
    ("coercer_scan",       ["coercer"], ["scan", "-t", "{target}", "-u", "{target}", "-d", "{domain}"],
                           _P1, [_SC, _AT, _AN], "network", (0,), 60),
    ("nxc_petitpotam",     ["nxc", "netexec"], ["smb", "{target}", "-M", "petitpotam"],
                           _P2, [_AT, _AN], "network"),
    ("nxc_printerbug",     ["nxc", "netexec"], ["smb", "{target}", "-M", "printerbug"],
                           _P2, [_AT, _AN], "network"),
    ("nxc_shadowcoerce",   ["nxc", "netexec"], ["smb", "{target}", "-M", "shadowcoerce"],
                           _P2, [_AT, _AN], "network"),
    ("nxc_dfscoerce",      ["nxc", "netexec"], ["smb", "{target}", "-M", "dfscoerce"],
                           _P2, [_AT, _AN], "network"),

    # --- 8. ADCS exploitation ----------------------------------------------------------
    ("certipy_req",        ["certipy", "certipy-ad"], ["req", "-target", "{target}", "-ca", "{target}"],
                           _P2, [_AT], "network"),
    ("certipy_auth",       ["certipy", "certipy-ad"], ["auth", "-pfx", "{target}"],
                           _P2, [_AT], "local"),

    # --- 9. Kerberos ticket & delegation exploitation ----------------------------------
    ("impacket_getst",     ["getST.py", "impacket-getST"],
                           ["-dc-ip", "{target}", "-spn", "cifs/{target}"],
                           _P2, [_AT], "network"),
    ("impacket_gettgt",    ["getTGT.py", "impacket-getTGT"],
                           ["-dc-ip", "{target}"],
                           _P2, [_AT], "network"),
    ("impacket_ticketer",  ["ticketer.py", "impacket-ticketer"],
                           ["-domain", "{domain}", "-dc-ip", "{target}"],
                           _P2, [_AT], "network"),
    ("impacket_describeticket", ["describeTicket.py", "impacket-describeTicket"],
                                ["{target}"],
                                _P0, [_AT, _AN], "local"),

    # --- 10. Lateral movement / remote execution (P2, human-gated) ---------------------
    ("impacket_psexec",    ["psexec.py", "impacket-psexec"],
                           ["{target}"],
                           _P2, [_AT], "network"),
    ("impacket_wmiexec",   ["wmiexec.py", "impacket-wmiexec"],
                           ["{target}"],
                           _P2, [_AT], "network"),
    ("impacket_smbexec",   ["smbexec.py", "impacket-smbexec"],
                           ["{target}"],
                           _P2, [_AT], "network"),
    ("impacket_atexec",    ["atexec.py", "impacket-atexec"],
                           ["{target}"],
                           _P2, [_AT], "network"),
    ("impacket_dcomexec",  ["dcomexec.py", "impacket-dcomexec"],
                           ["{target}"],
                           _P2, [_AT], "network"),

    # --- 11. RBCD / delegation abuse ---------------------------------------------------
    ("impacket_rbcd",      ["rbcd.py"],
                           ["-dc-ip", "{target}", "-action", "read", "-delegate-to", "{target}"],
                           _P2, [_AT, _AN], "network"),

    # --- 12. LAPS / gMSA password reading ----------------------------------------------
    ("nxc_laps",           ["nxc", "netexec"], ["ldap", "{target}", "--laps"],
                           _P2, [_AT, _AN], "network"),
    ("nxc_gmsa",           ["nxc", "netexec"], ["ldap", "{target}", "--gmsa"],
                           _P2, [_AT, _AN], "network"),

    # --- 13. NTLM relay (P3 — MITM, runs only under auto-approve) ---------------------
    ("impacket_ntlmrelayx", ["ntlmrelayx.py", "impacket-ntlmrelayx"],
                            ["-t", "{target}", "--no-http-server"],
                            _P3, [_AT], "network"),

    # --- 14. Cross-domain trust enumeration --------------------------------------------
    ("nxc_trusts",         ["nxc", "netexec"], ["ldap", "{target}", "-M", "enum_trusts"],
                           _P1, [_SC, _AT, _AN], "network"),
]


# Concise, action-oriented purpose per tool. This is what the LLM planner reads when it
# chooses a scan plan (planner.py lists each tool as "- <id> [<policy>]: <description>"), so
# each line says WHAT the tool finds and WHEN it applies (which service/port/tech). Keep each
# to one line, no secrets, no host-specific content.
_PURPOSE: dict[str, str] = {
    # recon
    "subfinder": "Passive subdomain enumeration for a domain (OSINT sources). Use when the target is a domain.",
    "amass_passive": "Passive subdomain/ASN enumeration for a domain. Broader, slower than subfinder.",
    "assetfinder": "Quick passive subdomain discovery for a domain.",
    "sublist3r": "Passive subdomain enumeration via search engines. Domain targets.",
    "theharvester": "OSINT emails/hosts/subdomains for a domain from public sources.",
    "whois_lookup": "WHOIS registration/ownership for a domain or IP.",
    "dnsrecon": "DNS enumeration (records, zone transfer attempt, brute). Domain targets.",
    "waybackurls": "Historical URLs for a domain from the Wayback Machine (endpoint discovery).",
    "gau": "Known URLs for a domain from Wayback/CommonCrawl/OTX (endpoint discovery).",
    "waybacklister": "Finds still-exposed 'Index of /' directory listings by probing historical paths from the Wayback Machine. Domain targets. Catches forgotten exposed directories scanners of live-only content miss.",
    "js_endpoint_miner": "Mines served .js files for /path-shaped URL strings and probes common API-spec endpoints (/openapi.json, /swagger.json, /actuator/mappings). Discovers UNLINKED endpoints that bundled JavaScript references but no HTML page links to — a major class of hidden surface in modern SPAs and REST APIs. P1 passive.",
    "weak_cred_probe": "Tries ~16 common default credential pairs (admin/admin, root/root, tomcat/tomcat, phpLiteAdmin admin/admin, etc.) against a known HTTP login form. Catches the classic default-cred bug that chains to full compromise. Argv-only, bounded (16 attempts, 150s budget), P2 approval-gated.",
    "xxe_probe": "Sends 6 XML External Entity payload shapes (file:// SYSTEM entity, parameter-entity blind, PHP base64 filter, SOAP envelope wrapper) to a known XML-intake endpoint. Confirms file-disclosure XXE by matching leaked /etc/passwd / /etc/hostname / win.ini / <?php content in the response body. Argv-only, bounded (6 payloads, 90s budget), P2 approval-gated.",
    "katana": "Active web crawler — discovers endpoints/links on a live HTTP(S) site. Use when a web service is open.",
    "whatweb": "Web technology fingerprint (server, CMS, frameworks) for an HTTP(S) URL. First step on any web service.",
    "wafw00f": "Detects whether a WAF fronts an HTTP(S) site. Use before active web testing.",
    # scan / enum
    "naabu": "Fast TCP port discovery for a host. Complements nmap.",
    "masscan": "Very high-rate port sweep (noisy) — gated; use only for authorized wide ranges.",
    "gobuster_dir": "Directory/file brute force on a web server (wordlist). Use when a web service is open.",
    "ffuf": "Fast web fuzzer for content/parameter discovery (FUZZ keyword). Web services.",
    "feroxbuster": "Recursive content discovery on a web server. Use when a web service is open.",
    "dirsearch": "Web path brute force. Alternative to gobuster/feroxbuster.",
    "arjun": "HTTP parameter discovery for a URL (hidden GET/POST params).",
    "smbmap": "Enumerate SMB shares and access on a host. Use when 445/139 is open.",
    "enum4linux_ng": "Full SMB/NetBIOS enumeration (users, shares, groups, policy). Use when SMB is open.",
    "smbclient_list": "List SMB shares with a null session. Use when 445 is open.",
    "ldapsearch_base": "Read the LDAP root DSE (naming contexts, domain info). Use when 389/636 is open.",
    "impacket_getuserspns": "Kerberoasting — request TGS tickets for service accounts with SPNs to crack offline. Use when Kerberos (88) is open and domain creds available.",
    "impacket_getnpusers": "AS-REP roasting — find accounts without Kerberos pre-authentication. Use when Kerberos (88) is open and domain creds available.",
    "impacket_finddelegation": "Enumerate delegation settings (unconstrained, constrained, RBCD) across AD accounts. Finds lateral movement and privilege escalation paths via Kerberos delegation abuse. Use when LDAP is open and domain creds available.",
    "impacket_getadusers": "Enumerate all domain users with attributes (name, email, password-last-set, last-logon, description). Catches passwords stored in description fields. Use when LDAP is open and domain creds available.",
    "impacket_lookupsid": "SID brute-force enumeration — discovers domain users, groups, and machine accounts via LSA SID lookups. Also reveals cross-domain trust relationships. Use when SMB (445) is open and domain creds available.",
    "impacket_rpcdump": "Enumerate RPC endpoints exposed on a host. Lists all registered RPC interfaces (MS-DRSR, MS-RPRN, MS-EFSRPC, etc.) — identifies attack surface for PrinterBug, PetitPotam, and other coercion vectors. Use when port 135 is open.",
    "rpcclient_enum": "Anonymous RPC enumeration — attempts null-session user/group enumeration, domain info, and password policy queries via SMB/RPC. Detects whether anonymous access is permitted. Use when SMB (445/139) is open.",
    "nxc_smb_signing": "SMB banner grab — reports SMB signing status, SMBv1, null auth, and DC detection. SMB signing disabled enables NTLM relay attacks. Use when SMB (445) is open.",
    "impacket_mssqlenum": "MSSQL enumeration — lists databases, linked servers, server roles, and current user context via Windows authentication. Linked servers enable cross-domain pivoting. Use when MSSQL (1433) is open and domain creds available.",
    "ad_enum": "AD misconfiguration enumeration — checks for passwords in description fields, LAPS readability, gMSA accounts, trust relationships, and admin group membership. Use when LDAP is open and domain creds available.",
    "bloodhound_python": "Active Directory attack-path collection (users, groups, ACLs, sessions, trusts). Use when LDAP+SMB are open and domain creds available.",
    "bloodhound_analyzer": "Analyzes BloodHound JSON output for AD attack paths — identifies dangerous ACL relationships (GenericAll, WriteDacl, WriteOwner, ForceChangePassword), GPO abuse (writable GPOs linked to privileged OUs), delegation abuse (unconstrained, constrained, RBCD), and multi-hop privilege escalation chains. Run AFTER bloodhound_python.",
    "certipy_analyzer": "Analyzes Certipy JSON output for ADCS ESC1-ESC8 vulnerabilities — classifies each certificate template and CA for exploitable misconfigurations (enrollee-supplies-subject, low-priv enrollment, template write access, HTTP enrollment, SAN override). Run AFTER certipy_find.",
    "dig_axfr": "DNS zone transfer (AXFR) attempt against a DNS server. Leaks all DNS records if the server allows it. Use when port 53 is open and domain name known.",
    "cewl": "Build a wordlist by spidering a website (for later auth testing).",
    "onesixtyone": "SNMP community-string brute (gated). Use when 161/udp SNMP is present.",
    "smtp_user_enum": "SMTP user enumeration via VRFY/EXPN (gated). Use when 25/465/587 is open.",
    # vuln assessment
    "nikto": "Web server misconfig & known-issue scanner for an HTTP(S) URL. Core web vuln check.",
    "wpscan": "WordPress vulnerability scanner (core/plugins/themes/users). Use when WordPress is detected.",
    "joomscan": "Joomla vulnerability scanner. Use when Joomla is detected.",
    "droopescan": "Drupal/SilverStripe CMS scanner. Use when Drupal is detected.",
    "cmseek": "CMS detection & basic enumeration (WordPress/Joomla/Drupal/…). Use to identify a CMS on a web service.",
    "graphql_cop": "GraphQL security audit for a GraphQL endpoint.",
    "shcheck": "HTTP security-header assessment for a URL. Quick, safe config check.",
    "humble": "Detailed HTTP security-header analysis for a URL.",
    "sslyze": "TLS/SSL configuration audit (protocols, ciphers, cert) for a host. Use when a TLS port is open.",
    "ssh_audit": "SSH server config/algorithm audit. Use when 22/ssh is open.",
    "subzy": "Subdomain-takeover check for discovered subdomains. Use after subdomain enumeration.",
    "swaks_relay": "SMTP open-relay / delivery check for a mail server. Use when SMTP is open.",
    "corsy": "CORS misconfiguration scanner for a URL.",
    "wapiti": "Active web vulnerability scanner — sends payloads (gated). Broad web app coverage.",
    "xsstrike": "Active XSS discovery & fuzzing for a URL (gated).",
    "xsrfprobe": "Active CSRF audit for a web app (gated).",
    # exploitation (attack agent, human-gated)
    "sqlmap": "SQL-injection exploitation for a parameterized URL. ATTACK only, human-gated.",
    "ghauri": "SQL-injection exploitation (fast). ATTACK only, human-gated.",
    "commix": "Command-injection exploitation for a URL. ATTACK only, human-gated.",
    "sstimap": "Server-side template injection exploitation. ATTACK only, human-gated.",
    "dotdotpwn": "Path-traversal fuzzer. ATTACK only, human-gated.",
    "fuxploider": "File-upload vulnerability exploitation. ATTACK only, human-gated.",
    "nosqlmap": "NoSQL-injection exploitation. ATTACK only, human-gated.",
    "hydra": "Online credential brute force across many protocols. ATTACK only, human-gated.",
    "medusa": "Online credential brute force (parallel). ATTACK only, human-gated.",
    "responder": "LLMNR/NBT-NS/mDNS poisoning (MITM). Policy-DENIED — never auto-runs.",
    "mitm6": "IPv6 DNS takeover (MITM). Policy-DENIED — never auto-runs.",
    "bettercap": "Network MITM framework. Policy-DENIED — never auto-runs.",
    "ettercap": "ARP/MITM interception. Policy-DENIED — never auto-runs.",
    "beef": "Browser exploitation framework (C2). Policy-DENIED — never auto-runs.",
    "sliver": "Adversary C2 framework. Policy-DENIED — never auto-runs.",
    # post-exploitation (attack agent)
    "netexec_smb": "Authenticated SMB enumeration/execution with creds. ATTACK only, human-gated.",
    "impacket_secretsdump": "Dump secrets (SAM/LSA/NTDS) with creds. ATTACK only, human-gated.",
    "lsassy": "Remote LSASS credential extraction with creds. ATTACK only, human-gated.",
    "bloodyad": "Active Directory object read/modify with creds. ATTACK only, human-gated.",
    "certipy_find": "AD CS (ADCS) certificate template and CA enumeration — finds ESC1-ESC8 misconfigurations. Use when LDAP is open and domain creds available.",
    "chisel": "TCP/UDP tunnel for pivoting. ATTACK only, human-gated.",
    "ligolo_proxy": "Reverse tunnel/pivot proxy. ATTACK only, human-gated.",
    "krbrelayx": "Kerberos relay/unconstrained-delegation abuse. Policy-DENIED — never auto-runs.",
    # hash cracking (offline, local)
    "hashcat_kerberoast": "Offline crack of Kerberoast TGS hashes (mode 13100). Run after impacket_getuserspns finds service accounts with SPNs. P0 local-only.",
    "hashcat_asrep": "Offline crack of AS-REP hashes (mode 18200). Run after impacket_getnpusers finds accounts without pre-auth. P0 local-only.",
    "john_kerberoast": "Offline crack of Kerberoast TGS hashes (krb5tgs format). Alternative to hashcat_kerberoast when no GPU available. P0 local-only.",
    "john_asrep": "Offline crack of AS-REP hashes (krb5asrep format). Alternative to hashcat_asrep when no GPU available. P0 local-only.",
    # coercion checks
    "coercer_scan": "Scan for authentication coercion vectors (PetitPotam, PrinterBug, DFSCoerce, ShadowCoerce, MS-EFSRPC) on a target. Identifies which coercion methods the DC is vulnerable to. Use when SMB/RPC is open and domain creds available.",
    "nxc_petitpotam": "Check if target is vulnerable to PetitPotam (MS-EFSRPC) coercion. Enables NTLM relay to ADCS for domain compromise. P2 human-gated.",
    "nxc_printerbug": "Check if target has the Print Spooler service enabled (PrinterBug/SpoolSample). Enables NTLM relay via forced authentication. P2 human-gated.",
    "nxc_shadowcoerce": "Check if target is vulnerable to ShadowCoerce (MS-FSRVP) coercion. Another NTLM relay trigger vector. P2 human-gated.",
    "nxc_dfscoerce": "Check if target is vulnerable to DFSCoerce (MS-DFSNM) coercion. Another NTLM relay trigger vector. P2 human-gated.",
    # ADCS exploitation
    "certipy_req": "Request a certificate from an ADCS CA — used to exploit ESC1-ESC8 template vulnerabilities found by certipy_find/certipy_analyzer. ATTACK only, human-gated.",
    "certipy_auth": "Authenticate with a PFX certificate obtained via certipy_req. Converts cert to NTLM hash for pass-the-hash. ATTACK only, human-gated.",
    # Kerberos ticket / delegation exploitation
    "impacket_getst": "Request a service ticket (S4U2Self/S4U2Proxy) — used for constrained delegation and RBCD exploitation. ATTACK only, human-gated.",
    "impacket_gettgt": "Request a TGT with known credentials or NTLM hash. First step for Kerberos-based attacks (pass-the-hash, overpass-the-hash). ATTACK only, human-gated.",
    "impacket_ticketer": "Forge Kerberos tickets (golden/silver). ATTACK only, human-gated.",
    "impacket_describeticket": "Parse and describe a Kerberos ticket (.ccache/.kirbi). Useful for analyzing captured/forged tickets. P0 local-only.",
    # lateral movement / remote execution
    "impacket_psexec": "Remote command execution via SMB service creation (creates a service, drops a binary). Noisiest but most reliable. ATTACK only, human-gated.",
    "impacket_wmiexec": "Remote command execution via WMI (semi-interactive shell). Stealthier than psexec. ATTACK only, human-gated.",
    "impacket_smbexec": "Remote command execution via SMB (similar to psexec but uses a batch file). ATTACK only, human-gated.",
    "impacket_atexec": "Remote command execution via Windows Task Scheduler (AT protocol). ATTACK only, human-gated.",
    "impacket_dcomexec": "Remote command execution via DCOM (MMC20, ShellWindows, ShellBrowserWindow). ATTACK only, human-gated.",
    # RBCD / delegation abuse
    "impacket_rbcd": "Read/write Resource-Based Constrained Delegation (msDS-AllowedToActOnBehalfOfOtherIdentity). Use to check or exploit RBCD delegation paths found by bloodhound_analyzer. ATTACK only, human-gated.",
    # LAPS / gMSA
    "nxc_laps": "Read LAPS (Local Administrator Password Solution) passwords from AD. Retrieves local admin passwords if the authenticated user has read access. ATTACK only, human-gated.",
    "nxc_gmsa": "Read gMSA (Group Managed Service Account) passwords from AD. Retrieves service account NTLM hashes if the authenticated user has read access. ATTACK only, human-gated.",
    # NTLM relay
    "impacket_ntlmrelayx": "NTLM relay server — relays captured NTLM authentication to a target. Used with coercion tools (PetitPotam/PrinterBug) for ADCS relay (ESC8), RBCD write, or shadow credentials. Policy-DENIED — runs only under auto-approve.",
    # cross-domain trust
    "nxc_trusts": "Enumerate AD trust relationships (forest, external, parent-child trusts) and their properties (direction, transitivity, SID filtering). Use when LDAP is open and domain creds available.",
}


# --------------------------------------------------------------------------- #
# Register every catalog row that isn't already a built-in tool, and index the ids by agent
# so the manifests can offer them to the right phase.
# --------------------------------------------------------------------------- #
CATALOG_IDS_BY_AGENT: dict[AgentRole, list[str]] = {_RE: [], _SC: [], _VA: [], _AT: [], _AN: []}


def _describe(tool_id: str, cls: PolicyClass) -> str:
    base = _PURPOSE.get(tool_id)
    return base if base else f"Catalog tool {tool_id} ({cls.value})."


def _load() -> None:
    for row in CATALOG:
        tool_id, bins, tmpl, cls, agents, tkind = row[0], row[1], row[2], row[3], row[4], row[5]
        oks = row[6] if len(row) > 6 else (0,)
        tool_timeout = row[7] if len(row) > 7 else 600
        for ag in agents:
            CATALOG_IDS_BY_AGENT.setdefault(ag, [])
            if tool_id not in CATALOG_IDS_BY_AGENT[ag]:
                CATALOG_IDS_BY_AGENT[ag].append(tool_id)
        if tool_id in REGISTRY._tools:          # don't shadow a built-in of the same id
            continue
        REGISTRY.register(ToolSpec(
            id=tool_id, version="catalog-1", policy_class=cls, allowed_agents=list(agents),
            supported_modes=list(_MODES), build_argv=_mk_build(tool_id, bins, tmpl),
            timeout_s=tool_timeout, ok_exit_codes=tuple(oks), target_kind=tkind,
            description=_describe(tool_id, cls),
        ))


def tool_ids_for(agent: AgentRole) -> list[str]:
    """Catalog tool ids an agent may use — for extending that agent's manifest."""
    return list(CATALOG_IDS_BY_AGENT.get(agent, []))


_load()
