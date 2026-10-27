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

from vapt_domain.enums import AgentRole, PolicyClass

from .registry import REGISTRY, ToolSpec, _valid_host

_P0, _P1, _P2, _P3 = (PolicyClass.P0_PASSIVE, PolicyClass.P1_LOW_IMPACT,
                      PolicyClass.P2_INTRUSIVE, PolicyClass.P3_EXCLUDED)
_RE, _SC, _VA, _AT = (AgentRole.RECON, AgentRole.SCAN, AgentRole.VALIDATE, AgentRole.ATTACK)
_MODES = ["black_box", "gray_box", "white_box"]

_WORDLIST_DEFAULT = "/usr/share/seclists/Discovery/Web-Content/common.txt"


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


def _mk_build(tool_id: str, bins: list[str], template: list[str]):
    env_key = "VAPT_" + tool_id.upper().replace("-", "_") + "_BIN"
    flag = _COOKIE_HEADER_FLAG.get(tool_id)

    def build(args: dict) -> list[str]:
        argv = [os.environ.get(env_key, bins[0])]
        for tok in template:
            v = _resolve(tok, args)
            if v is not None and v != "":
                argv.append(v)
        # Authenticated-scanning cookie — appended at argv build time, not plan time, so a
        # single plan item adapts to "unauth before login" vs "authed after login".
        if flag:
            cookie = os.environ.get("VAPT_WEB_LOGIN_COOKIE", "").strip()
            if cookie and not cookie.startswith("-") \
               and all(c not in cookie for c in ("\r", "\n", "\x00")):
                argv += [flag, f"Cookie: {cookie}"]
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
    ("smbmap",      ["smbmap"],       ["-H", "{target}"],                            _P1, [_SC], "network"),
    ("enum4linux_ng", ["enum4linux-ng", "enum4linux"], ["-A", "{target}"],          _P1, [_SC], "network"),
    ("smbclient_list", ["smbclient"], ["-L", "{target}", "-N"],                      _P1, [_SC], "network", (0, 1)),
    ("ldapsearch_base", ["ldapsearch"], ["-x", "-H", "ldap://{target}", "-s", "base", "-b", ""], _P1, [_SC], "network"),
    ("cewl",        ["cewl"],         ["-d", "1", "{url}"],                          _P1, [_SC], "network"),
    ("onesixtyone", ["onesixtyone"],  ["{target}"],                                  _P2, [_SC], "network"),  # SNMP community brute → gated
    ("smtp_user_enum", ["smtp-user-enum"], ["-M", "VRFY", "-U", "{wordlist}", "-t", "{target}"], _P2, [_SC], "network"),

    # --- 3. Vulnerability assessment --------------------------------------------------
    ("nikto",       ["nikto"],        ["-ask", "no", "-nointeractive", "-maxtime", "180", "-host", "{url}"], _P1, [_SC, _VA], "network", (0, 1)),  # self-cap at 3m (nikto on IIS can run until the tool timeout otherwise)
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
    ("dotdotpwn",   ["dotdotpwn"],    ["-m", "http", "-h", "{target}", "-q"],        _P2, [_AT], "network"),
    ("fuxploider",  ["fuxploider"],   ["-u", "{url}", "--not-regex", "nonexistent"], _P2, [_AT], "network"),
    ("nosqlmap",    ["nosqlmap", "NoSQLMap"], ["--url", "{url}"],                    _P2, [_AT], "network"),
    ("hydra",       ["hydra"],        ["-L", "{wordlist}", "-P", "{wordlist}", "-f", "{target}"], _P2, [_AT], "network"),
    ("medusa",      ["medusa"],       ["-U", "{wordlist}", "-P", "{wordlist}", "-h", "{target}"], _P2, [_AT], "network"),
    # P3 — registered but policy-denied (MITM / C2): catalogued, never auto-runs.
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
    ("certipy_find", ["certipy", "certipy-ad"], ["find", "-target", "{target}"],     _P2, [_AT], "network"),
    ("chisel",      ["chisel"],       ["client"],                                    _P2, [_AT], "network"),
    ("ligolo_proxy", ["ligolo-proxy"], ["-selfcert"],                               _P2, [_AT], "local"),
    ("krbrelayx",   ["krbrelayx", "krbrelayx.py"], [],                               _P3, [_AT], "network"),
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
    "certipy_find": "AD CS (ADCS) misconfiguration enumeration. ATTACK only, human-gated.",
    "chisel": "TCP/UDP tunnel for pivoting. ATTACK only, human-gated.",
    "ligolo_proxy": "Reverse tunnel/pivot proxy. ATTACK only, human-gated.",
    "krbrelayx": "Kerberos relay/unconstrained-delegation abuse. Policy-DENIED — never auto-runs.",
}


# --------------------------------------------------------------------------- #
# Register every catalog row that isn't already a built-in tool, and index the ids by agent
# so the manifests can offer them to the right phase.
# --------------------------------------------------------------------------- #
CATALOG_IDS_BY_AGENT: dict[AgentRole, list[str]] = {_RE: [], _SC: [], _VA: [], _AT: []}


def _describe(tool_id: str, cls: PolicyClass) -> str:
    base = _PURPOSE.get(tool_id)
    return base if base else f"Catalog tool {tool_id} ({cls.value})."


def _load() -> None:
    for row in CATALOG:
        tool_id, bins, tmpl, cls, agents, tkind = row[0], row[1], row[2], row[3], row[4], row[5]
        oks = row[6] if len(row) > 6 else (0,)
        for ag in agents:
            CATALOG_IDS_BY_AGENT.setdefault(ag, [])
            if tool_id not in CATALOG_IDS_BY_AGENT[ag]:
                CATALOG_IDS_BY_AGENT[ag].append(tool_id)
        if tool_id in REGISTRY._tools:          # don't shadow a built-in of the same id
            continue
        REGISTRY.register(ToolSpec(
            id=tool_id, version="catalog-1", policy_class=cls, allowed_agents=list(agents),
            supported_modes=list(_MODES), build_argv=_mk_build(tool_id, bins, tmpl),
            timeout_s=600, ok_exit_codes=tuple(oks), target_kind=tkind,
            description=_describe(tool_id, cls),
        ))


def tool_ids_for(agent: AgentRole) -> list[str]:
    """Catalog tool ids an agent may use — for extending that agent's manifest."""
    return list(CATALOG_IDS_BY_AGENT.get(agent, []))


_load()
