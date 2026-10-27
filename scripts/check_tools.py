#!/usr/bin/env python3
"""check_tools.py — report which of the pentest-tool catalog is installed on this host.

Groups by phase, prints INSTALLED / missing, and a summary. Also flags Windows-only tools
(run from a Windows target, not this box), reference/data entries (no binary), and API
services. Pure stdlib; safe to run anywhere.

    python3 scripts/check_tools.py            # full report
    python3 scripts/check_tools.py --missing  # only what's missing (install TODO)
"""
from __future__ import annotations
import shutil, sys, os

# (display name, [candidate binaries], kind)  kind: bin|script|api|module|data|win
CATALOG = {
 "1. Recon & Asset Discovery": [
  ("Amass",["amass"],"bin"),("Subfinder",["subfinder"],"bin"),("assetfinder",["assetfinder"],"bin"),
  ("asnmap",["asnmap"],"bin"),("metabigor",["metabigor"],"bin"),("Shodan CLI",["shodan"],"api"),
  ("uncover",["uncover"],"api"),("theHarvester",["theHarvester","theharvester"],"bin"),
  ("Recon-ng",["recon-ng"],"bin"),("SpiderFoot",["spiderfoot","sf"],"bin"),("dnsx",["dnsx"],"bin"),
  ("dnsrecon",["dnsrecon"],"bin"),("httpx",["httpx"],"bin"),("Katana",["katana"],"bin"),
  ("waybackurls",["waybackurls"],"bin"),("gau",["gau"],"bin"),("ParamSpider",["paramspider"],"bin"),
  ("LinkFinder",["linkfinder","LinkFinder.py"],"script"),("git-dumper",["git-dumper"],"bin"),
  ("WhatWeb",["whatweb"],"bin"),("wafw00f",["wafw00f"],"bin"),("EyeWitness",["eyewitness","EyeWitness"],"bin"),
  ("ExifTool",["exiftool"],"bin"),("whois",["whois"],"bin"),("dig",["dig"],"bin"),("nslookup",["nslookup"],"bin"),
  ("Sublist3r",["sublist3r"],"bin"),("Wappalyzer CLI",["wappalyzer"],"bin"),("S3Scanner",["s3scanner","S3Scanner"],"bin"),
  ("DNSDumpster",[],"api"),("OSINT Framework",[],"data"),("Google Dorks/GHDB",[],"data"),
 ],
 "2. Scanning & Enumeration": [
  ("Nmap",["nmap"],"bin"),("Masscan",["masscan"],"bin"),("Naabu",["naabu"],"bin"),
  ("Netdiscover",["netdiscover"],"bin"),("Gobuster",["gobuster"],"bin"),("ffuf",["ffuf"],"bin"),
  ("feroxbuster",["feroxbuster"],"bin"),("dirb",["dirb"],"bin"),("dirsearch",["dirsearch"],"bin"),
  ("wfuzz",["wfuzz"],"bin"),("kiterunner",["kr","kiterunner"],"bin"),("Arjun",["arjun"],"bin"),
  ("graphw00f",["graphw00f"],"bin"),("smbmap",["smbmap"],"bin"),("enum4linux-ng",["enum4linux-ng","enum4linux"],"bin"),
  ("windapsearch",["windapsearch"],"bin"),("ldapdomaindump",["ldapdomaindump"],"bin"),("adPEAS",["adpeas","adPEAS"],"script"),
  ("Kerbrute",["kerbrute"],"bin"),("onesixtyone",["onesixtyone"],"bin"),("BloodHound CE",["bloodhound","bloodhound-python","bloodhound-ce-python"],"bin"),
  ("SecLists",[],"data"),("CeWL",["cewl"],"bin"),("smtp-user-enum",["smtp-user-enum"],"bin"),
  ("smbclient",["smbclient"],"bin"),("ldapsearch",["ldapsearch"],"bin"),
 ],
 "3. Vulnerability Assessment": [
  ("Nuclei",["nuclei"],"bin"),("OpenVAS/Greenbone",["gvm-cli","openvas","gvmd"],"bin"),("Vuls",["vuls"],"bin"),
  ("Nikto",["nikto"],"bin"),("OWASP ZAP",["zap.sh","zaproxy","zap-baseline.py"],"bin"),("Wapiti",["wapiti"],"bin"),
  ("WPScan",["wpscan"],"bin"),("CMSeeK",["cmseek","CMSeeK"],"bin"),("JoomScan",["joomscan"],"bin"),
  ("droopescan",["droopescan"],"bin"),("CMSmap",["cmsmap"],"bin"),("magescan",["magescan"],"bin"),
  ("XSStrike",["xsstrike","XSStrike"],"bin"),("Corsy",["corsy"],"script"),("CORScanner",["cors","corscanner"],"script"),
  ("XSRFProbe",["xsrfprobe"],"bin"),("Bolt",["bolt"],"script"),("jwt_tool",["jwt_tool","jwt_tool.py"],"script"),
  ("graphql-cop",["graphql-cop"],"bin"),("shcheck",["shcheck","shcheck.py"],"bin"),("humble",["humble","humble.py"],"script"),
  ("interactsh",["interactsh-client"],"bin"),("testssl.sh",["testssl.sh"],"bin"),("sslyze",["sslyze"],"bin"),
  ("ssh-audit",["ssh-audit"],"bin"),("Lynis",["lynis"],"bin"),("trufflehog",["trufflehog"],"bin"),
  ("gitleaks",["gitleaks"],"bin"),("subzy",["subzy"],"bin"),("PingCastle",["PingCastle.exe"],"win"),
  ("CSP Evaluator",[],"api"),("openssl",["openssl"],"bin"),("swaks",["swaks"],"bin"),
 ],
 "4. Exploitation": [
  ("Metasploit",["msfconsole","msfrpcd"],"bin"),("sqlmap",["sqlmap"],"bin"),("Ghauri",["ghauri"],"bin"),
  ("NoSQLMap",["nosqlmap","NoSQLMap"],"bin"),("Commix",["commix"],"bin"),("SSRFmap",["ssrfmap"],"script"),
  ("Gopherus",["gopherus"],"script"),("SSTImap",["sstimap"],"script"),("XXEinjector",["xxeinjector"],"script"),
  ("dotdotpwn",["dotdotpwn"],"bin"),("ysoserial",["ysoserial","ysoserial.jar"],"bin"),("Fuxploider",["fuxploider"],"script"),
  ("Upload_Bypass",["upload_bypass"],"script"),("BeEF",["beef"],"bin"),("RouterSploit",["rsf","routersploit"],"bin"),
  ("Pwntools",["pwn"],"module"),("Hydra",["hydra"],"bin"),("Medusa",["medusa"],"bin"),("Hashcat",["hashcat"],"bin"),
  ("John",["john"],"bin"),("Responder",["responder","Responder.py"],"bin"),("mitm6",["mitm6"],"bin"),
  ("Coercer",["coercer"],"bin"),("Certipy",["certipy","certipy-ad"],"bin"),("Bettercap",["bettercap"],"bin"),
  ("Ncat/Netcat",["ncat","nc"],"bin"),("curl",["curl"],"bin"),("tcpdump",["tcpdump"],"bin"),
  ("Ettercap",["ettercap"],"bin"),("searchsploit",["searchsploit"],"bin"),("PayloadsAllTheThings",[],"data"),
 ],
 "5. Post-Exploitation": [
  ("LinPEAS/WinPEAS",["linpeas.sh","winpeas.exe"],"script"),("Linux Exploit Suggester",["linux-exploit-suggester.sh","les.sh"],"script"),
  ("pspy",["pspy","pspy64"],"bin"),("GTFOBins/LOLBAS",[],"data"),("Mimikatz",["mimikatz.exe"],"win"),
  ("Rubeus",["Rubeus.exe"],"win"),("PowerSploit/PowerView",["PowerView.ps1"],"win"),("BloodyAD",["bloodyAD","bloodyad"],"bin"),
  ("krbrelayx",["krbrelayx","krbrelayx.py"],"script"),("NetExec",["nxc","netexec"],"bin"),
  ("Impacket",["impacket-secretsdump","secretsdump.py","impacket-ntlmrelayx"],"bin"),("Pupy",["pupy"],"bin"),
  ("Sliver",["sliver-client","sliver-server","sliver"],"bin"),("chisel",["chisel"],"bin"),
  ("ligolo-ng",["ligolo-proxy","proxy","agent"],"bin"),("Lsassy",["lsassy"],"bin"),
  ("PrintSpoofer",["PrintSpoofer.exe"],"win"),("Group3r",["Group3r.exe","group3r"],"bin"),
 ],
}

def found(cands):
    for c in cands:
        if shutil.which(c): return c
    # also check a couple of common opt locations for scripts
    for c in cands:
        for base in ("/opt","/usr/share","/usr/local/bin",os.path.expanduser("~")):
            p=os.path.join(base,c)
            if os.path.exists(p): return p
    return None

only_missing = "--missing" in sys.argv
tot=inst=0; miss=[]
for phase, tools in CATALOG.items():
    lines=[]
    for name,cands,kind in tools:
        if kind in ("data","api","win"):
            tag={"data":"ref/data","api":"API svc","win":"windows-only"}[kind]
            lines.append(("skip",f"  ·  {name:<26} [{tag}]"))
            continue
        tot+=1
        hit=found(cands)
        if hit:
            inst+=1
            if not only_missing: lines.append(("ok",f"  \033[92m✓\033[0m {name:<26} {hit}"))
        else:
            miss.append((phase,name,cands))
            lines.append(("no",f"  \033[91m✗\033[0m {name:<26} (install: {cands[0] if cands else '?'})"))
    shown=[t for k,t in lines if not (only_missing and k=='ok')]
    if shown:
        print(f"\n\033[1m{phase}\033[0m")
        for t in shown: print(t)

print(f"\n{'='*50}\nInstalled {inst}/{tot} installable tools  ·  {len(miss)} missing")
