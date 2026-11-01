"""Manual verification tools — LLM test, reachability, nmap, DNS."""
from __future__ import annotations

import asyncio
import os
import re
import shutil
import time
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from vapt_domain.enums import Role
from ..deps import CurrentUser, get_current_user

router = APIRouter(prefix="/api/v2/tools", tags=["tools"])

_PRIVATE_RANGES = re.compile(
    r"^(127\.|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|0\.0\.0\.0|::1|localhost)"
)

_SAFE_HOST = re.compile(r"^[a-zA-Z0-9._:-]+$")


def _validate_target(target: str) -> str:
    """Validate and extract a host from user input. Blocks obviously bad input."""
    target = target.strip()
    if not target:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "target is required")
    if len(target) > 500:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "target too long")
    parsed = urlparse(target if "://" in target else f"http://{target}")
    host = parsed.hostname or target
    if not _SAFE_HOST.match(host):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "invalid target characters")
    return host


# --------------------------------------------------------------------------- #
#  LLM connection test                                                         #
# --------------------------------------------------------------------------- #

class LLMTestResult(BaseModel):
    connected: bool
    provider: str = ""
    model: str = ""
    endpoint: str = ""
    response_text: str = ""
    latency_ms: int = 0
    error: str = ""
    profiles: list[str] = []


@router.post("/llm-test", response_model=LLMTestResult)
def test_llm(
    user: CurrentUser = Depends(get_current_user),
) -> LLMTestResult:
    """Send a short test prompt to the configured LLM and report status."""
    try:
        from vapt_llm import LLMGateway, profiles_from_env
        profiles = profiles_from_env()
    except Exception as exc:
        return LLMTestResult(
            connected=False,
            provider=os.environ.get("VAPT_LLM_PROVIDER", ""),
            model=os.environ.get("VAPT_LLM_MODEL", ""),
            endpoint=os.environ.get("VAPT_LLM_BASE_URL", ""),
            error=f"Failed to load LLM profiles: {exc}",
        )

    profile_names = list(profiles.keys())
    profile_id = profile_names[0] if profile_names else "default"
    cfg = profiles.get(profile_id)
    if cfg is None:
        return LLMTestResult(connected=False, profiles=profile_names, error="No profiles configured")

    gateway = LLMGateway(profiles)
    started = time.time()
    try:
        resp = gateway.invoke(
            profile_id=profile_id,
            messages=[{"role": "user", "content": "Reply with exactly: CONNECTION_OK"}],
        )
        latency = int((time.time() - started) * 1000)
        if resp.error:
            return LLMTestResult(
                connected=False, provider=cfg.provider, model=cfg.model_id,
                endpoint=cfg.endpoint or "", latency_ms=latency,
                error=resp.error, profiles=profile_names,
            )
        return LLMTestResult(
            connected=True, provider=cfg.provider, model=cfg.model_id,
            endpoint=cfg.endpoint or "", response_text=resp.text[:200],
            latency_ms=latency, profiles=profile_names,
        )
    except Exception as exc:
        latency = int((time.time() - started) * 1000)
        return LLMTestResult(
            connected=False, provider=cfg.provider, model=cfg.model_id,
            endpoint=cfg.endpoint or "", latency_ms=latency,
            error=str(exc)[:300], profiles=profile_names,
        )


# --------------------------------------------------------------------------- #
#  Reachability check (ping + HTTP probe)                                      #
# --------------------------------------------------------------------------- #

class ReachabilityResult(BaseModel):
    target: str
    reachable: bool
    ping_ok: bool = False
    ping_latency_ms: float | None = None
    http_ok: bool = False
    http_status: int | None = None
    http_title: str = ""
    http_server: str = ""
    http_latency_ms: int | None = None
    dns_resolved: str = ""
    error: str = ""


@router.post("/reachability", response_model=ReachabilityResult)
async def check_reachability(
    body: dict,
    user: CurrentUser = Depends(get_current_user),
) -> ReachabilityResult:
    """Check if a target IP or URL is reachable via ping and HTTP."""
    raw = body.get("target", "")
    host = _validate_target(raw)
    result = ReachabilityResult(target=host, reachable=False)

    # DNS lookup
    try:
        proc = await asyncio.create_subprocess_exec(
            "getent", "hosts", host,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
        if stdout:
            result.dns_resolved = stdout.decode().strip().split()[0]
    except Exception:
        pass

    # Ping (3 packets, 2s timeout)
    try:
        proc = await asyncio.create_subprocess_exec(
            "ping", "-c", "3", "-W", "2", host,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
        output = stdout.decode()
        if proc.returncode == 0:
            result.ping_ok = True
            result.reachable = True
            m = re.search(r"rtt min/avg/max/mdev = [\d.]+/([\d.]+)/", output)
            if m:
                result.ping_latency_ms = float(m.group(1))
    except Exception:
        pass

    # HTTP probe
    url = raw if "://" in raw else f"http://{host}"
    try:
        import httpx
        started = time.time()
        async with httpx.AsyncClient(timeout=10, follow_redirects=True, verify=False) as client:
            resp = await client.get(url)
            result.http_latency_ms = int((time.time() - started) * 1000)
            result.http_ok = resp.status_code < 500
            result.http_status = resp.status_code
            result.http_server = resp.headers.get("server", "")
            result.reachable = True
            m = re.search(r"<title[^>]*>([^<]+)</title>", resp.text[:2000], re.IGNORECASE)
            if m:
                result.http_title = m.group(1).strip()[:100]
    except Exception:
        pass

    if not result.reachable:
        result.error = f"Host {host} is not reachable via ping or HTTP"

    return result


# --------------------------------------------------------------------------- #
#  Nmap scan                                                                   #
# --------------------------------------------------------------------------- #

class NmapResult(BaseModel):
    target: str
    command: str = ""
    open_ports: list[dict] = []
    os_guess: str = ""
    raw_output: str = ""
    latency_ms: int = 0
    error: str = ""


@router.post("/nmap", response_model=NmapResult)
async def run_nmap(
    body: dict,
    user: CurrentUser = Depends(get_current_user),
) -> NmapResult:
    """Run a basic nmap scan on a target. Analyst+ only."""
    raw = body.get("target", "")
    host = _validate_target(raw)
    scan_type = body.get("scan_type", "quick")
    ports = body.get("ports", "")

    if not shutil.which("nmap"):
        return NmapResult(target=host, error="nmap is not installed on the server")

    args = ["nmap"]
    if scan_type == "quick":
        args += ["-T4", "-F", host]
    elif scan_type == "top100":
        args += ["-T4", "--top-ports", "100", host]
    elif scan_type == "full":
        args += ["-T4", "-p-", host]
    elif scan_type == "service":
        args += ["-T4", "-sV", "-F", host]
    elif scan_type == "custom" and ports:
        safe_ports = re.sub(r"[^0-9,\-]", "", ports)[:50]
        args += ["-T4", "-p", safe_ports, host]
    else:
        args += ["-T4", "-F", host]

    cmd_str = " ".join(args)
    result = NmapResult(target=host, command=cmd_str)

    started = time.time()
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
        result.latency_ms = int((time.time() - started) * 1000)
        output = stdout.decode()
        result.raw_output = output[:5000]

        for line in output.splitlines():
            m = re.match(r"^(\d+)/(tcp|udp)\s+(\S+)\s+(.*)", line)
            if m:
                result.open_ports.append({
                    "port": int(m.group(1)),
                    "protocol": m.group(2),
                    "state": m.group(3),
                    "service": m.group(4).strip(),
                })

        os_match = re.search(r"OS details?:\s*(.+)", output)
        if os_match:
            result.os_guess = os_match.group(1).strip()[:200]

        if stderr:
            err = stderr.decode().strip()
            if err and not result.open_ports:
                result.error = err[:300]
    except asyncio.TimeoutError:
        result.latency_ms = int((time.time() - started) * 1000)
        result.error = "Scan timed out (120s limit)"
    except Exception as exc:
        result.latency_ms = int((time.time() - started) * 1000)
        result.error = str(exc)[:300]

    return result


# --------------------------------------------------------------------------- #
#  DNS lookup                                                                  #
# --------------------------------------------------------------------------- #

class DNSResult(BaseModel):
    target: str
    records: list[dict] = []
    error: str = ""


@router.post("/dns", response_model=DNSResult)
async def dns_lookup(
    body: dict,
    user: CurrentUser = Depends(get_current_user),
) -> DNSResult:
    """Perform a DNS lookup for a target hostname."""
    raw = body.get("target", "")
    host = _validate_target(raw)
    result = DNSResult(target=host)

    dig = shutil.which("dig")
    nslookup = shutil.which("nslookup")
    tool = dig or nslookup

    if not tool:
        result.error = "Neither dig nor nslookup is installed"
        return result

    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]

    if dig:
        for rtype in record_types:
            try:
                proc = await asyncio.create_subprocess_exec(
                    dig, "+short", host, rtype,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
                lines = [l.strip() for l in stdout.decode().splitlines() if l.strip()]
                for val in lines:
                    result.records.append({"type": rtype, "value": val[:200]})
            except Exception:
                pass
    else:
        try:
            proc = await asyncio.create_subprocess_exec(
                nslookup, host,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            for line in stdout.decode().splitlines():
                line = line.strip()
                if line.startswith("Address:") and not line.endswith("#53"):
                    result.records.append({"type": "A", "value": line.split(":", 1)[1].strip()})
                elif line.startswith("Name:"):
                    result.records.append({"type": "CNAME", "value": line.split(":", 1)[1].strip()})
        except Exception as exc:
            result.error = str(exc)[:200]

    if not result.records and not result.error:
        result.error = f"No DNS records found for {host}"

    return result
