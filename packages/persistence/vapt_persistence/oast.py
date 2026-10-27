"""OAST (Out-of-band Application Security Testing) coordinator.

Blind SSRF / blind XXE / blind SSTI / blind RCE need an EXTERNAL callback server to
confirm — the exploited target makes a DNS/HTTP request to a canary host, we observe the
callback, we have proof. The in-band `vapt-web-probe` detector cannot cover these: no
echo in the response body means the probe gives up as "no vuln", missing real blind-only
findings.

This module coordinates a per-run interactsh session:
  1. `obtain_oast_handle(run_id)` — spin up an interactsh-client subprocess (or reuse
     a cached session), capture its unique callback domain, store in Redis.
  2. `canary_url(run_id, label)` — build a unique OAST URL (`{label}.{session}.oast.site`)
     for a probe to inject into a payload.
  3. `collect_callbacks(run_id)` — poll the session's log, return any inbound HTTP/DNS
     hits since the last call. Correlate by the `label` subdomain.
  4. `release_oast_handle(run_id)` — tear down the session when the webvuln phase ends.

Fail-safe: any Redis / subprocess / network issue degrades the probe to its old in-band
behaviour (same as today). Nothing OAST-related ever blocks a scan.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import time

_PREFIX = "vapt:oast:"
_DEFAULT_TTL = int(os.environ.get("VAPT_OAST_TTL", "3600"))


def _client():
    import redis
    return redis.Redis.from_url(
        os.environ.get("VAPT_REDIS_URL", "redis://localhost:6379/0"),
        socket_timeout=3,
    )


def _bin() -> str | None:
    """Resolve interactsh-client binary (installed via `go install
    github.com/projectdiscovery/interactsh/...`). Overridable via VAPT_INTERACTSH_BIN
    for operators who ship it elsewhere."""
    override = os.environ.get("VAPT_INTERACTSH_BIN", "").strip()
    if override and os.path.isfile(override):
        return override
    cand = shutil.which("interactsh-client") or os.path.expanduser(
        "~/go/bin/interactsh-client")
    return cand if cand and os.path.isfile(cand) else None


def obtain_oast_handle(run_id: str) -> dict | None:
    """Start (or reuse) an interactsh session for this run. Returns {domain, pid, log_file}
    or None if interactsh isn't installed. Fail-safe: never raises — any issue returns
    None and the probes degrade to in-band only."""
    if not run_id:
        return None
    bin_path = _bin()
    if not bin_path:
        return None
    try:
        r = _client()
        cached = r.get(_PREFIX + run_id)
        if cached:
            return json.loads(cached)
        # Fresh session: run interactsh-client in -json -poll-interval 2s to dump every
        # callback as a JSON line to a log file we tail later. The session domain is
        # printed on stderr/stdout at startup; we parse the first "with id XYZ.oast.site"
        # line to extract it.
        log_path = f"/tmp/vapt-oast-{run_id}.jsonl"
        # Clean any prior log file from an earlier run with the same run_id.
        try:
            os.remove(log_path)
        except FileNotFoundError:
            pass
        # Open with append so the subprocess can write while we tail.
        logf = open(log_path, "a+")
        proc = subprocess.Popen(
            [bin_path, "-json", "-o", log_path, "-poll-interval", "2"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL, text=True, bufsize=1,
        )
        # Parse the first few lines to grab the session domain. interactsh prints
        # "Listing 1 payload for OOB Testing" then "payload-id.oast.fun" etc.
        session_domain = None
        deadline = time.time() + 15
        while time.time() < deadline and session_domain is None:
            line = proc.stdout.readline() if proc.stdout else ""
            if not line:
                break
            # Match any .oast.* domain emitted at startup.
            import re
            m = re.search(r"\b([a-z0-9]{20,}\.oast\.[a-z]+)\b", line)
            if m:
                session_domain = m.group(1).lower()
        if not session_domain:
            # interactsh didn't give us a domain — kill it and give up quietly.
            try:
                proc.terminate()
            except Exception:
                pass
            logf.close()
            return None
        handle = {"domain": session_domain, "pid": proc.pid, "log_file": log_path}
        r.set(_PREFIX + run_id, json.dumps(handle), ex=_DEFAULT_TTL)
        return handle
    except Exception:
        return None


def canary_url(run_id: str, label: str) -> str | None:
    """Build an http://{label}.{session}.oast.site style URL to inject into a payload.
    Returns None if no session was obtained. The `label` must be a short alphanumeric
    tag the normalizer can scan for in the callback log to correlate."""
    if not run_id or not label:
        return None
    try:
        r = _client()
        raw = r.get(_PREFIX + run_id)
        if not raw:
            return None
        h = json.loads(raw)
        safe = "".join(c for c in str(label).lower() if c.isalnum() or c in "-")[:32]
        if not safe:
            return None
        return f"http://{safe}.{h['domain']}/"
    except Exception:
        return None


def collect_callbacks(run_id: str, since_ts: float = 0) -> list[dict]:
    """Return every callback JSON line in the session log since `since_ts`. Each entry
    has `remote-address`, `protocol`, `full-id`, `timestamp`, etc. Caller correlates by
    inspecting `full-id` for the label it injected."""
    if not run_id:
        return []
    try:
        r = _client()
        raw = r.get(_PREFIX + run_id)
        if not raw:
            return []
        h = json.loads(raw)
        log_path = h.get("log_file", "")
        if not log_path or not os.path.isfile(log_path):
            return []
        out: list[dict] = []
        with open(log_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except Exception:
                    continue
                ts = entry.get("timestamp", "")
                # Soft since-filter (interactsh timestamps are RFC3339 strings; we don't
                # strictly parse — the caller usually just wants "everything so far").
                if since_ts and ts and ts < since_ts:
                    continue
                out.append(entry)
        return out
    except Exception:
        return []


def release_oast_handle(run_id: str) -> None:
    """Terminate the interactsh subprocess and drop the Redis handle. Best-effort — a
    dead subprocess or missing handle doesn't raise. Called when the webvuln phase ends
    so OAST state (which includes a subprocess + log file) doesn't outlive the scan."""
    if not run_id:
        return
    try:
        r = _client()
        raw = r.get(_PREFIX + run_id)
        if raw:
            h = json.loads(raw)
            pid = h.get("pid")
            if pid:
                try:
                    os.kill(int(pid), 15)  # SIGTERM
                except Exception:
                    pass
            lf = h.get("log_file", "")
            if lf and os.path.isfile(lf):
                try:
                    os.remove(lf)
                except Exception:
                    pass
        r.delete(_PREFIX + run_id)
    except Exception:
        return
