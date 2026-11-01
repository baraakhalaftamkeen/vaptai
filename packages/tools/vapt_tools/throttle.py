"""Per-target politeness throttle for the tool broker.

Problem this exists to solve: a target host (especially a single-threaded dev server) can
become unresponsive after a sequence of heavy scanners run back-to-back against it, because
sockets aren't closed fast enough and the server queues up requests. The next tool then
appears to hang — not because the tool is broken, but because the target has wedged under
cumulative load. Giving the target a short breather BETWEEN tools lets it recover without
changing anything the tools themselves do.

Mechanism — a politeness gap per TARGET HOST, coordinated via Redis so it works across
workers and runs:
  * before executing a tool against host X, ensure at least `VAPT_TARGET_MIN_GAP_MS` have
    passed since the previous tool against X finished;
  * if the previous tool was "heavy" (ran longer than `VAPT_TARGET_HEAVY_THRESHOLD_S`),
    extend the gap by `VAPT_TARGET_HEAVY_COOLDOWN_MS` on top — e.g. after a 3-minute nikto
    we pause ~2s before the next tool hits the same host.
  * after each tool execution (whether ok/failed/timeout), record its finish time and
    elapsed seconds under `vapt:throttle:<host>` so later calls can honour the gap.

Fail-open: if Redis isn't reachable the throttle silently no-ops. The broker's own
subprocess timeout is still the safety net, so politeness is a best-effort courtesy, not
a correctness invariant.

Disable entirely with `VAPT_TARGET_THROTTLE_DISABLED=1` (unit tests, debugging).

Env knobs (all optional):
  VAPT_REDIS_URL                 redis://localhost:6379/0 (reused from the rest of the app)
  VAPT_TARGET_MIN_GAP_MS         300   — minimum gap between back-to-back tools
  VAPT_TARGET_HEAVY_THRESHOLD_S  60    — a tool longer than this triggers the cooldown
  VAPT_TARGET_HEAVY_COOLDOWN_MS  2000  — extra gap after a heavy tool
  VAPT_TARGET_THROTTLE_DISABLED  "1" to switch off
"""
from __future__ import annotations

import json
import os
import time
from urllib.parse import urlparse

_PREFIX = "vapt:throttle:"
_KEY_TTL_SECONDS = 3600       # politeness state auto-expires an hour after the last tool


def _env_int(name: str, default: int) -> int:
    try:
        return max(0, int(os.environ.get(name, default)))
    except (TypeError, ValueError):
        return default


def _client():
    # Imported lazily so a deployment without the redis lib still imports this module.
    import redis  # type: ignore
    return redis.Redis.from_url(
        os.environ.get("VAPT_REDIS_URL", "redis://localhost:6379/0"),
        socket_timeout=1.0,
        socket_connect_timeout=0.5,
        decode_responses=True,
    )


def _extract_host(args: dict) -> str | None:
    """The host politeness is keyed on. Prefers `url`'s hostname (an explicit endpoint),
    falls back to the generic `target` field; returns None if neither looks like a host."""
    url = str(args.get("url", "")).strip()
    if url.lower().startswith(("http://", "https://")):
        host = urlparse(url).hostname
        if host:
            return host.lower()
    tgt = str(args.get("target", "")).strip()
    if tgt and not tgt.startswith("-"):      # option-like value is never a host
        return tgt.lower()
    return None


def _disabled() -> bool:
    return os.environ.get("VAPT_TARGET_THROTTLE_DISABLED", "").strip() == "1"


def _waf_multiplier(host: str) -> float:
    """Gap 6 — rate-adaptive: check if a WAF was detected for this host and return a
    throttle multiplier. A WAF-protected host gets 3x the normal gap to avoid blocks."""
    try:
        c = _client()
        raw = c.get("vapt:waf:" + host)
    except Exception:
        return 1.0
    if raw:
        return 3.0
    return 1.0


def _error_backoff(host: str) -> float:
    """Gap 6 — rate-adaptive: check recent error rate. If the target returned many errors
    (5xx, timeouts) recently, back off with an exponential factor."""
    try:
        c = _client()
        err_count = int(c.get("vapt:errors:" + host) or 0)
    except Exception:
        return 1.0
    if err_count >= 5:
        return 4.0
    if err_count >= 3:
        return 2.0
    return 1.0


def record_waf(args: dict) -> None:
    """Record that a WAF was detected for this host. Called by the wafw00f normalizer
    or any tool that detects WAF-like behavior (429s, challenge pages)."""
    if _disabled():
        return
    host = _extract_host(args)
    if not host:
        return
    try:
        _client().set("vapt:waf:" + host, "1", ex=_KEY_TTL_SECONDS)
    except Exception:
        return


def record_error(args: dict) -> None:
    """Record a target error (5xx, timeout, connection reset) for adaptive backoff."""
    if _disabled():
        return
    host = _extract_host(args)
    if not host:
        return
    try:
        c = _client()
        key = "vapt:errors:" + host
        c.incr(key)
        c.expire(key, _KEY_TTL_SECONDS)
    except Exception:
        return


def wait_turn(args: dict) -> None:
    """Block (sleep) until it's polite to launch the next tool against this host.
    Gap 6: now rate-adaptive — WAF-protected hosts and error-prone targets get longer
    gaps automatically. Silent no-op if disabled, Redis is unreachable, or no host."""
    if _disabled():
        return
    host = _extract_host(args)
    if not host:
        return
    try:
        c = _client()
        raw = c.get(_PREFIX + host)
    except Exception:
        return
    if not raw:
        return
    try:
        state = json.loads(raw)
        last_end = float(state.get("last_end") or 0)
        last_elapsed = float(state.get("last_elapsed") or 0)
    except Exception:
        return

    min_gap_ms = _env_int("VAPT_TARGET_MIN_GAP_MS", 300)
    heavy_s = _env_int("VAPT_TARGET_HEAVY_THRESHOLD_S", 60)
    cooldown_ms = _env_int("VAPT_TARGET_HEAVY_COOLDOWN_MS", 2000)
    gap = min_gap_ms / 1000.0
    if last_elapsed >= heavy_s:
        gap += cooldown_ms / 1000.0

    # Gap 6: adaptive multipliers based on WAF detection and error rate
    gap *= _waf_multiplier(host)
    gap *= _error_backoff(host)

    wait = (last_end + gap) - time.time()
    if wait > 0:
        time.sleep(min(wait, 10.0))


def record_finish(args: dict, elapsed_seconds: float) -> None:
    """Record when a tool against this host finished and how long it took, so the next
    caller knows how long to wait. Silent no-op without Redis / without a host."""
    if _disabled():
        return
    host = _extract_host(args)
    if not host:
        return
    try:
        payload = json.dumps({"last_end": time.time(),
                              "last_elapsed": float(elapsed_seconds)})
        _client().set(_PREFIX + host, payload, ex=_KEY_TTL_SECONDS)
    except Exception:
        return
