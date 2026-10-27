"""Ephemeral, run-scoped web-login credentials for authenticated scanning (Stage 2).

The runtime "log in?" dialog collects a test-account username/password at scan time. Those
are a live secret, so they are held ONLY here: in Redis, under a short TTL, keyed by run id.
They are NEVER written to the SQL database, the LangGraph checkpoint, the transactional
outbox, a ToolActionRecord, or the ledger — the three durable stops on the approve/resume
path carry only a decision, never the secret. The API writes the slot; the webvuln node
reads it at scan time and feeds it to wapiti's `--form-*` login via the process env; the slot
is cleared when the webvuln phase ends and TTL-expires as a backstop.

Redis is already the Celery transport (VAPT_REDIS_URL), so no new dependency. Reads fail
SAFE: any Redis problem yields "no credentials" → the scan simply runs unauthenticated,
never an error. A write failure is raised so the operator learns the credentials were not
stored (rather than silently scanning logged-out).
"""
from __future__ import annotations

import json
import os

_PREFIX = "vapt:webcreds:"
_COOKIE_PREFIX = "vapt:webcookie:"           # obtained session cookie (post-login)
# How long a submitted credential may live in Redis. Covers one run's active window; the
# node also clears it explicitly at phase end. Bounded, never indefinite. Default raised
# from 3600 → 14400 (4h) after a DineHub run that ran ~85min of webvuln phase saw its
# creds slot expire mid-phase — the IDOR plan builder (which re-runs _webvuln_plan on
# every webvuln() iteration) started returning None for `get_web_credentials_b` and the
# idor_probe plan item was dropped. 4h accommodates deep authenticated scans + buffer.
_DEFAULT_TTL = int(os.environ.get("VAPT_WEB_CREDS_TTL", "14400"))
_MAX_FIELD = 8192


def _client():
    # Imported lazily so a deployment without the redis lib still imports this module (the
    # feature then degrades to unauthenticated scanning rather than breaking startup).
    import redis

    return redis.Redis.from_url(
        os.environ.get("VAPT_REDIS_URL", "redis://localhost:6379/0"),
        socket_timeout=3,
    )


def set_web_credentials(run_id: str, username: str, password: str, *, ttl: int | None = None) -> None:
    """Stash one run's web-login credentials in the TTL slot. Raises on a bad field or a
    Redis failure so the caller (API) can tell the operator the creds were not stored."""
    if not run_id:
        raise ValueError("run_id required")
    if not username or not password:
        raise ValueError("username and password required")
    if len(username) > _MAX_FIELD or len(password) > _MAX_FIELD:
        raise ValueError("credential field too long")
    if any(c in username + password for c in ("\r", "\n", "\x00")):
        raise ValueError("credential contains control characters")
    payload = json.dumps({"u": username, "p": password})
    _client().set(_PREFIX + run_id, payload, ex=max(1, ttl if ttl is not None else _DEFAULT_TTL))


def get_web_credentials(run_id: str) -> tuple[str, str] | None:
    """Return (username, password) for this run, or None. Fails SAFE: any error → None, so
    a Redis hiccup makes the scan run unauthenticated rather than crash the graph."""
    try:
        raw = _client().get(_PREFIX + run_id)
        if not raw:
            return None
        d = json.loads(raw)
        u, p = str(d.get("u", "")), str(d.get("p", ""))
        return (u, p) if (u and p) else None
    except Exception:
        return None


def clear_web_credentials(run_id: str) -> None:
    """Delete the slot (called when the webvuln phase ends). Best-effort; TTL is the backstop."""
    try:
        _client().delete(_PREFIX + run_id)
        _client().delete(_COOKIE_PREFIX + run_id)
    except Exception:
        pass


# --- authenticated-scanning session cookie -----------------------------------
# After a webvuln pass logs in (POST creds to the discovered login_url), we cache the
# resulting session cookie so every subsequent tool in the phase reuses it instead of
# re-posting creds. Same TTL + fail-safe semantics as the credentials slot.
def set_web_cookie(run_id: str, cookie: str, *, ttl: int | None = None) -> None:
    if not run_id or not cookie:
        return
    if len(cookie) > _MAX_FIELD or any(c in cookie for c in ("\r", "\n", "\x00")):
        return
    try:
        _client().set(_COOKIE_PREFIX + run_id, cookie,
                      ex=max(1, ttl if ttl is not None else _DEFAULT_TTL))
    except Exception:
        return


def get_web_cookie(run_id: str) -> str | None:
    """Return the cached authenticated-session cookie for this run, or None."""
    try:
        raw = _client().get(_COOKIE_PREFIX + run_id)
        if not raw:
            return None
        return raw.decode() if isinstance(raw, bytes) else str(raw)
    except Exception:
        return None


def clear_web_cookie(run_id: str) -> None:
    try:
        _client().delete(_COOKIE_PREFIX + run_id)
    except Exception:
        pass


# --- SECOND account for IDOR / authz tests --------------------------------
# A run may hold TWO credential sets so the IDOR probe can act as user A AND
# user B. The second set is a SIDECAR to the primary — same TTL, same fail-safe,
# but under distinct keys (:B suffix) so clear_web_credentials wipes both.
def set_web_credentials_b(run_id: str, username: str, password: str,
                          *, ttl: int | None = None) -> None:
    if not run_id:
        raise ValueError("run_id required")
    if not username or not password:
        raise ValueError("username and password required")
    if len(username) > _MAX_FIELD or len(password) > _MAX_FIELD:
        raise ValueError("credential field too long")
    if any(c in username + password for c in ("\r", "\n", "\x00")):
        raise ValueError("credential contains control characters")
    payload = json.dumps({"u": username, "p": password})
    _client().set(_PREFIX + run_id + ":B", payload,
                  ex=max(1, ttl if ttl is not None else _DEFAULT_TTL))


def get_web_credentials_b(run_id: str) -> tuple[str, str] | None:
    try:
        raw = _client().get(_PREFIX + run_id + ":B")
        if not raw:
            return None
        d = json.loads(raw)
        u, p = str(d.get("u", "")), str(d.get("p", ""))
        return (u, p) if (u and p) else None
    except Exception:
        return None


def set_web_cookie_a(run_id: str, cookie: str, *, ttl: int | None = None) -> None:
    """Store user A's session cookie after login (idor_probe reads :A suffix)."""
    if not run_id or not cookie:
        return
    try:
        _client().set(_COOKIE_PREFIX + run_id + ":A", cookie,
                      ex=max(1, ttl if ttl is not None else _DEFAULT_TTL))
    except Exception:
        return


def set_web_cookie_b(run_id: str, cookie: str, *, ttl: int | None = None) -> None:
    """Store user B's session cookie after login (idor_probe reads :B suffix)."""
    if not run_id or not cookie:
        return
    try:
        _client().set(_COOKIE_PREFIX + run_id + ":B", cookie,
                      ex=max(1, ttl if ttl is not None else _DEFAULT_TTL))
    except Exception:
        return


# --- THIRD account for the admin + 2-user IDOR model -----------------------
# Recommended pattern on apps where IDOR requires two REAL users (each with
# their own private objects — orders, invoices, messages):
#   web_credentials   → admin  (unlocks /admin/* for authenticated scanning)
#   web_credentials_b → user A (first normal user — IDOR source)
#   web_credentials_c → user B (second normal user — IDOR cross-check)
# idor_probe then pairs B+C (two users with the same role) rather than A+B
# (admin+user, which produces false "legitimate access" positives on admin
# pages the user is simply not allowed to see). When _c isn't provided the
# probe falls back to the old A+B behavior.
def set_web_credentials_c(run_id: str, username: str, password: str,
                          *, ttl: int | None = None) -> None:
    if not run_id:
        raise ValueError("run_id required")
    if not username or not password:
        raise ValueError("username and password required")
    if len(username) > _MAX_FIELD or len(password) > _MAX_FIELD:
        raise ValueError("credential field too long")
    if any(c in username + password for c in ("\r", "\n", "\x00")):
        raise ValueError("credential contains control characters")
    payload = json.dumps({"u": username, "p": password})
    _client().set(_PREFIX + run_id + ":C", payload,
                  ex=max(1, ttl if ttl is not None else _DEFAULT_TTL))


def get_web_credentials_c(run_id: str) -> tuple[str, str] | None:
    try:
        raw = _client().get(_PREFIX + run_id + ":C")
        if not raw:
            return None
        d = json.loads(raw)
        u, p = str(d.get("u", "")), str(d.get("p", ""))
        return (u, p) if (u and p) else None
    except Exception:
        return None


def set_web_cookie_c(run_id: str, cookie: str, *, ttl: int | None = None) -> None:
    """Store user C's session cookie after login (idor_probe reads :C suffix)."""
    if not run_id or not cookie:
        return
    try:
        _client().set(_COOKIE_PREFIX + run_id + ":C", cookie,
                      ex=max(1, ttl if ttl is not None else _DEFAULT_TTL))
    except Exception:
        return


# Extend the primary clear() so the secondary slots don't outlive the scan.
_orig_clear = clear_web_credentials


def clear_web_credentials(run_id: str) -> None:  # type: ignore[no-redef]
    """Delete all credential + cookie slots for a run (A, B, C, and the plain
    legacy slot). TTL is still the backstop; this is the explicit cleanup."""
    _orig_clear(run_id)
    try:
        c = _client()
        c.delete(_PREFIX + run_id + ":B")
        c.delete(_PREFIX + run_id + ":C")
        c.delete(_COOKIE_PREFIX + run_id + ":A")
        c.delete(_COOKIE_PREFIX + run_id + ":B")
        c.delete(_COOKIE_PREFIX + run_id + ":C")
    except Exception:
        pass
