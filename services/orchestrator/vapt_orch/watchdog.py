"""Stale-executing watchdog — cleans orphaned ``tool_actions`` rows on worker boot.

A tool action goes `proposed → executing → executed`. The broker's subprocess
timeout + outer exception handlers normally guarantee the `executed` row lands,
but a few failure modes leave an executing row stranded forever:

  * The Celery worker is SIGKILLed mid-task (user restart, OOM, systemd reboot)
    before the task's finalization code can write ``action.executed``.
  * The ledger write for ``action.executed`` raises after retries exhausted (the
    ``IntegrityError`` seq race pattern we fixed earlier can still bite under
    extreme concurrency).
  * A caller-side bug in a graph node swallows the broker result without
    writing the ledger event.

In every one of these cases the UI shows the action "running" forever and the
operator has to manually SQL-fix the row. This module runs ONCE per worker
boot: it scans ``tool_actions`` for rows older than
:data:`_STALE_AGE_MINUTES` still in ``executing`` or ``proposed`` state, marks
them ``failed``, and writes a synthetic ``action.executed`` ledger event so
the UI/report pipeline sees them as "ran but did not complete" instead of
pretending they are still live.

Fail-safe by construction:
  * Runs AFTER the worker is `worker_ready` (not during module import), so a
    broken watchdog can never prevent the worker from booting.
  * Catches every exception inside its own body — a cleanup failure is logged
    but never bubbles up to Celery.
  * The threshold defaults to 15 minutes, which is well past the longest
    legitimate ``timeout_s`` in the registry (``wapiti`` at 420s, ``nmap_vuln``
    at 900s all finish under 15 min). Operators can override via
    ``VAPT_WATCHDOG_STALE_MINUTES``.
"""
from __future__ import annotations

import logging
import os
from datetime import UTC, datetime, timedelta

from celery.signals import worker_ready
from sqlalchemy import and_, or_, select

from vapt_persistence import ledger
# Lazy-resolve SessionLocal via the module. `vapt_persistence.db.SessionLocal`
# is populated by `init_engine()`; if we import it eagerly here (module load
# time), tests and short-lived scripts that call init_engine AFTER importing
# the watchdog see a stale None binding. Looking it up through `dbmod.*` at
# call time is the standard pattern used elsewhere in the codebase.
import vapt_persistence.db as dbmod
from vapt_persistence.models import ToolActionRecord

_log = logging.getLogger(__name__)

# Rows older than this in `executing`/`proposed` state are swept. 15 min is a
# generous ceiling vs the longest tool timeout in the registry (wapiti 420s,
# nmap_vuln 900s). Operators who run longer-timeout custom tools can bump this.
_STALE_AGE_MINUTES = int(os.environ.get("VAPT_WATCHDOG_STALE_MINUTES", "15"))

# States the watchdog considers stale when old. The real state machine is
# `proposed → authorized → executing → executed`; everything else is terminal
# (`failed`, `denied`) and never gets touched. We MUST include `authorized`
# because tasks can and do stall there — observed on csp_check 2026-10-24,
# where approval completed but the broker call never fired, leaving 5 rows
# wedged in `authorized` forever.
_STALE_STATES = ("executing", "proposed", "authorized")


def cleanup_orphaned_actions() -> int:
    """Mark stale `executing`/`proposed` tool_actions as failed and write the
    missing `action.executed` ledger event. Returns the count of rows swept.
    Safe to call multiple times — only rows older than the threshold with
    their state still in `_STALE_STATES` are touched.

    Each sweep: ONE SQLAlchemy UPDATE + one ledger `action.executed` event per
    row. Both happen under the SessionLocal boundary so a mid-sweep crash
    leaves the DB consistent (partial sweep is fine — the next worker boot
    will finish it)."""
    cutoff = datetime.now(UTC) - timedelta(minutes=_STALE_AGE_MINUTES)
    swept = 0
    try:
        # Make sure the engine is initialized before we try to open a session —
        # `worker_ready` can fire before any task has run, meaning the lazy
        # init_engine() call in tasks.py hasn't happened yet. Calling
        # init_engine with the env URL is idempotent on repeat calls.
        if dbmod.SessionLocal is None:
            from vapt_persistence import init_engine as _init_engine
            _db_url = os.environ.get("VAPT_DATABASE_URL", "")
            if not _db_url:
                _log.warning("watchdog: VAPT_DATABASE_URL unset — cannot sweep")
                return 0
            _init_engine(_db_url)
        with dbmod.SessionLocal() as s:
            stale = s.execute(
                select(ToolActionRecord).where(
                    and_(
                        or_(*[ToolActionRecord.state == st for st in _STALE_STATES]),
                        ToolActionRecord.created_at < cutoff,
                    )
                )
            ).scalars().all()
            for rec in stale:
                try:
                    rec.state = "failed"
                    # Synthetic ledger event so the report pipeline / UI see the
                    # action as "ran but did not complete". The payload shape
                    # matches what the broker would have written on a real
                    # subprocess timeout, so downstream parsers (report.py's
                    # gap builder, ferments the `tool_by_digest` map) don't need
                    # a special case.
                    ledger.record_event(
                        s, rec.run_id, "action.executed",
                        {
                            "digest": rec.action_digest,
                            "outcome": "failed",
                            "exit_code": None,
                            "elapsed_seconds": None,
                            "note": "worker_restart_orphan",
                        },
                    )
                    s.commit()
                    swept += 1
                except Exception as e:
                    # Per-row isolation: a bad row shouldn't poison the sweep.
                    s.rollback()
                    _log.warning("watchdog: failed to sweep %s: %s",
                                 rec.action_digest, e)
        if swept:
            _log.warning(
                "watchdog: swept %d orphan tool_actions older than %d min",
                swept, _STALE_AGE_MINUTES,
            )
    except Exception as e:
        # Never let the watchdog crash the worker. If the DB is down at boot,
        # the operator has bigger problems; log and continue.
        _log.warning("watchdog: cleanup failed: %s", e)
    return swept


@worker_ready.connect
def _on_worker_ready(sender=None, **_kwargs) -> None:
    """Celery signal handler: runs ONCE when the worker finishes booting and is
    about to start accepting tasks. Subscribed via module import — see
    `vapt_orch.tasks` which imports this module to activate the signal."""
    cleanup_orphaned_actions()
