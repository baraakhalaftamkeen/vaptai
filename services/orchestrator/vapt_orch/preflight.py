"""Worker boot-time binary preflight check.

The orchestrator shells out to several custom worker binaries under
``workers/bin/*`` (``vapt-recon-fetch``, ``vapt-web-probe``,
``vapt-dom-xss-probe``, ``vapt-idor-probe``, …). Each one has an
``os.path.exists(bin_path)`` gate inside the engagement graph: when the
file is missing, the orchestrator silently returns ``[]`` and the feature
gated on it (e.g. the Stage-3 recon agent) never fires — the operator
sees no ledger trace and no error. This has already bitten us once (the
2026-10-26 DineHub run where ``vapt-recon-fetch`` wasn't on the worker's
filesystem because the worker hadn't been restarted after a code update).

This module runs ONCE per worker boot via Celery's ``worker_ready``
signal. It verifies every binary listed in ``_REQUIRED_BINARIES`` exists
and is executable, and logs a LOUD warning for each missing one. We do
NOT abort worker boot — missing binaries only degrade specific features
(e.g. no recon agent, no DOM-XSS static analysis) and the operator may
still want the worker up for the other probes; the warning + ledger-
event trail makes the degradation visible instead of silent.

Env override: set ``VAPT_WORKER_BIN_DIR`` to point at a non-standard
location (e.g. a Docker volume mount, a dev checkout under /opt).
"""
from __future__ import annotations

import logging
import os
import stat

from celery.signals import worker_ready

_log = logging.getLogger(__name__)

# Every worker binary the engagement graph may shell out to. Keep this
# list in sync with ``packages/tools/vapt_tools/registry.py``'s
# ``_build_*`` functions that reference ``workers/bin/*``.
_REQUIRED_BINARIES = (
    "vapt-recon-fetch",
    "vapt-web-probe",
    "vapt-dom-xss-probe",
    "vapt-idor-probe",
    "vapt-stored-xss-probe",
    "vapt-csp-check",
    "vapt-yaml-deser-probe",
)


def _default_bin_dir() -> str:
    """Default location: ``workers/bin`` under the repo root (same path
    the engagement graph uses when ``VAPT_RECON_FETCH_BIN`` is unset).
    Three ``dirname`` levels up from this file is the repo root."""
    here = os.path.dirname(os.path.abspath(__file__))
    # services/orchestrator/vapt_orch/preflight.py → repo root is 3 up.
    return os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(here))),
                        "workers", "bin")


def check_worker_binaries() -> dict[str, str]:
    """Return ``{binary_name: status}`` where status is one of
    ``"ok"``, ``"missing"``, or ``"not_executable"``. A missing or
    non-executable binary logs a loud warning so the operator can see it
    in the worker log immediately after boot."""
    bin_dir = os.environ.get("VAPT_WORKER_BIN_DIR", _default_bin_dir())
    result: dict[str, str] = {}
    for name in _REQUIRED_BINARIES:
        path = os.path.join(bin_dir, name)
        if not os.path.exists(path):
            result[name] = "missing"
            _log.warning(
                "preflight: worker binary MISSING: %s (expected at %s). "
                "Features gated on this binary will silently no-op; set "
                "VAPT_WORKER_BIN_DIR to override location.",
                name, path,
            )
            continue
        try:
            mode = os.stat(path).st_mode
        except OSError as e:
            result[name] = "stat_failed"
            _log.warning("preflight: cannot stat %s: %s", path, e)
            continue
        if not (mode & stat.S_IXUSR):
            result[name] = "not_executable"
            _log.warning(
                "preflight: worker binary NOT EXECUTABLE: %s (chmod +x "
                "the file; features gated on it will silently no-op).",
                path,
            )
            continue
        result[name] = "ok"
    missing = [n for n, s in result.items() if s != "ok"]
    if missing:
        _log.warning(
            "preflight: %d/%d required worker binaries are not ready: %s",
            len(missing), len(_REQUIRED_BINARIES), ", ".join(missing),
        )
    else:
        _log.info(
            "preflight: all %d required worker binaries ready in %s",
            len(_REQUIRED_BINARIES), bin_dir,
        )
    return result


@worker_ready.connect
def _on_worker_ready(sender=None, **_kwargs) -> None:
    """Celery signal handler: runs ONCE when the worker finishes booting."""
    try:
        check_worker_binaries()
    except Exception as e:
        # Never let the preflight crash the worker.
        _log.warning("preflight: check failed: %s", e)
