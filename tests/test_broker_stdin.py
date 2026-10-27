"""The broker must never give a tool an interactive stdin — a scanner that tries to
prompt (a sudo password behind a docker wrapper, say) would otherwise hang the worker
until the tool timeout. It should get EOF and fail fast instead."""
from __future__ import annotations

import subprocess

from vapt_tools import REGISTRY
from vapt_tools import broker as bmod
from vapt_tools.broker import ToolBroker


def test_subprocess_runs_with_devnull_stdin(monkeypatch):
    seen = {}

    class _Proc:
        returncode = 0
        stdout = "ok"
        stderr = ""

    def fake_run(argv, **kwargs):
        seen.update(kwargs)
        return _Proc()

    monkeypatch.setattr(bmod.shutil, "which", lambda b: "/usr/bin/" + b)
    monkeypatch.setattr(bmod.subprocess, "run", fake_run)

    ToolBroker(REGISTRY).execute("nmap_service_scan", {"target": "x", "ports": "80"})
    assert seen.get("stdin") is subprocess.DEVNULL
    assert seen.get("shell") is False          # still never a shell
