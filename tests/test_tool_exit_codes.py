"""Per-tool success exit codes. zap-baseline.py exits non-zero when it FINDS issues
(1=FAIL, 2=WARN) — that is a successful run with findings, not an error, so the broker
must treat it as 'ok' and keep its output. Other tools keep the strict 0-only default."""
from __future__ import annotations

from vapt_tools import REGISTRY
from vapt_tools import broker as bmod
from vapt_tools.broker import ToolBroker


class _Proc:
    def __init__(self, rc: int):
        self.returncode = rc
        self.stdout = "WARN-NEW: X-Content-Type-Options header missing"
        self.stderr = ""


def _run_with_rc(monkeypatch, rc):
    monkeypatch.setattr(bmod.shutil, "which", lambda b: f"/usr/local/bin/{b}")
    monkeypatch.setattr(bmod.subprocess, "run", lambda *a, **k: _Proc(rc))
    return ToolBroker(REGISTRY)


def test_zap_spec_declares_find_exit_codes():
    assert REGISTRY.get("zap_baseline").ok_exit_codes == (0, 1, 2)
    assert REGISTRY.get("nmap_service_scan").ok_exit_codes == (0,)  # default strict


def test_zap_nonzero_exit_is_ok(monkeypatch):
    broker = _run_with_rc(monkeypatch, 2)
    res = broker.execute("zap_baseline", {"target": "example.com"})
    assert res.outcome == "ok"          # WARN present -> still a successful run
    assert res.exit_code == 2


def test_default_tool_nonzero_is_failed(monkeypatch):
    broker = _run_with_rc(monkeypatch, 1)
    res = broker.execute("nmap_service_scan", {"target": "example.com", "ports": "80"})
    assert res.outcome == "failed"      # a real error for a strict-exit tool
