"""Preflight binary-check unit tests."""
from __future__ import annotations

import os
import stat

from vapt_orch import preflight


def test_check_worker_binaries_sees_shipped_set(monkeypatch):
    """With VAPT_WORKER_BIN_DIR pointing at the real repo workers/bin, every
    shipped binary should report "ok". Catches a regression where a binary
    stops being deployed."""
    monkeypatch.delenv("VAPT_WORKER_BIN_DIR", raising=False)
    result = preflight.check_worker_binaries()
    assert set(result.keys()) == set(preflight._REQUIRED_BINARIES)
    missing = [n for n, s in result.items() if s != "ok"]
    assert not missing, f"required binaries not ready: {missing}"


def test_check_worker_binaries_reports_missing(tmp_path, monkeypatch):
    """Pointed at an empty directory, every binary reports "missing"."""
    monkeypatch.setenv("VAPT_WORKER_BIN_DIR", str(tmp_path))
    result = preflight.check_worker_binaries()
    assert all(status == "missing" for status in result.values())


def test_check_worker_binaries_reports_not_executable(tmp_path, monkeypatch):
    """A binary that exists but isn't +x reports "not_executable"."""
    for name in preflight._REQUIRED_BINARIES:
        p = tmp_path / name
        p.write_text("#!/bin/sh\n")
        os.chmod(p, 0o644)  # readable but not executable
    monkeypatch.setenv("VAPT_WORKER_BIN_DIR", str(tmp_path))
    result = preflight.check_worker_binaries()
    assert all(status == "not_executable" for status in result.values())


def test_check_worker_binaries_mixed(tmp_path, monkeypatch):
    """Only a subset present: that subset is "ok", the rest are "missing"."""
    present = preflight._REQUIRED_BINARIES[:2]
    for name in present:
        p = tmp_path / name
        p.write_text("#!/bin/sh\n")
        os.chmod(p, stat.S_IRWXU)
    monkeypatch.setenv("VAPT_WORKER_BIN_DIR", str(tmp_path))
    result = preflight.check_worker_binaries()
    for name in present:
        assert result[name] == "ok"
    for name in preflight._REQUIRED_BINARIES[2:]:
        assert result[name] == "missing"
