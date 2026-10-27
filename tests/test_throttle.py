"""Per-target politeness throttle in the broker.

Covers:
  * host extraction from args (`url` wins over `target`, option-like values rejected);
  * wait_turn() sleeps when the previous tool against the same host finished recently;
  * record_finish() stores last_end and last_elapsed under the right Redis key;
  * a "heavy" previous tool extends the gap (cooldown);
  * fail-open when Redis is unreachable;
  * disabled via env var.

Uses a stub Redis so the test is deterministic (no live Redis required).
"""
from __future__ import annotations

import json
import time

import pytest
from vapt_tools import throttle


# -- in-memory stub Redis ----------------------------------------------------
class _StubRedis:
    def __init__(self):
        self.store: dict[str, str] = {}

    def get(self, k):
        return self.store.get(k)

    def set(self, k, v, ex=None):
        self.store[k] = v

    @classmethod
    def from_url(cls, *_a, **_kw):
        return _SHARED_STUB


_SHARED_STUB = _StubRedis()


@pytest.fixture(autouse=True)
def _env_clean(monkeypatch):
    for v in ("VAPT_TARGET_THROTTLE_DISABLED", "VAPT_TARGET_MIN_GAP_MS",
              "VAPT_TARGET_HEAVY_THRESHOLD_S", "VAPT_TARGET_HEAVY_COOLDOWN_MS"):
        monkeypatch.delenv(v, raising=False)
    # fresh stub per test so state doesn't leak between cases
    global _SHARED_STUB
    _SHARED_STUB = _StubRedis()


@pytest.fixture
def stub_redis(monkeypatch):
    import redis  # type: ignore
    monkeypatch.setattr(redis.Redis, "from_url",
                        classmethod(lambda cls, *a, **kw: _SHARED_STUB))
    return _SHARED_STUB


# -- host extraction ---------------------------------------------------------
def test_host_prefers_url_hostname():
    assert throttle._extract_host({"url": "http://example.com:5000/search",
                                   "target": "other.host"}) == "example.com"


def test_host_falls_back_to_target():
    assert throttle._extract_host({"target": "example.com"}) == "example.com"


def test_host_rejects_option_like_and_missing():
    assert throttle._extract_host({}) is None
    assert throttle._extract_host({"target": "-oG/etc/passwd"}) is None


# -- wait_turn + record_finish round trip -----------------------------------
def test_record_then_wait_sleeps_for_the_gap(monkeypatch, stub_redis):
    monkeypatch.setenv("VAPT_TARGET_MIN_GAP_MS", "200")
    throttle.record_finish({"target": "example.com"}, elapsed_seconds=1.0)
    slept: list[float] = []
    monkeypatch.setattr(throttle.time, "sleep", slept.append)
    throttle.wait_turn({"target": "example.com"})
    assert slept and 0 < slept[0] <= 0.21                      # ~200ms gap


def test_heavy_previous_tool_extends_the_gap(monkeypatch, stub_redis):
    monkeypatch.setenv("VAPT_TARGET_MIN_GAP_MS", "100")
    monkeypatch.setenv("VAPT_TARGET_HEAVY_THRESHOLD_S", "60")
    monkeypatch.setenv("VAPT_TARGET_HEAVY_COOLDOWN_MS", "2000")
    throttle.record_finish({"target": "example.com"}, elapsed_seconds=180.0)  # heavy
    slept: list[float] = []
    monkeypatch.setattr(throttle.time, "sleep", slept.append)
    throttle.wait_turn({"target": "example.com"})
    # 100ms base + 2000ms cooldown ~ 2.1s (minus the few ms since record_finish)
    assert slept and 1.9 <= slept[0] <= 2.11


def test_different_hosts_do_not_share_a_gap(monkeypatch, stub_redis):
    monkeypatch.setenv("VAPT_TARGET_MIN_GAP_MS", "500")
    throttle.record_finish({"target": "a.example"}, elapsed_seconds=1.0)
    slept: list[float] = []
    monkeypatch.setattr(throttle.time, "sleep", slept.append)
    throttle.wait_turn({"target": "b.example"})       # different host → no wait
    assert slept == []


def test_disabled_is_a_noop(monkeypatch, stub_redis):
    monkeypatch.setenv("VAPT_TARGET_THROTTLE_DISABLED", "1")
    throttle.record_finish({"target": "example.com"}, elapsed_seconds=1.0)
    assert stub_redis.store == {}                       # nothing stored
    slept: list[float] = []
    monkeypatch.setattr(throttle.time, "sleep", slept.append)
    throttle.wait_turn({"target": "example.com"})
    assert slept == []


def test_redis_unreachable_is_fail_open(monkeypatch):
    def boom(*_a, **_kw):
        raise RuntimeError("no redis")
    import redis  # type: ignore
    monkeypatch.setattr(redis.Redis, "from_url", classmethod(lambda cls, *a, **kw: boom()))
    slept: list[float] = []
    monkeypatch.setattr(throttle.time, "sleep", slept.append)
    # neither call must raise
    throttle.record_finish({"target": "example.com"}, elapsed_seconds=1.0)
    throttle.wait_turn({"target": "example.com"})
    assert slept == []


def test_record_finish_stores_elapsed(monkeypatch, stub_redis):
    throttle.record_finish({"target": "example.com"}, elapsed_seconds=42.5)
    raw = stub_redis.store["vapt:throttle:example.com"]
    state = json.loads(raw)
    assert state["last_elapsed"] == pytest.approx(42.5)
    assert state["last_end"] == pytest.approx(time.time(), abs=5)
