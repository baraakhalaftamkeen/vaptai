import pytest
from vapt_tools import REGISTRY, action_digest, idempotency_key


def test_argv_rejects_option_like_target():
    spec = REGISTRY.get("http_probe")
    with pytest.raises(ValueError):
        spec.build_argv({"target": "-oG/etc/passwd"})


def test_argv_builds_safe_array(monkeypatch):
    # Isolate from any ambient VAPT_HTTPX_BIN override (e.g. a dev .env that points at
    # ProjectDiscovery's httpx) so this asserts the default binary deterministically.
    monkeypatch.delenv("VAPT_HTTPX_BIN", raising=False)
    spec = REGISTRY.get("http_probe")
    argv = spec.build_argv({"target": "example.com"})
    assert argv[0] == "httpx"
    assert "example.com" in argv
    # no shell metacharacters survive as a single token
    assert not any(";" in a or "&&" in a for a in argv)


def test_digest_and_key_are_stable():
    d1 = action_digest("dns_resolve", "default", "example.com", {"target": "example.com"})
    d2 = action_digest("dns_resolve", "default", "example.com", {"target": "example.com"})
    assert d1 == d2
    assert idempotency_key("run1", "task1", d1) == idempotency_key("run1", "task1", d2)


def test_unknown_tool_raises():
    with pytest.raises(KeyError):
        REGISTRY.get("nope")
