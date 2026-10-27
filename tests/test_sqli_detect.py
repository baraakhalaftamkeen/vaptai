"""sqli_detect Tier-2 confirmer — argv safety, normalizer parsing, orchestration guard.

The build-time rule that makes this tool safe to run under the SCAN agent is a
single commitment: the argv NEVER contains an exploitation flag (--os-shell,
--os-cmd, --eval, --dump, --dump-all, --dbs, --tables, --columns, --schema,
--passwords, --privileges, --sql-shell, --sql-query, --file-read, --file-write,
--udf-inject). The tests here enforce that from several angles so a future edit
to the builder can't quietly re-add one.
"""
from __future__ import annotations

import pytest

from vapt_agents.manifests import SCAN
from vapt_agents.normalize import _sqli_detect, normalize
from vapt_domain.enums import AgentRole, PolicyClass
from vapt_tools import REGISTRY
from vapt_tools.registry import _SQLI_DETECT_FORBIDDEN


# --------------------------------------------------------------------------- #
# Registry + manifest
# --------------------------------------------------------------------------- #
def test_sqli_detect_is_registered():
    spec = REGISTRY.get("sqli_detect")
    assert spec.policy_class is PolicyClass.P2_INTRUSIVE
    assert AgentRole.SCAN in spec.allowed_agents
    assert AgentRole.VALIDATE in spec.allowed_agents
    # ATTACK must NOT be here — if a future edit widens it, that is a safety
    # downgrade (ATTACK agent has its own catalog sqlmap entry and playbook flow).
    assert AgentRole.ATTACK not in spec.allowed_agents


def test_sqli_detect_in_scan_manifest():
    assert "sqli_detect" in SCAN.allowed_tool_ids


# --------------------------------------------------------------------------- #
# Argv safety — the core invariant
# --------------------------------------------------------------------------- #
def _argv(**args):
    spec = REGISTRY.get("sqli_detect")
    return spec.build_argv(args)


def test_argv_never_contains_forbidden_sqlmap_flags():
    # A GET-form build, a POST-form build, and a param-pinned build must all pass.
    for args in (
        dict(target="example.com", url="http://example.com/x?id=1"),
        dict(target="example.com", url="http://example.com/x", method="post", data="a=1"),
        dict(target="example.com", url="http://example.com/x?id=1", param="id"),
    ):
        argv = _argv(**args)
        for forbidden in _SQLI_DETECT_FORBIDDEN:
            assert forbidden not in argv, (
                f"sqli_detect built argv containing forbidden flag {forbidden!r}: {argv}"
            )


def test_argv_bounded_technique_set():
    # Default BE (boolean + error). Letters outside BEUST are rejected.
    assert "BE" in _argv(target="example.com", url="http://example.com/x?id=1")
    with pytest.raises(ValueError):
        _argv(target="example.com", url="http://example.com/x?id=1", technique="BX")
    with pytest.raises(ValueError):
        _argv(target="example.com", url="http://example.com/x?id=1", technique="--dump")


def test_argv_level_and_risk_default_to_one():
    argv = _argv(target="example.com", url="http://example.com/x?id=1")
    assert argv[argv.index("--level") + 1] == "1"
    assert argv[argv.index("--risk") + 1] == "1"


def test_argv_level_and_risk_overridable_in_bounds():
    # The auth-endpoint dispatcher sets level=2, risk=3 for login SQLi detection
    # (safe for SELECT-backed login/register endpoints). Builder must accept it.
    argv = _argv(target="example.com", url="http://example.com/x?id=1",
                 technique="BEU", level=2, risk=3)
    assert argv[argv.index("--level") + 1] == "2"
    assert argv[argv.index("--risk") + 1] == "3"
    assert argv[argv.index("--technique") + 1] == "BEU"


def test_argv_rejects_out_of_bounds_level_or_risk():
    with pytest.raises(ValueError):
        _argv(target="example.com", url="http://example.com/x?id=1", level=0)
    with pytest.raises(ValueError):
        _argv(target="example.com", url="http://example.com/x?id=1", level=4)
    with pytest.raises(ValueError):
        _argv(target="example.com", url="http://example.com/x?id=1", risk=0)
    with pytest.raises(ValueError):
        _argv(target="example.com", url="http://example.com/x?id=1", risk=4)
    with pytest.raises(ValueError):
        _argv(target="example.com", url="http://example.com/x?id=1", level="nope")


def test_argv_rejects_off_scope_url():
    with pytest.raises(ValueError):
        _argv(target="example.com", url="http://evil.com/x?id=1")


def test_argv_rejects_option_like_url():
    with pytest.raises(ValueError):
        _argv(target="example.com", url="-u http://x/")


def test_argv_rejects_invalid_param_name():
    with pytest.raises(ValueError):
        _argv(target="example.com", url="http://example.com/x?id=1", param="id;rm -rf /")


def test_argv_post_requires_data():
    with pytest.raises(ValueError):
        _argv(target="example.com", url="http://example.com/x", method="post")


def test_argv_rejects_invalid_data():
    with pytest.raises(ValueError):
        _argv(target="example.com", url="http://example.com/x", method="post",
              data="rm -rf /")


# --------------------------------------------------------------------------- #
# Normalizer — a confirmed hit is proof, a miss is info-only
# --------------------------------------------------------------------------- #
_SQLMAP_HIT = """
[*] starting @ 12:00:01

[12:00:03] [INFO] testing connection to the target URL
[12:00:04] [INFO] testing if parameter 'id' is dynamic
sqlmap identified the following injection point(s) with a total of 42 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 2672=2672
---
"""

_SQLMAP_MISS = """
[*] starting @ 12:00:01
[12:00:03] [INFO] testing connection to the target URL
[12:00:04] [WARNING] all tested parameters do not appear to be injectable.
"""

_SQLMAP_ERROR = """
[12:00:01] [CRITICAL] unable to connect to the target URL
"""


def test_normalizer_promotes_identified_injection():
    obs = _sqli_detect(_SQLMAP_HIT)
    assert len(obs) == 1
    o = obs[0]
    assert o.source_tool == "sqli_detect"
    assert o.severity == "high"
    assert o.detail["confirmed"] is True
    assert "id" in o.detail["params"]
    assert o.detail["method"] == "GET"
    assert any("boolean-based" in t.lower() for t in o.detail["techniques"])


def test_normalizer_returns_empty_on_explicit_miss():
    assert _sqli_detect(_SQLMAP_MISS) == []


def test_normalizer_returns_empty_on_error():
    assert _sqli_detect(_SQLMAP_ERROR) == []


def test_normalize_dispatch_wires_through():
    # The top-level normalize() must route tool_id="sqli_detect" to the parser,
    # not to the generic fallback. A hit observation flows end-to-end with the
    # dispatch — proving the branch landed in normalize.py.
    stdout_blob = [{"stdout": _SQLMAP_HIT}]
    obs = normalize("sqli_detect", stdout_blob)
    assert obs and obs[0].detail.get("confirmed") is True


def test_normalize_dispatch_miss_surfaces_diagnostic():
    stdout_blob = [{"stdout": _SQLMAP_MISS, "stderr": "warn: skipped"}]
    obs = normalize("sqli_detect", stdout_blob)
    assert len(obs) == 1
    assert obs[0].severity == "info"
    assert obs[0].detail.get("confirmed") is not True
