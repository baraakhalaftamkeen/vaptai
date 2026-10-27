"""The engagement's Allowed ports must bound the nmap scan end to end:
  * ScopeInput accepts a spec string (with ranges) and a legacy list[int];
  * scan_plan_for(scope) / the planner carry the scope's ports to nmap -p;
  * an empty scope falls back to the broad default set, never the old fixed 3 ports;
  * the nmap argv builder accepts ranges.
"""
from __future__ import annotations

import pytest

from vapt_agents import phases
from vapt_agents.planner import plan_scan
from vapt_agents.runscope import RunScope
from vapt_domain.enums import PolicyClass, TestingMode
from vapt_domain.schemas import ScopeInput
from vapt_tools import REGISTRY


def _scope(ports: str = "") -> RunScope:
    return RunScope(
        run_id="r1", testing_mode=TestingMode.BLACK_BOX, target="172.25.188.23",
        domains=[], ip_cidrs=["172.25.188.23/32"],
        allowed_action_classes=[PolicyClass.P0_PASSIVE, PolicyClass.P1_LOW_IMPACT],
        allowed_ports=ports,
    )


# -- schema coercion ---------------------------------------------------------
def test_scope_accepts_spec_string_with_range():
    s = ScopeInput(allowed_ports="1-65535")
    assert s.allowed_ports == "1-65535"


def test_scope_accepts_comma_and_ranges():
    s = ScopeInput(allowed_ports=" 80, 443 ,8000-8100 ".replace(" ", ""))
    assert s.allowed_ports == "80,443,8000-8100"


def test_scope_coerces_legacy_int_list():
    s = ScopeInput(allowed_ports=[80, 443, 3389])
    assert s.allowed_ports == "80,443,3389"


def test_scope_rejects_bad_spec():
    with pytest.raises(ValueError):
        ScopeInput(allowed_ports="80;rm -rf")
    with pytest.raises(ValueError):
        ScopeInput(allowed_ports="80,99999")       # out of range


def test_scope_empty_is_blank():
    assert ScopeInput().allowed_ports == ""
    assert ScopeInput(allowed_ports="").allowed_ports == ""


# -- scan plan carries the scope's ports -------------------------------------
def test_scan_plan_uses_scope_ports():
    plan = phases.scan_plan_for(_scope("22,3389,445"))
    nmap = dict(plan)["nmap_service_scan"]
    assert nmap["ports"] == "22,3389,445"


def test_scan_plan_defaults_when_empty():
    plan = phases.scan_plan_for(_scope(""))
    nmap = dict(plan)["nmap_service_scan"]
    assert nmap["ports"] == phases.DEFAULT_PORTS
    # the default must be broader than the old fixed three ports
    assert nmap["ports"] != "80,443,22"
    assert "3389" in nmap["ports"] and "445" in nmap["ports"]


def test_planner_fallback_uses_scope_ports():
    res = plan_scan(None, _scope("1-1024"))
    assert res.used_model is False
    nmap = next(a for a in res.actions if a.tool_id == "nmap_service_scan")
    assert nmap.args["ports"] == "1-1024"


# -- the argv builder actually accepts the range ----------------------------
def test_nmap_builder_accepts_range():
    spec = REGISTRY.get("nmap_service_scan")
    argv = spec.build_argv({"target": "172.25.188.23", "ports": "1-65535"})
    assert "-p" in argv
    assert argv[argv.index("-p") + 1] == "1-65535"
    assert argv[0] == "nmap" and "-sT" in argv       # still connect-scan, non-privileged
    assert "-sV" in argv                             # version detection → services show versions


def test_nmap_builder_rejects_option_injection():
    spec = REGISTRY.get("nmap_service_scan")
    with pytest.raises(ValueError):
        spec.build_argv({"target": "172.25.188.23", "ports": "-oG /tmp/x"})
