"""The probe target must be a concrete host derived from scope, never a CIDR used
verbatim (which made every action fail 'target not in approved scope'). Also tolerant
of an IP typed into the domains box."""
from __future__ import annotations

from vapt_harness.harness import scope_contains
from vapt_orch.tasks import _resolve_scope


def test_cidr_32_yields_host_and_is_in_scope():
    # The regression: 172.25.188.23/32 entered as the CIDR.
    hostnames, cidrs, target = _resolve_scope([], ["172.25.188.23/32"])
    assert target == "172.25.188.23"                 # a host, not the network
    assert cidrs == ["172.25.188.23/32"]
    assert scope_contains(target, domains=hostnames, ip_cidrs=cidrs) is True


def test_bare_ip_in_cidr_box_still_works():
    hostnames, cidrs, target = _resolve_scope([], ["172.25.188.23"])
    assert target == "172.25.188.23"
    assert cidrs == ["172.25.188.23/32"]
    assert scope_contains(target, domains=hostnames, ip_cidrs=cidrs) is True


def test_bare_ip_typed_into_domains_box_is_folded_to_cidr_scope():
    # A user who puts the IP in the "domains" field must not silently fall out of scope.
    hostnames, cidrs, target = _resolve_scope(["172.25.188.23"], [])
    assert target == "172.25.188.23"
    assert cidrs == ["172.25.188.23/32"]
    assert scope_contains(target, domains=hostnames, ip_cidrs=cidrs) is True


def test_hostname_target_matches_domain_scope():
    hostnames, cidrs, target = _resolve_scope(["example.com"], [])
    assert target == "example.com"
    assert hostnames == ["example.com"]
    assert scope_contains(target, domains=hostnames, ip_cidrs=cidrs) is True


def test_broader_cidr_picks_first_usable_host_in_scope():
    hostnames, cidrs, target = _resolve_scope([], ["10.0.0.0/29"])
    assert target == "10.0.0.1"                      # first usable host
    assert cidrs == ["10.0.0.0/29"]
    assert scope_contains(target, domains=hostnames, ip_cidrs=cidrs) is True


def test_empty_scope_falls_back():
    hostnames, cidrs, target = _resolve_scope([], [])
    assert target == "example.com"
    assert hostnames == [] and cidrs == []


def test_domain_preferred_as_target_over_ip():
    hostnames, cidrs, target = _resolve_scope(["app.example.com"], ["10.1.1.5/32"])
    assert target == "app.example.com"               # hostname wins the target slot
    assert "10.1.1.5/32" in cidrs
    assert scope_contains("10.1.1.5", domains=hostnames, ip_cidrs=cidrs) is True
