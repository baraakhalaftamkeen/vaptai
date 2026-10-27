"""vapt_http_fetch bounded curl primitive — argv safety + normalizer parsing.

The LLM-webvuln planner can propose this tool. The build-time rule: argv is a FIXED
template with hardcoded safe flags; the only inputs the model controls are the URL,
method, body, and a whitelisted set of header names. Flags curl ships that could be
footguns (-o, -K, --config, -E, -k, --proxy, -u, --netrc, --resolve, --upload-file,
--interface, --unix-socket, --connect-to, --location-trusted) are NEVER emitted by
this builder, regardless of what the LLM proposes.
"""
from __future__ import annotations

import pytest

from vapt_agents.normalize import _http_fetch, normalize
from vapt_agents.manifests import SCAN
from vapt_domain.enums import AgentRole, PolicyClass
from vapt_tools import REGISTRY


def _argv(**args):
    return REGISTRY.get("vapt_http_fetch").build_argv(args)


# --------------------------------------------------------------------------- #
# Registry + manifest
# --------------------------------------------------------------------------- #
def test_registered_as_scan_validate_p2():
    spec = REGISTRY.get("vapt_http_fetch")
    assert spec.policy_class is PolicyClass.P2_INTRUSIVE
    assert AgentRole.SCAN in spec.allowed_agents
    assert AgentRole.VALIDATE in spec.allowed_agents
    assert AgentRole.ATTACK not in spec.allowed_agents


def test_in_scan_manifest():
    assert "vapt_http_fetch" in SCAN.allowed_tool_ids


# --------------------------------------------------------------------------- #
# Argv safety — the invariant
# --------------------------------------------------------------------------- #
_FORBIDDEN_CURL_FLAGS = (
    "-o", "--output", "-K", "--config", "-E", "--cert", "-k", "--insecure",
    "--proxy", "-u", "--user", "--netrc", "--netrc-file", "--resolve",
    "--upload-file", "-T", "--interface", "--unix-socket", "--connect-to",
    "--location-trusted",
)


def test_argv_never_contains_forbidden_curl_flags():
    for args in (
        dict(target="example.com", url="http://example.com/x"),
        dict(target="example.com", url="http://example.com/x", method="post", data="a=1"),
        dict(target="example.com", url="http://example.com/x",
             headers=["Content-Type: application/json", "X-Forwarded-For: 127.0.0.1"]),
    ):
        argv = _argv(**args)
        for forbidden in _FORBIDDEN_CURL_FLAGS:
            assert forbidden not in argv, (
                f"vapt_http_fetch argv contained forbidden curl flag {forbidden!r}: {argv}"
            )


def test_argv_hardcodes_safe_bounds():
    argv = _argv(target="example.com", url="http://example.com/x")
    assert "--max-time" in argv and "10" == argv[argv.index("--max-time") + 1]
    assert "--max-filesize" in argv
    assert "1048576" == argv[argv.index("--max-filesize") + 1]
    assert "-A" in argv
    assert argv[argv.index("-A") + 1] == "vapt-http-fetch/1.0"


def test_argv_rejects_off_scope_url():
    with pytest.raises(ValueError):
        _argv(target="example.com", url="http://evil.com/x")


def test_argv_rejects_option_like_url():
    with pytest.raises(ValueError):
        _argv(target="example.com", url="-X POST http://x/")


def test_argv_rejects_file_scheme():
    with pytest.raises(ValueError):
        _argv(target="example.com", url="file:///etc/passwd")


def test_argv_post_requires_data():
    with pytest.raises(ValueError):
        _argv(target="example.com", url="http://example.com/x", method="post")


def test_argv_rejects_invalid_data():
    with pytest.raises(ValueError):
        _argv(target="example.com", url="http://example.com/x", method="post",
              data="; rm -rf /")


def test_argv_rejects_non_whitelisted_header():
    with pytest.raises(ValueError):
        # Authorization is deliberately NOT in the whitelist — session cookie is
        # the only auth path, and comes from the Redis slot, not the LLM.
        _argv(target="example.com", url="http://example.com/x",
              headers=["Authorization: Bearer x"])


def test_argv_rejects_header_with_crlf():
    with pytest.raises(ValueError):
        _argv(target="example.com", url="http://example.com/x",
              headers=["X-Test: foo\r\nSet-Cookie: injected=1"])


def test_argv_rejects_header_missing_colon():
    with pytest.raises(ValueError):
        _argv(target="example.com", url="http://example.com/x",
              headers=["XTestNoColon"])


# --------------------------------------------------------------------------- #
# Normalizer
# --------------------------------------------------------------------------- #
def test_normalizer_extracts_status_and_type():
    stdout = (
        '{"ok":true,"version":"1.2.3"}\n'
        "--- http_code:200 content_type:application/json;charset=utf-8 size:42"
    )
    obs = _http_fetch(stdout)
    assert len(obs) == 1
    o = obs[0]
    assert o.source_tool == "vapt_http_fetch"
    assert o.severity == "info"
    assert o.detail["status"] == "200"
    assert o.detail["content_type"].startswith("application/json")
    assert o.detail["size"] == "42"
    assert '{"ok":true' in o.detail["body_excerpt"]


def test_normalizer_handles_missing_meta_line_gracefully():
    obs = _http_fetch("some body with no meta line")
    assert len(obs) == 1
    assert obs[0].detail["status"] == ""


def test_normalize_dispatch_routes_tool_id():
    stdout = "body\n--- http_code:404 content_type:text/html size:12"
    obs = normalize("vapt_http_fetch", [{"stdout": stdout}])
    assert obs and obs[0].detail["status"] == "404"
