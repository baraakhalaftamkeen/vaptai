"""Offline workflow tests — no network, no 40-min DineHub runs.

Validates the full webvuln pipeline against a canned universe of tool outputs:
  * `plan_scan` consults the gateway (mocked) and `source=model` fires in the ledger
  * `_webvuln_plan` picks /fetch/logo and other wapiti-flagged routes correctly
  * `discovered_endpoint_urls` prioritises file-sink routes
  * `infer_template_engine` resolves Jinja2 on a `waitress` + `flask` stack
  * normalizers (dalfox / web_param_probe / sstimap / wapiti) parse real captured output
  * proof-promotion auto-confirms dalfox-V / sstimap / web_param_probe findings
  * reporting+remediation `_draft`/`draft_and_audit` return (text, used, diag) correctly
    and emit `source=model` on a happy-path mock gateway

The whole suite runs under one second against SQLite, so iteration on logic bugs no
longer costs a full lab run. New tool integrations should get a `_canned_<tool>` entry
in `FIXTURES` so they ride this same harness.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from unittest.mock import MagicMock

import pytest
import vapt_persistence.db as dbmod
from vapt_agents import manifests, phases
from vapt_agents.normalize import normalize
from vapt_agents.runscope import RunScope
from vapt_domain.enums import PolicyClass, TestingMode
from vapt_persistence import Base, init_engine
from vapt_persistence.models import Engagement, Finding, FindingObservation, Project, Run


# ---------------------------------------------------------------------------
# Canned captures taken from the DineHub lab (abbreviated). Each is the EXACT
# stdout the tool produced in a real run; the normalizers are what we actually
# want to exercise.
# ---------------------------------------------------------------------------
FIXTURES = {
    "httpx_dinehub": (
        'http://172.25.188.23:5000 [200] [DineHub - Delicious Deliveries] '
        '[waitress] [Bootstrap:5.3.3,jsDelivr]\n'
    ),
    "wapiti_dinehub": json.dumps({
        "vulnerabilities": {
            "Reflected Cross Site Scripting": [{
                "method": "POST", "path": "/admin/announcement",
                "parameter": "content", "info": "XSS", "level": 1,
            }],
            "SQL Injection": [{
                "method": "POST", "path": "/auth/login",
                "parameter": "password", "info": "SQLi", "level": 1,
            }],
            "Unencrypted Channels": [{
                "method": "GET", "path": "/fetch/logo",
                "parameter": "", "info": "", "level": 0,
            }],
        }
    }),
    "dalfox_verified": json.dumps([
        {"type": "V", "method": "GET",
         "data": "http://172.25.188.23:5000/admin/announcement?content=%3Cimg%20src%20onerror%3Dalert(1)%3E",
         "param": "content", "payload": "<img src onerror=alert(1)>",
         "cwe": "CWE-79", "severity": "H",
         "evidence": "payload executed via headless browser"},
    ]),
    "dalfox_empty_banner_only": (
        "               Dalfox v2.13.0\n"
        "[*] Starting scan [SID:Single] / URL: http://172.25.188.23:5000/admin/announcement\n"
        "[I] Found 0 testing points in DOM-based parameter mining\n"
        "[I] Content-Type is text/html; charset=utf-8\n"
        "[*] [duration: 2.128276577s][issues: 0] Finish Scan!\n"
        "[{}]"
    ),
    "web_param_probe_ssrf_confirmed": json.dumps({
        "findings": [
            {"type": "ssrf_localhost", "severity": "high",
             "url": "http://172.25.188.23:5000/fetch/logo?url=http://127.0.0.1:22/",
             "param": "url", "evidence": "SSH-2.0-OpenSSH banner reflected",
             "confirmed": True},
        ],
        "trace": [{"url": "http://172.25.188.23:5000/fetch/logo?url=...", "status": 200,
                   "cls": "ssrf_localhost", "note": ""}],
        "cookie_src": "redis",
        "budget_used": 1,
    }),
    "sstimap_jinja2_confirmed": (
        "[+] Target: http://172.25.188.23:5000/admin/announcement\n"
        "[~] Testing if GET parameter 'content' is injectable\n"
        "[+] SSTImap identified the following injection point:\n"
        "    Template engine: Jinja2\n"
        "    Language: python\n"
    ),
}


# ---------------------------------------------------------------------------
# Fixture: in-memory DB with one project/engagement/run.
# ---------------------------------------------------------------------------
@pytest.fixture()
def db(tmp_path):
    init_engine(f"sqlite:///{tmp_path}/wf.db")
    Base.metadata.create_all(dbmod.get_engine())
    s = dbmod.SessionLocal()
    p = Project(name="P"); s.add(p); s.flush()
    e = Engagement(project_id=p.id, name="L",
                   testing_mode="black_box", target_type="network")
    s.add(e); s.flush()
    r = Run(engagement_id=e.id, thread_id="t", status="running")
    s.add(r); s.flush()
    s.commit()
    yield s, r.id
    s.close()


def _scope(run_id, target="172.25.188.23"):
    return RunScope(
        run_id=run_id, testing_mode=TestingMode.BLACK_BOX, target=target,
        domains=[], ip_cidrs=[f"{target}/32"],
        allowed_action_classes=[PolicyClass.P0_PASSIVE, PolicyClass.P1_LOW_IMPACT,
                                PolicyClass.P2_INTRUSIVE],
        signed_profile=True,
    )


def _seed_wapiti(s, run_id, raw_json: str):
    """Normalize a wapiti JSON blob into real findings — mirrors what the broker+normalizer
    chain would persist on a real run."""
    obs = normalize("wapiti", [{"stdout": raw_json}])
    for o in obs:
        f = Finding(run_id=run_id, title=o.title, status="candidate", severity=o.severity)
        s.add(f); s.flush()
        s.add(FindingObservation(finding_id=f.id, source_tool=o.source_tool, detail=o.detail))
    s.commit()


def _seed_httpx(s, run_id, raw_text: str):
    obs = normalize("http_probe", [{"stdout": raw_text}])
    for o in obs:
        f = Finding(run_id=run_id, title=o.title, status="candidate", severity=o.severity)
        s.add(f); s.flush()
        s.add(FindingObservation(finding_id=f.id, source_tool=o.source_tool, detail=o.detail))
    s.commit()


# ---------------------------------------------------------------------------
# 1. engine inference: Flask-on-waitress must resolve to Jinja2
# ---------------------------------------------------------------------------
def test_engine_infer_jinja2_from_waitress_banner(db):
    s, run_id = db
    _seed_httpx(s, run_id, FIXTURES["httpx_dinehub"])
    assert phases.infer_template_engine(s, run_id) == "Jinja2"


def test_engine_infer_prefers_django_over_waitress(db):
    s, run_id = db
    _seed_httpx(s, run_id,
                "http://x [200] [App] [waitress] [Django:4.2,Bootstrap:5.0]\n")
    # Django must win: a Django app on a Python WSGI server is Django, not Jinja2.
    assert phases.infer_template_engine(s, run_id) == "Django"


def test_engine_infer_none_on_opaque_stack(db):
    s, run_id = db
    _seed_httpx(s, run_id, "http://x [200] [App] [nginx]\n")
    assert phases.infer_template_engine(s, run_id) is None


# ---------------------------------------------------------------------------
# 2. wapiti titles feed discovered_endpoint_urls → /fetch/logo surfaces
# ---------------------------------------------------------------------------
def test_discovered_urls_pull_fetch_logo_from_wapiti_title(db):
    s, run_id = db
    _seed_wapiti(s, run_id, FIXTURES["wapiti_dinehub"])
    urls = phases.discovered_endpoint_urls(
        s, _scope(run_id), base_url="http://172.25.188.23:5000", cap=10)
    paths = [u.rsplit("/", 1)[-1] if "/" in u.split("//", 1)[1] else u for u in urls]
    # The file-sink route must be IN the list AND ranked ahead of the generic ones.
    joined = ",".join(urls)
    assert "/fetch/logo" in joined
    assert "/admin/announcement" in joined
    # /fetch/logo (file-sink tier) must come before /admin/announcement (default tier)
    assert urls.index(next(u for u in urls if "/fetch/logo" in u)) < \
           urls.index(next(u for u in urls if "/admin/announcement" in u))


# ---------------------------------------------------------------------------
# 3. wapiti_xss_targets → ssti_detect plan item (POST + GET fallback)
# ---------------------------------------------------------------------------
def test_wapiti_xss_targets_captures_post_route(db):
    s, run_id = db
    _seed_httpx(s, run_id, FIXTURES["httpx_dinehub"])
    _seed_wapiti(s, run_id, FIXTURES["wapiti_dinehub"])
    tgts = phases.wapiti_xss_targets(s, run_id)
    # one entry: the /admin/announcement POST
    assert any("/admin/announcement" in url and param == "content" and method == "POST"
               for (url, param, method) in tgts)


# ---------------------------------------------------------------------------
# 4. normalizer: dalfox V → confirmed observation (proof-promote path)
# ---------------------------------------------------------------------------
def test_dalfox_verified_normalizes_to_confirmed():
    obs = normalize("dalfox", [{"stdout": FIXTURES["dalfox_verified"]}])
    assert len(obs) == 1
    assert obs[0].severity == "high"
    assert obs[0].detail["confirmed"] is True
    assert obs[0].detail["kind"] == "verified"
    assert "confirmed" in obs[0].title


# ---------------------------------------------------------------------------
# 5. normalizer: dalfox empty output → diagnostic observation
# ---------------------------------------------------------------------------
def test_dalfox_empty_emits_diagnostic():
    obs = normalize("dalfox", [{
        "stdout": FIXTURES["dalfox_empty_banner_only"],
        "stderr": "chromedp: context deadline exceeded",
    }])
    assert len(obs) == 1
    assert obs[0].severity == "info"
    assert "no XSS reported" in obs[0].title
    assert "chromedp" in obs[0].detail["stderr_tail"]


# ---------------------------------------------------------------------------
# 6. normalizer: web_param_probe SSRF confirmed
# ---------------------------------------------------------------------------
def test_web_param_probe_ssrf_normalizes_and_promotes():
    obs = normalize("web_param_probe",
                    [{"stdout": FIXTURES["web_param_probe_ssrf_confirmed"]}])
    assert len(obs) == 1
    assert obs[0].severity == "high"
    assert obs[0].detail["confirmed"] is True
    assert obs[0].detail["class"] == "ssrf_localhost"


# ---------------------------------------------------------------------------
# 7. normalizer: sstimap Jinja2 confirmed
# ---------------------------------------------------------------------------
def test_sstimap_jinja2_normalizes_and_promotes():
    obs = normalize("sstimap", [{"stdout": FIXTURES["sstimap_jinja2_confirmed"]}])
    assert len(obs) == 1
    assert obs[0].detail["confirmed"] is True
    assert obs[0].detail.get("engine") == "Jinja2"


# ---------------------------------------------------------------------------
# 8. _draft/draft_and_audit happy path: mock gateway returns real text →
#    (text, True, diag) with diag carrying finish_reason + model_id
# ---------------------------------------------------------------------------
@dataclass
class _GatewayResp:
    text: str = "ok"
    error: str | None = None
    finish_reason: str = "stop"
    profile_id: str = "reporting"
    provider: str = "openai"
    model_id: str = "Qwen3.6-35B-A3B-S"
    usage: dict = None
    latency_ms: int = 123
    trace_id: str = "t"
    parsed: dict | None = None
    def __post_init__(self):
        if self.usage is None:
            self.usage = {}


def test_draft_and_audit_happy_path(db, monkeypatch):
    s, run_id = db
    from vapt_orch.graph.drafting import draft_and_audit  # noqa: PLC0415
    gw = MagicMock()
    gw.invoke.return_value = _GatewayResp(text="This is a real executive summary.")
    text, used, diag = draft_and_audit(
        db=s, run_id=run_id, gateway=gw, manifest=manifests.REPORTING,
        messages=[{"role": "user", "content": "test"}],
        record_model_calls=False,
    )
    assert used is True
    assert text == "This is a real executive summary."
    assert diag["finish_reason"] == "stop"
    assert diag["model"] == "Qwen3.6-35B-A3B-S"


def test_draft_and_audit_error_carries_diag(db):
    s, run_id = db
    from vapt_orch.graph.drafting import draft_and_audit  # noqa: PLC0415
    gw = MagicMock()
    gw.invoke.return_value = _GatewayResp(
        text="", error="model did not return valid JSON", finish_reason="invalid_schema")
    text, used, diag = draft_and_audit(
        db=s, run_id=run_id, gateway=gw, manifest=manifests.REPORTING,
        messages=[{"role": "user", "content": "test"}],
        record_model_calls=False,
    )
    assert used is False
    assert text == ""
    assert diag["finish_reason"] == "invalid_schema"
    assert "did not return" in diag["error"]


def test_draft_and_audit_no_gateway_offline(db):
    s, run_id = db
    from vapt_orch.graph.drafting import draft_and_audit  # noqa: PLC0415
    text, used, diag = draft_and_audit(
        db=s, run_id=run_id, gateway=None, manifest=manifests.REPORTING,
        messages=[{"role": "user", "content": "test"}],
        record_model_calls=False,
    )
    assert used is False
    assert diag == {"reason": "no_gateway"}


# ---------------------------------------------------------------------------
# 9. Qwen3 reasoning-content quirk: content='' + reasoning_content!='' → use rc
# ---------------------------------------------------------------------------
def test_gateway_extract_text_returns_empty_not_repr_dump():
    """Regression: when content AND reasoning_content are both empty, the gateway must
    return an empty string so the caller treats it as "no text" and renders the UI's
    'No executive summary was generated' fallback. The previous `str(result)` behaviour
    leaked the raw LangChain message repr into the report page, dumping
    "content='' additional_kwargs={...} finish_reason='length'..." as the exec summary.
    This confirms the empty-text contract."""
    from vapt_llm.gateway import LLMGateway  # noqa: PLC0415

    class _Truncated:
        content = ""
        additional_kwargs = {"refusal": None}
        response_metadata = {"finish_reason": "length"}
        def __str__(self):
            # If any code path leaks str(self) into the report, this would appear verbatim.
            return "SHOULD-NOT-APPEAR-IN-REPORT"
    assert LLMGateway._extract_text(_Truncated()) == ""


def test_gateway_extracts_reasoning_content_for_qwen3():
    """Qwen3-family reasoning models return the completion in
    additional_kwargs['reasoning_content'] instead of .content. Confirmed on
    Qwen3.6-35B-A3B-S via the LiteLLM proxy — ledger showed `finish_reason=stop
    latency_ms=14366` with source=deterministic because the gateway was pulling
    the empty .content field. The fix is to fall back to reasoning_content."""
    from vapt_llm.gateway import LLMGateway  # noqa: PLC0415

    class _MockMsg:
        def __init__(self, content, reasoning):
            self.content = content
            self.additional_kwargs = {"reasoning_content": reasoning}

    # Empty content + reasoning_content present → use reasoning_content
    msg = _MockMsg("", "This is the actual response that was in reasoning.")
    assert LLMGateway._extract_text(msg) == "This is the actual response that was in reasoning."
    # Content present → use it (don't override with reasoning)
    msg2 = _MockMsg("direct answer", "unused reasoning")
    assert LLMGateway._extract_text(msg2) == "direct answer"
    # Both empty → fall back to str() so caller sees something non-empty for debugging
    msg3 = _MockMsg("", "")
    result = LLMGateway._extract_text(msg3)
    assert isinstance(result, str)


# ---------------------------------------------------------------------------
# 10. sstimap diagnostic when zero findings
# ---------------------------------------------------------------------------
def test_gateway_per_profile_max_output_tokens_override():
    """Reporting on Qwen3 needs 8192 output tokens (reasoning burns ~2-4k before any
    text), while planning on gpt-oss-20b is fine with the 4096 default. The gateway
    must honour VAPT_LLM_REPORTING_MAX_OUTPUT_TOKENS without affecting other profiles."""
    import os
    from vapt_llm import profiles_from_env  # noqa: PLC0415

    saved = {k: os.environ.get(k) for k in (
        "VAPT_LLM_PROVIDER", "VAPT_LLM_BASE_URL", "VAPT_LLM_MODEL",
        "VAPT_LLM_API_KEY_ENV", "VAPT_LLM_REPORTING_MAX_OUTPUT_TOKENS",
    )}
    try:
        os.environ["VAPT_LLM_PROVIDER"] = "openai"
        os.environ["VAPT_LLM_BASE_URL"] = "http://x/v1"
        os.environ["VAPT_LLM_MODEL"] = "test-model"
        os.environ["VAPT_LLM_API_KEY_ENV"] = "VAPT_LLM_API_KEY_ENV"  # self-ref dummy
        os.environ["VAPT_LLM_REPORTING_MAX_OUTPUT_TOKENS"] = "8192"
        profs = profiles_from_env()
        assert profs["reporting"].max_output_tokens == 8192
        # Planning stays at the default (4096 after today's bump)
        assert profs["planning"].max_output_tokens == 4096
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def test_wapiti_route_respects_host_port(db):
    """Regression: wapiti ran on port 5000 against DineHub and reported `/fetch/logo`.
    `discovered_endpoint_urls` was joining the path to the current base URL (port 80 IIS)
    which made the probe plan hit `http://host/fetch/logo` → 404 instead of
    `http://host:5000/fetch/logo` → the real sink. Fix: use wapiti observation's
    detail.host (parsed from http_request's Host header) to scope the path to its
    actual origin base."""
    s, run_id = db
    # Seed a wapiti finding whose Host header says port 5000
    f = Finding(run_id=run_id, title="wapiti: Unencrypted Channels at /fetch/logo",
                status="candidate", severity="medium")
    s.add(f); s.flush()
    s.add(FindingObservation(finding_id=f.id, source_tool="wapiti",
                             detail={"host": "172.25.188.23:5000",
                                     "path": "/fetch/logo"}))
    s.commit()

    # Probing against port-80 base must SKIP the port-5000 wapiti finding
    eps_80 = phases.discovered_endpoint_urls(
        s, _scope(run_id), base_url="http://172.25.188.23", cap=10)
    assert not any("/fetch/logo" in u for u in eps_80), (
        f"port-80 base should not include port-5000 wapiti route, got {eps_80}")

    # Probing against port-5000 base MUST include it
    eps_5000 = phases.discovered_endpoint_urls(
        s, _scope(run_id), base_url="http://172.25.188.23:5000", cap=10)
    assert any("/fetch/logo" in u for u in eps_5000), (
        f"port-5000 base should include its own wapiti route, got {eps_5000}")


def test_web_param_probe_normalizer_handles_none_statuses():
    """Regression: a probe that hits a DNS failure / connection-refused records
    status=None in its trace. Python 3's sorted() can't compare None vs int, so the
    normalizer used to raise TypeError and crash the whole webvuln node (observed as
    a Celery task failure on auto-approve runs). Fix: sort key coerces None to last."""
    out = json.dumps({
        "findings": [],
        "trace": [
            {"url": "http://h/x?p=1", "status": 404, "cls": "open_redirect"},
            {"url": "http://h/x?p=2", "status": None, "cls": "ssrf_blind_oast",
             "note": "err:ConnectionError"},
            {"url": "http://h/x?p=3", "status": 200, "cls": "open_redirect"},
        ],
    })
    obs = normalize("web_param_probe", [{"stdout": out}])
    assert len(obs) == 1
    assert obs[0].severity == "info"
    assert "statuses=" in obs[0].title


def test_idor_builder_accepts_id_bearing_urls_only():
    from vapt_tools import REGISTRY
    # Mix of ID-bearing + non-ID + off-scope URLs → builder keeps only in-scope ID ones
    argv = REGISTRY.get("idor_probe").build_argv({
        "target": "example.com",
        "urls": ",".join([
            "http://example.com/order/42",   # ✓ id-bearing in-scope
            "http://example.com/register",   # ✗ no numeric id
            "http://example.com/user/7/pw",  # ✓ id-bearing
            "http://evil.com/order/1",       # ✗ off-scope
            "http://example.com:5000/receipt/13",  # ✓ (same host)
        ]),
    })
    assert argv[0].endswith("vapt-idor-probe")
    assert "--target" in argv and "example.com" in argv
    joined = ",".join(argv)
    assert "/order/42" in joined and "/user/7/pw" in joined and "/receipt/13" in joined
    assert "/register" not in joined and "evil.com" not in joined


def test_idor_builder_rejects_empty_urls():
    import pytest as _pytest
    from vapt_tools import REGISTRY
    with _pytest.raises(ValueError):
        REGISTRY.get("idor_probe").build_argv({"target": "example.com", "urls": ""})
    with _pytest.raises(ValueError):
        REGISTRY.get("idor_probe").build_argv({"target": "example.com",
                                                "urls": "http://example.com/no-id"})


def test_idor_normalizer_confirmed_promotes():
    out = json.dumps({"findings": [
        {"type": "idor", "severity": "high",
         "url": "http://h/order/42", "param": "id=42",
         "evidence": "user B accessed user A's order (body differs)",
         "confirmed": True},
    ]})
    obs = normalize("idor_probe", [{"stdout": out}])
    assert len(obs) == 1
    assert obs[0].severity == "high"
    assert obs[0].detail["confirmed"] is True
    assert "confirmed" in obs[0].title


def test_idor_normalizer_empty_emits_diagnostic():
    out = json.dumps({"findings": [], "trace": [
        {"url": "http://h/order/42", "status": 200, "note": "A"},
        {"url": "http://h/order/42", "status": 403, "note": "B"},
    ]})
    obs = normalize("idor_probe", [{"stdout": out}])
    assert len(obs) == 1
    assert obs[0].severity == "info"
    assert "no cross-tenant" in obs[0].title


def test_scan_manifest_offers_idor_probe():
    assert "idor_probe" in manifests.SCAN.allowed_tool_ids


def test_is_file_sink_route_identifies_fetch_logo():
    """The file-sink detector must flag the exact DineHub route that catches SSRF via
    `url` param. If this ever returns False for /fetch/logo, the probe planner will drop
    it from the always-probe tier and we're back to 3/20."""
    assert phases.is_file_sink_route("http://x:5000/fetch/logo") is True
    assert phases.is_file_sink_route("http://x:5000/download") is True
    assert phases.is_file_sink_route("http://x:5000/view/42") is True
    assert phases.is_file_sink_route("http://x:5000/image/get") is True
    # Not a sink
    assert phases.is_file_sink_route("http://x:5000/") is False
    assert phases.is_file_sink_route("http://x:5000/register") is False
    assert phases.is_file_sink_route("http://x:5000/admin/announcement") is False


def test_harness_summarizes_args_for_ledger():
    """action.proposed must carry a short, whitelisted args summary so operators can
    distinguish 15 web_param_probe invocations by WHICH route each targeted. Credentials
    must never appear; large values must be capped."""
    from vapt_harness.harness import _summarize_args
    assert _summarize_args({"url": "http://h/x", "param": "q", "password": "secret"}) == {
        "url": "http://h/x", "param": "q",
    }
    # Lists serialized compact
    out = _summarize_args({"seeds": ["http://h/a", "http://h/b"]})
    assert "http://h/a" in out["seeds"] and "http://h/b" in out["seeds"]
    # Capped
    long_seeds = ["http://h/x" * 50]
    out = _summarize_args({"seeds": long_seeds})
    assert len(out["seeds"]) <= 201  # 200 + ellipsis


def test_sstimap_empty_emits_diagnostic():
    obs = normalize("ssti_detect", [{
        "stdout": "[I] Testing complete, no injection found.\n",
        "stderr": "DEBUG: tried engine Jinja2 — no payload rendered\n",
    }])
    assert len(obs) == 1
    assert obs[0].severity == "info"
    assert "no SSTI detected" in obs[0].title
    assert "no payload rendered" in obs[0].detail["stderr_tail"]


# ---------------------------------------------------------------------------
# 11. End-to-end narrative: given a full DineHub fixture bundle, verify
#    all key signals land in the DB and the planner would pick the right
#    targets. This is the "40-min run in 50ms" check.
# ---------------------------------------------------------------------------
def test_end_to_end_dinehub_signals(db):
    s, run_id = db
    _seed_httpx(s, run_id, FIXTURES["httpx_dinehub"])
    _seed_wapiti(s, run_id, FIXTURES["wapiti_dinehub"])

    # Engine resolves (unblocks ssti_detect)
    assert phases.infer_template_engine(s, run_id) == "Jinja2"

    # Wapiti XSS target captured (feeds ssti_detect + dalfox planners)
    xss = phases.wapiti_xss_targets(s, run_id)
    assert len(xss) == 1

    # /fetch/logo discoverable (feeds web_param_probe planners)
    urls = phases.discovered_endpoint_urls(
        s, _scope(run_id), base_url="http://172.25.188.23:5000", cap=10)
    assert any("/fetch/logo" in u for u in urls)

    # dalfox-verified payload normalizes correctly
    d_obs = normalize("dalfox", [{"stdout": FIXTURES["dalfox_verified"]}])
    assert d_obs and d_obs[0].detail["confirmed"] is True

    # web_param_probe SSRF normalizes correctly
    wp_obs = normalize("web_param_probe",
                       [{"stdout": FIXTURES["web_param_probe_ssrf_confirmed"]}])
    assert wp_obs and wp_obs[0].detail["class"] == "ssrf_localhost"
