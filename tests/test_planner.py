"""Planning agent: deterministic fallback when there is no gateway or the model output
is unusable; and strict validation of a model-proposed plan against the registry and
the manifests (unknown tools and above-ceiling intrusive tools are dropped — the model
cannot invent a tool or schedule an intrusive action)."""
from __future__ import annotations

from vapt_agents.planner import plan_scan
from vapt_agents.runscope import RunScope
from vapt_domain.enums import PolicyClass, TestingMode
from vapt_llm import GatewayResponse


def _scope():
    return RunScope(
        run_id="r1", testing_mode=TestingMode.BLACK_BOX, target="example.com",
        domains=["example.com"], ip_cidrs=[],
        allowed_action_classes=[PolicyClass.P0_PASSIVE, PolicyClass.P1_LOW_IMPACT],
    )


class FakeGateway:
    def __init__(self, response: GatewayResponse):
        self._response = response
        self.calls = 0

    def invoke(self, profile_id, messages, output_schema=None, data_class="standard", context=None):
        self.calls = self.calls + 1
        return self._response


def _resp(parsed, *, error=None):
    return GatewayResponse(
        text="", parsed=parsed, profile_id="planning", provider="openai",
        model_id="gpt-oss-20b", finish_reason="stop" if parsed is not None else "invalid_schema",
        usage={"total_tokens": 42}, latency_ms=12, trace_id="t", error=error,
    )


def test_fallback_when_no_gateway():
    res = plan_scan(None, _scope())
    assert res.used_model is False
    assert [a.tool_id for a in res.actions] == ["nmap_service_scan", "http_probe", "nuclei_safe"]


def test_model_plan_validated_and_filtered():
    parsed = {"steps": [
        {"tool_id": "nmap_service_scan", "ports": "80,443", "rationale": "service discovery"},
        {"tool_id": "rm_rf_everything", "rationale": "malicious / unknown"},
        {"tool_id": "nuclei_intrusive", "rationale": "intrusive — above planner ceiling"},
        {"tool_id": "http_probe", "rationale": "banner"},
    ]}
    gw = FakeGateway(_resp(parsed))
    res = plan_scan(gw, _scope())
    assert gw.calls == 1
    assert res.used_model is True
    kept = [a.tool_id for a in res.actions]
    assert kept == ["nmap_service_scan", "http_probe"]       # unknown + intrusive dropped
    assert any("rm_rf_everything" in n for n in res.notes)
    assert any("nuclei_intrusive" in n for n in res.notes)
    # args carried through, target never taken from the model
    nmap = res.actions[0]
    assert nmap.args.get("ports") == "80,443"
    assert "target" not in nmap.args


def test_fallback_when_model_output_unusable():
    gw = FakeGateway(_resp(None, error="model did not return valid JSON"))
    res = plan_scan(gw, _scope())
    assert res.used_model is False
    assert [a.tool_id for a in res.actions] == ["nmap_service_scan", "http_probe", "nuclei_safe"]


def test_fallback_when_all_steps_invalid():
    gw = FakeGateway(_resp({"steps": [{"tool_id": "nuclei_intrusive"}, {"tool_id": "bogus"}]}))
    res = plan_scan(gw, _scope())
    assert res.used_model is False                           # nothing survived -> default plan
    assert [a.tool_id for a in res.actions] == ["nmap_service_scan", "http_probe", "nuclei_safe"]
