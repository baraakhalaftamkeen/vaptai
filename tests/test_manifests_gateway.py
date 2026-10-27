"""Agent-manifest enforcement and gateway hardening: secret redaction, manifest
budgets, and the rule that a fallback profile may never widen the data class."""
from __future__ import annotations

import pytest
from vapt_agents.manifests import (
    SCAN,
    AgentManifest,
    ManifestError,
    ManifestGuard,
    redact,
)
from vapt_domain.enums import PolicyClass
from vapt_llm import GatewayResponse, redact_secrets
from vapt_llm.gateway import LLMGateway, ModelProfileConfig


# -- redaction ---------------------------------------------------------------
def test_redact_secrets_masks_keys_and_bearer():
    msg = "auth failed: Authorization: Bearer sk-13UXhvabcdef and api_key=sk-secret9999"
    out = redact_secrets(msg, "sk-13UXhvabcdef")
    assert "sk-13UXhvabcdef" not in out
    assert "sk-secret9999" not in out
    assert "redacted" in out


def test_manifest_redact_masks_secret_fields():
    cleaned = redact(SCAN, {"target": "example.com", "authorization": "Bearer x", "api_key": "y"})
    assert cleaned["target"] == "example.com"
    assert cleaned["authorization"] == "***redacted***"
    assert cleaned["api_key"] == "***redacted***"


# -- manifest guard ----------------------------------------------------------
def test_manifest_guard_caps_iterations_and_tokens():
    m = AgentManifest(
        agent_id="t@1", role=SCAN.role, prompt_version="v1", description="",
        max_iterations=2, max_tokens=100,
    )
    g = ManifestGuard(m)
    g.step(); g.step()
    with pytest.raises(ManifestError):
        g.step()                       # third iteration over the cap

    g2 = ManifestGuard(m)
    g2.charge_tokens(60)
    with pytest.raises(ManifestError):
        g2.charge_tokens(60)           # 120 > 100


def test_manifest_within_risk_ceiling():
    assert SCAN.within_risk_ceiling(PolicyClass.P2_INTRUSIVE)       # scan may propose intrusive
    assert not SCAN.within_risk_ceiling(PolicyClass.P3_EXCLUDED)    # never excluded


# -- fallback never widens the data class ------------------------------------
def _profiles():
    local = ModelProfileConfig(
        profile_id="local", provider="openai", model_id="m",
        allowed_data_classes=["local"], fallback_profile="hosted",
    )
    hosted = ModelProfileConfig(
        profile_id="hosted", provider="openai", model_id="m",
        allowed_data_classes=["standard"],
    )
    standard = ModelProfileConfig(
        profile_id="standard", provider="openai", model_id="m",
        allowed_data_classes=["standard"], fallback_profile="hosted",
    )
    return {"local": local, "hosted": hosted, "standard": standard}


def test_fallback_blocked_when_it_would_widen_data_class(monkeypatch):
    gw = LLMGateway(_profiles())

    # Both profiles "fail" so a fallback would be attempted if allowed.
    def fake_once(cfg, messages, output_schema):
        return GatewayResponse(
            text="", parsed=None, profile_id=cfg.profile_id, provider=cfg.provider,
            model_id=cfg.model_id, finish_reason="error", usage={}, latency_ms=1,
            trace_id="t", error="boom",
        )

    monkeypatch.setattr(gw, "_invoke_once", fake_once)
    # local data class is NOT permitted on the hosted fallback -> fallback refused.
    resp = gw.invoke("local", [{"role": "user", "content": "hi"}], data_class="local")
    assert resp.error == "boom"
    assert resp.fallback_used is False
    assert resp.profile_id == "local"


def test_fallback_used_when_permitted(monkeypatch):
    gw = LLMGateway(_profiles())

    def fake_once(cfg, messages, output_schema):
        if cfg.profile_id == "standard":          # primary fails
            return GatewayResponse("", None, "standard", "openai", "m", "error", {}, 1, "t", error="boom")
        return GatewayResponse("ok", None, "hosted", "openai", "m", "stop", {}, 1, "t")  # fallback ok

    monkeypatch.setattr(gw, "_invoke_once", fake_once)
    resp = gw.invoke("standard", [{"role": "user", "content": "hi"}], data_class="standard")
    assert resp.error is None
    assert resp.fallback_used is True
    assert resp.profile_id == "hosted"
