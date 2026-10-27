"""Provider-independent LLM gateway (plan §9).

Agents depend on this interface, never directly on Ollama/OpenAI. The gateway owns
application-specific routing, data-class guarantees and usage accounting. LangChain
supplies the provider integrations behind each profile.

A model response NEVER executes its own tool calls directly — callers receive a
normalized decision and remain responsible for policy + brokering.
"""
from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass, field
from typing import Any

# Patterns for secrets that must never surface in a stored error or a log line.
_SECRET_PATTERNS = (
    re.compile(r"\bBearer\s+[A-Za-z0-9._\-]+", re.IGNORECASE),
    re.compile(r"\bsk-[A-Za-z0-9._\-]{6,}"),
    re.compile(r"(?i)(api[_-]?key|authorization|token|password|secret)\s*[=:]\s*\S+"),
)


def redact_secrets(text: str | None, *extra_values: str) -> str | None:
    """Mask API keys / bearer tokens in free text before it is stored or logged.

    Masks the literal secret values passed in `extra_values` (e.g. the resolved API
    key) plus common key/token shapes. Returns None unchanged so callers can store
    'no error' as NULL."""
    if not text:
        return text
    out = text
    for val in extra_values:
        if val and len(val) >= 4:
            out = out.replace(val, "***redacted***")
    for pat in _SECRET_PATTERNS:
        out = pat.sub("***redacted***", out)
    return out


@dataclass
class ModelProfileConfig:
    profile_id: str
    provider: str                       # "ollama" | "openai" | ...
    model_id: str
    endpoint: str | None = None
    api_key_ref: str | None = None   # reference, not the secret itself
    temperature: float = 0.0
    timeout_s: int = 60
    max_output_tokens: int = 2048
    allowed_data_classes: list[str] = field(default_factory=lambda: ["standard"])
    fallback_profile: str | None = None
    prompt_version: str = "v1"


@dataclass
class GatewayResponse:
    text: str
    parsed: dict | None
    profile_id: str
    provider: str
    model_id: str
    finish_reason: str
    usage: dict
    latency_ms: int
    trace_id: str
    error: str | None = None
    fallback_used: bool = False      # True if a fallback profile served this response


class LLMGateway:
    """Resolves a profile to a LangChain chat model and returns a normalized response.

    Fallback may never widen data permissions: local-only engagement content cannot
    silently be routed to a hosted provider.
    """

    def __init__(self, profiles: dict[str, ModelProfileConfig]):
        self._profiles = profiles
        self._clients: dict[str, Any] = {}

    def _build_client(self, cfg: ModelProfileConfig):
        if cfg.provider == "ollama":
            from langchain_ollama import ChatOllama

            return ChatOllama(
                model=cfg.model_id,
                base_url=cfg.endpoint or "http://localhost:11434",
                temperature=cfg.temperature,
                # Ollama caps generation via num_predict.
                num_predict=cfg.max_output_tokens or None,
            )
        if cfg.provider == "openai":
            from langchain_openai import ChatOpenAI

            # Local OpenAI-compatible servers (vLLM, llama.cpp, LM Studio, Ollama's
            # /v1) usually need no key, but the client requires a non-empty value.
            api_key = os.environ.get(cfg.api_key_ref or "OPENAI_API_KEY", "") or "not-needed"
            return ChatOpenAI(
                model=cfg.model_id,
                api_key=api_key,
                base_url=cfg.endpoint,
                temperature=cfg.temperature,
                timeout=cfg.timeout_s,
                max_retries=1,
                max_tokens=cfg.max_output_tokens or None,
            )
        raise ValueError(f"unsupported provider: {cfg.provider}")

    def _client(self, cfg: ModelProfileConfig):
        if cfg.profile_id not in self._clients:
            self._clients[cfg.profile_id] = self._build_client(cfg)
        return self._clients[cfg.profile_id]

    @staticmethod
    def _extract_text(result) -> str:
        """Pull the response text out of a LangChain message, handling the Qwen3-family
        reasoning-model quirk where output goes to `additional_kwargs['reasoning_content']`
        instead of `.content`. Confirmed on Qwen3.6-35B-A3B-S via the LiteLLM proxy:
        plain `.content` is often empty while `latency_ms=14000` and `finish_reason=stop`
        signal a successful call — the actual text is in reasoning_content.

        Resolution order: content → reasoning_content → str(result). The first non-empty
        wins so a model that fills both (some proxies normalize into content) still works."""
        text = getattr(result, "content", "") or ""
        if isinstance(text, str) and text.strip():
            return text
        # Reasoning-model fallback: Qwen3 / DeepSeek-R1 variants put the completion here.
        add = getattr(result, "additional_kwargs", {}) or {}
        rc = add.get("reasoning_content") or add.get("reasoning")
        if isinstance(rc, str) and rc.strip():
            return rc
        # Response-metadata fallback (some LiteLLM profiles stash the text there).
        meta = getattr(result, "response_metadata", {}) or {}
        rc2 = meta.get("reasoning_content")
        if isinstance(rc2, str) and rc2.strip():
            return rc2
        # Nothing usable in content / reasoning_content / response_metadata — return the
        # empty string so the caller treats this as "model returned nothing" and surfaces
        # a clean fallback. The old `str(result)` leaked the LangChain repr dump into the
        # report ("content='' additional_kwargs={...}") which is worse than no text at all.
        return ""

    @staticmethod
    def _extract_json(text: str) -> dict | None:
        """Bounded repair: pull the first balanced JSON object out of a reply.

        Models often wrap JSON in prose or fences. This does not 'fix' malformed
        JSON — it only locates it. Invalid JSON stays invalid, and the caller sees
        finish_reason=invalid_schema rather than a silently wrong decision.
        """
        import json as _json

        if not text:
            return None
        start = text.find("{")
        while start != -1:
            depth = 0
            for i in range(start, len(text)):
                if text[i] == "{":
                    depth += 1
                elif text[i] == "}":
                    depth -= 1
                    if depth == 0:
                        try:
                            obj = _json.loads(text[start : i + 1])
                            return obj if isinstance(obj, dict) else None
                        except Exception:
                            break
            start = text.find("{", start + 1)
        return None

    def _structured(self, client, lc_messages, output_schema: dict):
        """Try native structured output, else fall back to prompt + JSON extraction."""
        import json as _json

        try:
            structured = client.with_structured_output(output_schema)
            result = structured.invoke(lc_messages)
            if isinstance(result, dict):
                return result, _json.dumps(result), {}
            if hasattr(result, "model_dump"):
                d = result.model_dump()
                return d, _json.dumps(d), {}
        except Exception:
            pass  # server/model lacks schema support — fall through

        schema_hint = _json.dumps(output_schema)
        nudged = list(lc_messages) + [
            (
                "user",
                "Reply with a single JSON object and nothing else. "
                f"It must match this JSON Schema: {schema_hint}",
            )
        ]
        result = client.invoke(nudged)
        text = self._extract_text(result)
        usage = getattr(result, "usage_metadata", {}) or {}
        return self._extract_json(text), text, usage

    def invoke(
        self,
        profile_id: str,
        messages: list[dict],
        output_schema: dict | None = None,
        data_class: str = "standard",
        context: dict | None = None,
        _visited: set[str] | None = None,
    ) -> GatewayResponse:
        cfg = self._profiles.get(profile_id)
        if cfg is None:
            raise KeyError(f"unknown model profile: {profile_id}")
        if data_class not in cfg.allowed_data_classes:
            raise PermissionError(
                f"profile {profile_id} not permitted for data class {data_class!r}"
            )

        resp = self._invoke_once(cfg, messages, output_schema)

        # Fallback: only on a real failure, only to a configured profile, only once per
        # profile, and ONLY if that fallback is itself permitted for this data class.
        # A local-only data class can never be silently routed to a hosted fallback.
        failed = bool(resp.error) or resp.finish_reason in ("error", "invalid_schema")
        if failed and cfg.fallback_profile:
            visited = _visited or {profile_id}
            fb = self._profiles.get(cfg.fallback_profile)
            if (
                fb is not None
                and cfg.fallback_profile not in visited
                and data_class in fb.allowed_data_classes   # never widen
            ):
                visited.add(cfg.fallback_profile)
                fb_resp = self.invoke(
                    cfg.fallback_profile, messages, output_schema, data_class, context, visited
                )
                fb_resp.fallback_used = True
                # Keep the fallback only if it actually succeeded; else keep the primary error.
                if not fb_resp.error and (output_schema is None or fb_resp.parsed is not None):
                    return fb_resp
        return resp

    def _invoke_once(
        self,
        cfg: ModelProfileConfig,
        messages: list[dict],
        output_schema: dict | None,
    ) -> GatewayResponse:
        trace_id = f"{cfg.profile_id}-{int(time.time()*1000)}"
        started = time.time()
        # The resolved secret value, so we can scrub it from any error text.
        secret = os.environ.get(cfg.api_key_ref or "", "")
        try:
            client = self._client(cfg)
            lc_messages = [(m["role"], m["content"]) for m in messages]

            if output_schema is not None:
                # Schema-constrained decision. Not every model/server supports this;
                # on failure we fall back to a plain call plus bounded JSON repair so
                # a weaker model degrades instead of breaking the run.
                parsed, text, usage = self._structured(client, lc_messages, output_schema)
                latency = int((time.time() - started) * 1000)
                return GatewayResponse(
                    text=text,
                    parsed=parsed,
                    profile_id=cfg.profile_id,
                    provider=cfg.provider,
                    model_id=cfg.model_id,
                    finish_reason="stop" if parsed is not None else "invalid_schema",
                    usage=usage,
                    latency_ms=latency,
                    trace_id=trace_id,
                    error=None if parsed is not None else "model did not return valid JSON",
                )

            result = client.invoke(lc_messages)
            text = self._extract_text(result)
            latency = int((time.time() - started) * 1000)
            # Prefer the LLM's own finish_reason over a hardcoded "stop" — a Qwen3
            # reasoning run that hit the output cap mid-reasoning reports 'length' with
            # empty content; the hardcoded "stop" previously hid that from operators.
            meta = getattr(result, "response_metadata", {}) or {}
            real_finish = str(meta.get("finish_reason") or "stop")
            err = None
            if not text and real_finish == "length":
                err = ("output truncated at max_output_tokens before any content was "
                       "emitted; raise VAPT_LLM_MAX_OUTPUT_TOKENS for this profile")
            return GatewayResponse(
                text=text,
                parsed=None,
                profile_id=cfg.profile_id,
                provider=cfg.provider,
                model_id=cfg.model_id,
                finish_reason=real_finish,
                usage=getattr(result, "usage_metadata", {}) or {},
                latency_ms=latency,
                trace_id=trace_id,
                error=err,
            )
        except Exception as exc:  # outage / transport error -> normalized, redacted error
            latency = int((time.time() - started) * 1000)
            return GatewayResponse(
                text="",
                parsed=None,
                profile_id=cfg.profile_id,
                provider=cfg.provider,
                model_id=cfg.model_id,
                finish_reason="error",
                usage={},
                latency_ms=latency,
                trace_id=trace_id,
                error=redact_secrets(str(exc), secret),
            )
