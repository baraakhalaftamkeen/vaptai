"""Build model profiles from environment settings.

One source of truth so the API, the orchestrator and the smoke test all talk to the
same endpoint with the same limits. Secrets are referenced by env-var NAME, never
inlined into a profile.

Environment:
  VAPT_LLM_PROVIDER     ollama | openai        (openai = any OpenAI-compatible server)
  VAPT_LLM_BASE_URL     e.g. http://10.0.0.5:11434  or  http://10.0.0.5:8000/v1
  VAPT_LLM_MODEL        e.g. qwen2.5:14b-instruct
  VAPT_LLM_API_KEY_ENV  name of the env var holding the key (default OPENAI_API_KEY)
  VAPT_LLM_TIMEOUT_S    request timeout, default 60
  VAPT_LLM_DATA_CLASSES comma list of permitted data classes, default "standard"
"""
from __future__ import annotations

import os

from .gateway import ModelProfileConfig

# Task-shaped profiles. They can point at different models later; for now a single
# endpoint backs all three, which keeps the agent code unchanged when that changes.
PROFILE_PLANNING = "planning"
PROFILE_VALIDATION = "validation"
PROFILE_REPORTING = "reporting"


def profiles_from_env(prefix: str = "VAPT_LLM_") -> dict[str, ModelProfileConfig]:
    provider = os.environ.get(f"{prefix}PROVIDER", "ollama").strip().lower()
    base_url = os.environ.get(f"{prefix}BASE_URL", "").strip() or None
    model = os.environ.get(f"{prefix}MODEL", "").strip()
    key_env = os.environ.get(f"{prefix}API_KEY_ENV", "OPENAI_API_KEY").strip()
    timeout_s = int(os.environ.get(f"{prefix}TIMEOUT_S", "60"))
    # Default 4096 (was 2048). Qwen3-family and other reasoning models can spend
    # 2k+ tokens on hidden chain-of-thought before any content leaves the model, so the
    # old 2048 cap silently truncated reports to empty with finish_reason='length'.
    # Operators can override globally with VAPT_LLM_MAX_OUTPUT_TOKENS or per-profile
    # with VAPT_LLM_PLANNING_MAX_OUTPUT_TOKENS / _VALIDATION_ / _REPORTING_.
    max_out = int(os.environ.get(f"{prefix}MAX_OUTPUT_TOKENS", "4096"))
    data_classes = [
        c.strip()
        for c in os.environ.get(f"{prefix}DATA_CLASSES", "standard").split(",")
        if c.strip()
    ]

    if not model:
        raise ValueError(f"{prefix}MODEL is not set — the gateway needs a model id")

    def model_for(profile_id: str) -> str:
        # Optional per-profile override, e.g. VAPT_LLM_PLANNING_MODEL=gpt-oss-20b
        return os.environ.get(f"{prefix}{profile_id.upper()}_MODEL", "").strip() or model

    def max_out_for(profile_id: str) -> int:
        # Per-profile output cap — e.g. reporting on Qwen3 needs 8k because the model
        # routinely spends 2-4k tokens on reasoning before any user-visible text.
        v = os.environ.get(f"{prefix}{profile_id.upper()}_MAX_OUTPUT_TOKENS", "").strip()
        return int(v) if v else max_out

    def mk(profile_id: str, temperature: float) -> ModelProfileConfig:
        return ModelProfileConfig(
            profile_id=profile_id,
            provider=provider,
            model_id=model_for(profile_id),
            endpoint=base_url,
            api_key_ref=key_env,
            temperature=temperature,
            timeout_s=timeout_s,
            max_output_tokens=max_out_for(profile_id),
            allowed_data_classes=data_classes,
        )

    return {
        # Decision quality matters most for planning/validation -> temperature 0.
        PROFILE_PLANNING: mk(PROFILE_PLANNING, 0.0),
        PROFILE_VALIDATION: mk(PROFILE_VALIDATION, 0.0),
        # Reporting benefits from a little latitude in prose.
        PROFILE_REPORTING: mk(PROFILE_REPORTING, 0.2),
    }
