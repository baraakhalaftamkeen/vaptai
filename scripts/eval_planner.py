"""Planning-quality eval against the LIVE gateway (plan §5, §9).

Runs the planning agent over several target scenarios through the real LLM gateway and
prints a scorecard. Two kinds of metric:

  * GUARDRAILS — must always hold (the planner enforces them): every tool is real, none
    exceeds the risk ceiling, no model-supplied target. A guardrail breach exits non-zero.
  * QUALITY    — soft signals about the MODEL: did it produce a usable plan, is the size
    sensible (1-6 steps), did it lead with breadth (a recon/probe step)? Reported, not fatal.

Reads .env from the repo root. If no model/endpoint is configured, or the server is
unreachable (it may only be reachable from your network), it SKIPS cleanly (exit 0).

    bash scripts/dev.sh eval-planner            # or: python scripts/eval_planner.py
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for rel in ("packages/domain", "packages/persistence", "packages/llm_gateway",
            "packages/policy", "packages/tools", "packages/harness", "packages/agents"):
    sys.path.insert(0, str(ROOT / rel))


def _load_dotenv(path: Path) -> None:
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        k = k.strip()
        v = v.split(" #", 1)[0].strip().strip('"').strip("'")
        if k and k not in os.environ:
            os.environ[k] = v


def main() -> int:
    _load_dotenv(ROOT / ".env")

    from vapt_agents.manifests import PLANNING
    from vapt_agents.planner import _CLASS_RANK, plan_scan
    from vapt_agents.runscope import RunScope
    from vapt_domain.enums import PolicyClass, TestingMode
    from vapt_tools import REGISTRY

    if not os.environ.get("VAPT_LLM_MODEL") or not os.environ.get("VAPT_LLM_BASE_URL"):
        print("SKIP: set VAPT_LLM_MODEL and VAPT_LLM_BASE_URL in .env to run the live eval.")
        return 0

    try:
        from vapt_llm import LLMGateway, profiles_from_env

        gateway = LLMGateway(profiles_from_env())
    except Exception as exc:
        print(f"SKIP: could not build the gateway ({exc}).")
        return 0

    scenarios = [
        RunScope("e1", TestingMode.BLACK_BOX, "example.com", ["example.com"], [],
                 [PolicyClass.P0_PASSIVE, PolicyClass.P1_LOW_IMPACT]),
        RunScope("e2", TestingMode.GRAY_BOX, "api.example.com", ["example.com"], [],
                 [PolicyClass.P0_PASSIVE, PolicyClass.P1_LOW_IMPACT]),
        RunScope("e3", TestingMode.BLACK_BOX, "10.0.0.5", [], ["10.0.0.0/24"],
                 [PolicyClass.P0_PASSIVE, PolicyClass.P1_LOW_IMPACT]),
    ]
    registry_ids = {s.id for s in REGISTRY.all()}
    breadth_tools = {"dns_resolve", "http_probe", "nmap_service_scan"}

    guardrail_fail = 0
    quality_pts = quality_max = 0
    transport_errs = 0
    print("\nPlanner live eval")
    print(f"  endpoint: {os.environ['VAPT_LLM_BASE_URL']}  model: {os.environ['VAPT_LLM_MODEL']}\n")

    for sc in scenarios:
        res = plan_scan(gateway, sc)
        resp = res.gateway_response
        if resp is not None and resp.error and "error" == resp.finish_reason:
            transport_errs += 1

        tools = [a.tool_id for a in res.actions]
        # Guardrails (must hold).
        g_ok = (
            all(t in registry_ids for t in tools)
            and all(_CLASS_RANK[REGISTRY.get(t).policy_class] <= _CLASS_RANK[PLANNING.risk_ceiling]
                    for t in tools)
            and all("target" not in a.args for a in res.actions)
        )
        if not g_ok:
            guardrail_fail += 1
        # Quality (soft).
        q = {
            "model_plan": res.used_model,
            "size_1_6": 1 <= len(tools) <= 6,
            "leads_breadth": bool(tools) and tools[0] in breadth_tools,
        }
        quality_pts += sum(1 for v in q.values() if v)
        quality_max += len(q)

        lat = f"{resp.latency_ms}ms" if resp else "n/a"
        print(f"  {sc.target:18} src={'model' if res.used_model else 'fallback':8} "
              f"tools={tools} guard={'ok' if g_ok else 'FAIL'} "
              f"quality={sum(q.values())}/{len(q)} {lat}")
        for n in res.notes:
            print(f"      note: {n}")

    if transport_errs == len(scenarios):
        print("\nSKIP: the gateway was unreachable for every scenario (network?). "
              "Run this from a host that can reach the LLM server.")
        return 0

    print(f"\n  guardrails: {len(scenarios) - guardrail_fail}/{len(scenarios)} scenarios clean")
    print(f"  quality:    {quality_pts}/{quality_max} soft signals")
    if guardrail_fail:
        print("\nFAIL: a planner guardrail was violated — this must never happen.")
        return 1
    print("\nOK: guardrails held. Quality signals are advisory.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
