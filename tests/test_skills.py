"""Skill registry + planner-enrichment tests (Batch 1).

Load-time invariants: every shipped SKILL.md parses, every `tools_available` id
resolves to the live `vapt_tools.REGISTRY`, every `phase` is a valid `AgentRole`.

Retrieval: `find_skills` filters by phase and ranks on target-kind overlap +
auth-sensitivity + confidence.

Planner integration: the skill-hint block is injected into the user prompt, but
a model-proposed step naming a tool_id outside the manifest's allowed set is
STILL dropped — the skill library does not widen governance.

Isolation: no code path in `vapt_skills` lets a skill body reach the tool broker.
"""
from __future__ import annotations

import re

from vapt_agents import planner
from vapt_agents.manifests import PLANNING, SCAN
from vapt_agents.runscope import RunScope
from vapt_domain.enums import AgentRole, PolicyClass, TestingMode
from vapt_llm import GatewayResponse
from vapt_skills import SKILL_REGISTRY, find_skills, format_skill_hints
from vapt_skills.registry import SkillLoadError, SkillRegistry
from vapt_tools import REGISTRY


def _scope() -> RunScope:
    return RunScope(
        run_id="r1", testing_mode=TestingMode.BLACK_BOX, target="example.com",
        domains=["example.com"], ip_cidrs=[],
        allowed_action_classes=[PolicyClass.P0_PASSIVE, PolicyClass.P1_LOW_IMPACT],
    )


class _FakeGateway:
    def __init__(self, parsed):
        self._parsed = parsed
        self.last_messages = None

    def invoke(self, profile_id, messages, output_schema=None, data_class="standard", context=None):
        self.last_messages = messages
        return GatewayResponse(
            text="", parsed=self._parsed, profile_id="planning", provider="openai",
            model_id="m", finish_reason="stop" if self._parsed is not None else "error",
            usage={"total_tokens": 1}, latency_ms=1, trace_id="t", error=None,
        )


# --------------------------------------------------------------------------- #
# Load-time invariants
# --------------------------------------------------------------------------- #
def test_shipped_library_loads_at_least_batch_1():
    # Batch 1 ships 15 skills; adding more should never remove this many.
    assert len(SKILL_REGISTRY) >= 15


def test_every_skill_tool_resolves_to_live_registry():
    known = {s.id for s in REGISTRY.all()}
    for skill in SKILL_REGISTRY.all():
        unknown = [t for t in skill.tools_available if t not in known]
        assert not unknown, (
            f"{skill.id} ({skill.source_path}) names unknown tool_ids: {unknown}. "
            f"Either register the tool or drop it from this skill."
        )


def test_every_skill_phase_is_a_valid_agent_role():
    valid = {r.value for r in AgentRole}
    for skill in SKILL_REGISTRY.all():
        assert skill.phase in valid, (
            f"{skill.id}: phase {skill.phase!r} is not an AgentRole value"
        )


def test_batch_1_covers_the_core_phases():
    # Non-regression guard: Batch 1 is supposed to span recon→scan→validate→
    # attack→reporting. If a phase disappears, the planner-enrichment hook
    # silently emits nothing for it — fail loudly here instead.
    phases_present = {s.phase for s in SKILL_REGISTRY.all()}
    for required in ("recon", "scan", "validate", "attack", "reporting"):
        assert required in phases_present, f"Batch 1 is missing phase {required!r}"


def test_loader_rejects_unknown_tool_id(tmp_path):
    bad = tmp_path / "library" / "scan"
    bad.mkdir(parents=True)
    (bad / "bogus.md").write_text(
        "---\n"
        "id: scan-bogus\n"
        "title: nope\n"
        "phase: scan\n"
        "when_to_use: never\n"
        "tools_available: [this_tool_does_not_exist]\n"
        "---\nbody\n",
        encoding="utf-8",
    )
    try:
        SkillRegistry.load(tmp_path / "library")
    except SkillLoadError as e:
        assert "unknown tool_id" in str(e)
    else:
        raise AssertionError("expected SkillLoadError for unknown tool_id")


def test_loader_rejects_unknown_phase(tmp_path):
    bad = tmp_path / "library"
    bad.mkdir()
    (bad / "x.md").write_text(
        "---\n"
        "id: xyz\n"
        "title: t\n"
        "phase: not_an_agent_role\n"
        "when_to_use: n\n"
        "tools_available: [http_probe]\n"
        "---\n",
        encoding="utf-8",
    )
    try:
        SkillRegistry.load(bad)
    except SkillLoadError as e:
        assert "phase" in str(e)
    else:
        raise AssertionError("expected SkillLoadError for bad phase")


# --------------------------------------------------------------------------- #
# Retrieval
# --------------------------------------------------------------------------- #
def test_find_skills_filters_by_phase():
    scan_only = find_skills(phase="scan", limit=100)
    assert scan_only
    assert all(s.phase == "scan" for s in scan_only)
    recon_only = find_skills(phase="recon", limit=100)
    assert recon_only
    assert all(s.phase == "recon" for s in recon_only)
    # The two sets must be disjoint — a skill belongs to one phase.
    assert {s.id for s in scan_only}.isdisjoint({s.id for s in recon_only})


def test_find_skills_prefers_matching_target_kinds():
    web_hits = find_skills(phase="scan", target_kinds=["web"], limit=10)
    assert web_hits
    for s in web_hits:
        assert "web" in s.target_kinds, (s.id, s.target_kinds)


def test_find_skills_is_deterministic():
    # Same inputs → same ordered output. This is the invariant the planner relies on
    # (so a run's prompt digest is stable across retries); scoring + id tiebreak must
    # not drift.
    args = dict(phase="scan", target_kinds=["web"], auth_detected=True, limit=5)
    first = [s.id for s in find_skills(**args)]
    second = [s.id for s in find_skills(**args)]
    assert first == second


def test_find_skills_ranks_high_confidence_above_medium():
    # scan-sqli-detection is the only medium-confidence scan skill in Batch 1; the
    # web+auth query should place it strictly after at least one high-confidence
    # scan skill with the same target_kinds + auth_sensitive match.
    hits = [s.id for s in find_skills(
        phase="scan", target_kinds=["web"], auth_detected=True, limit=100,
    )]
    assert "scan-sqli-detection" in hits
    assert "scan-web-dast" in hits
    assert hits.index("scan-sqli-detection") > hits.index("scan-web-dast")


def test_format_skill_hints_header_mentions_governance():
    hints = format_skill_hints(phase="scan", target_kinds=["web"], auth_detected=True, limit=3)
    assert hints
    # The header must make the governance invariant explicit — a prompt-injection
    # attempt in a skill body would otherwise have a surface to argue from.
    assert "tool_ids must still come from Available tools" in hints


def test_format_skill_hints_empty_when_no_match():
    # No skills exist for the planning phase (planner is the consumer, not the content).
    assert format_skill_hints(phase="planning") == ""


# --------------------------------------------------------------------------- #
# Planner integration
# --------------------------------------------------------------------------- #
def test_planner_injects_skill_hints_into_user_prompt():
    gw = _FakeGateway({"steps": [{"tool_id": "nmap_service_scan", "rationale": "x"}]})
    planner.plan_scan(gw, _scope())
    assert gw.last_messages is not None
    user_msg = gw.last_messages[-1]["content"]
    # The skill hint block is marked by its header; its presence means the planner
    # pulled from vapt_skills, not from a hardcoded string.
    assert "Reference knowledge" in user_msg
    # And at least one scan-phase skill id must appear. We don't name specific ids
    # here — the library grows, and the top-N ranking may float different skills
    # in. The invariant is that SOME scan skill made it into the user prompt.
    scan_ids = [s.id for s in SKILL_REGISTRY.all() if s.phase == "scan"]
    assert any(sid in user_msg for sid in scan_ids), (
        "no scan-phase skill id appears in the planner user prompt"
    )


def test_planner_system_prompt_reinforces_governance():
    gw = _FakeGateway({"steps": [{"tool_id": "nmap_service_scan", "rationale": "x"}]})
    planner.plan_scan(gw, _scope())
    system_msg = gw.last_messages[0]["content"]
    assert "ONLY the tool_ids" in system_msg
    assert "does NOT widen" in system_msg


def test_skills_cannot_widen_the_manifest_even_when_hinted():
    # A skill names tool_ids the SCAN manifest permits. The model, however, could
    # still try to schedule something outside the manifest (e.g. sqlmap, which is
    # catalogued ATTACK-only). The planner's drop-rules must filter it even with
    # the enrichment hook active. This is the load-bearing isolation property.
    parsed = {"steps": [
        {"tool_id": "nmap_service_scan", "rationale": "ok"},
        {"tool_id": "sqlmap", "rationale": "should be dropped: ATTACK-only"},
        {"tool_id": "nuclei_intrusive", "rationale": "should be dropped: above planner ceiling"},
    ]}
    gw = _FakeGateway(parsed)
    res = planner.plan_scan(gw, _scope(), planning=PLANNING, scan=SCAN)
    kept = [a.tool_id for a in res.actions]
    assert "sqlmap" not in kept
    assert "nuclei_intrusive" not in kept
    assert "nmap_service_scan" in kept


# --------------------------------------------------------------------------- #
# Isolation — skill text never reaches the broker
# --------------------------------------------------------------------------- #
def test_skills_package_has_no_subprocess_or_broker_imports():
    """A skill is reference text, not a tool invocation. The package must not
    import anything that could execute a shell command, nor the broker that runs
    the governed argv. Any accidental coupling here would make skill bodies a
    potential path to execution (a prompt-injection surface we rejected by
    design)."""
    import vapt_skills
    pkg_path = __import__("pathlib").Path(vapt_skills.__file__).parent
    for py in pkg_path.rglob("*.py"):
        text = py.read_text(encoding="utf-8")
        for forbidden in ("import subprocess", "from subprocess",
                          "import vapt_tools.broker", "from vapt_tools.broker",
                          "os.system(", "os.popen("):
            assert forbidden not in text, (
                f"{py}: forbidden coupling {forbidden!r} — skills must stay reference-only"
            )


def test_skill_bodies_contain_no_executable_shell_lines():
    # Belt-and-braces: a shipped SKILL.md must not include lines that LOOK like a
    # ready-to-paste shell command of a governed binary (we don't want contributors
    # to drift the library toward copy-paste commands over governed tool_ids).
    # A literal shell line starts with the binary followed by a flag or a URL —
    # e.g. "wapiti -u http://...", "nuclei --dast". Prose like "wapiti re-login
    # mid-scan" is fine; the test is for copy-paste commands, not references.
    bad_line = re.compile(
        r"^\s*(wapiti|nuclei|arjun|katana|feroxbuster|sqlmap|dalfox|nmap)\s+-"
    )
    for skill in SKILL_REGISTRY.all():
        for i, line in enumerate(skill.body.splitlines(), start=1):
            assert not bad_line.match(line), (
                f"{skill.source_path}:{i}: body looks like a shell command "
                f"({line.strip()!r}); describe the tool_id by name, not an argv"
            )
