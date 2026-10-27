"""Skill library (plan §5, planner enrichment).

A SKILL is reviewed, in-house REFERENCE TEXT — a short Markdown document that tells
the planning LLM when a particular technique applies, which GOVERNED tool_ids to
prefer, and what pitfalls to avoid. Skills are advisory only:

  * they never carry argv or shell commands;
  * every `tools_available` id in a skill must resolve to a real `vapt_tools.REGISTRY`
    entry — the loader fails loudly at import time otherwise, so a skill can never
    name a tool the governor doesn't know;
  * the planner reads them to orient the model, but the model is still bound by the
    AgentManifest + policy engine + human-approval gates exactly as before.

Nothing here authorizes an action. The policy engine + harness + human approval still
gate every call.
"""
from __future__ import annotations

from .registry import (
    SKILL_REGISTRY,
    SkillRegistry,
    SkillSpec,
    find_skills,
    format_skill_hints,
    framework_refs_for_tools,
)

__all__ = [
    "SKILL_REGISTRY",
    "SkillRegistry",
    "SkillSpec",
    "find_skills",
    "format_skill_hints",
    "framework_refs_for_tools",
]
