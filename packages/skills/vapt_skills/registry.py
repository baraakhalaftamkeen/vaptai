"""Skill registry + retriever.

Loads every ``library/<phase>/*.md`` SKILL file at import time, validates its
frontmatter against the live tool registry + agent-role enum, and exposes a cheap
retriever the planner can call to decorate its LLM prompt with 3-5 relevant
reference entries.

Load-time invariants (any violation raises `SkillLoadError` — fail loudly, never
silently drop a bad skill in a security product):

  1. The file has YAML frontmatter delimited by ``---`` on the first and a later line.
  2. Every required field (``id``, ``title``, ``phase``, ``when_to_use``,
     ``tools_available``) is present.
  3. ``phase`` is a valid :class:`vapt_domain.enums.AgentRole` value.
  4. Every id in ``tools_available`` exists in :data:`vapt_tools.REGISTRY`.
  5. Every entry in ``target_kinds`` is one of ``web``/``network``/``host``/``local``.
  6. Ids are globally unique within the library.

The retriever returns `SkillSpec` instances; callers consume `.title`,
`.description`, `.tools_available` and framework-tag fields. The body is kept for
future enrichment (report step) but is never fed to any argv builder — see
``tests/test_skills.py`` for the isolation assertion.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from vapt_domain.enums import AgentRole
from vapt_tools import REGISTRY

# Phase values we accept in frontmatter. Mirrors AgentRole exactly so a typo like
# "scanning" fails loudly instead of silently matching nothing at retrieval time.
_VALID_PHASES: frozenset[str] = frozenset(r.value for r in AgentRole)

# Target kinds the planner / orchestrator track. "local" = white-box source bundle;
# everything else is a network-reachable kind. Keeps this list aligned with
# ToolSpec.target_kind + the RunScope's authorized surface.
_VALID_TARGET_KINDS: frozenset[str] = frozenset({"web", "network", "host", "local"})

_VALID_CONFIDENCE: frozenset[str] = frozenset({"low", "medium", "high"})

_ID_RE = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")

# Only load SKILL.md-style files; .md keeps the Markdown preview nice in editors.
_SKILL_GLOB = "*.md"

_LIBRARY_DIR = Path(__file__).resolve().parent / "library"


class SkillLoadError(RuntimeError):
    """A SKILL file failed load-time validation. Never a soft-degrade: a bad skill is a
    contract violation that must be caught in CI, not shipped into the planner prompt."""


@dataclass(frozen=True)
class SkillSpec:
    """One parsed SKILL.md. Frontmatter + body + the on-disk source path (for errors).

    The spec is frozen; the registry is populated once at import time and treated as
    immutable thereafter, matching the pattern used by :data:`vapt_tools.REGISTRY`.
    """

    id: str
    title: str
    phase: str                                   # one of _VALID_PHASES
    when_to_use: str
    tools_available: tuple[str, ...]             # every id exists in REGISTRY (verified at load)
    target_kinds: tuple[str, ...] = ()
    auth_sensitive: bool = False
    mitre_attack: tuple[str, ...] = ()
    cwe: tuple[str, ...] = ()
    owasp: tuple[str, ...] = ()
    confidence: str = "medium"
    version: int = 1
    body: str = ""                               # markdown body AFTER the second '---'
    source_path: str = ""                        # repo-relative path, for error messages


class SkillRegistry:
    """In-memory index. Thin wrapper over a dict so test code can rebuild it from a
    temp directory (``SkillRegistry.load(path)``) without touching the module global."""

    def __init__(self) -> None:
        self._skills: dict[str, SkillSpec] = {}

    def register(self, spec: SkillSpec) -> None:
        if spec.id in self._skills:
            raise SkillLoadError(
                f"duplicate skill id {spec.id!r} "
                f"({self._skills[spec.id].source_path} vs {spec.source_path})"
            )
        self._skills[spec.id] = spec

    def get(self, skill_id: str) -> SkillSpec:
        if skill_id not in self._skills:
            raise KeyError(f"unknown skill: {skill_id}")
        return self._skills[skill_id]

    def all(self) -> list[SkillSpec]:
        return list(self._skills.values())

    def __len__(self) -> int:
        return len(self._skills)

    @classmethod
    def load(cls, library_dir: Path) -> SkillRegistry:
        """Walk ``library_dir`` and populate a fresh registry. Each immediate
        subdirectory is a phase folder (``recon/``, ``scan/`` …); files directly in
        ``library_dir`` are also honored for small libraries. Raises on the first
        validation failure — deny by default is the whole point."""
        reg = cls()
        for root, _dirs, files in sorted(_walk(library_dir)):
            for fname in sorted(files):
                if not _is_skill_file(fname):
                    continue
                path = Path(root) / fname
                try:
                    spec = _parse_skill_file(path, library_dir)
                except SkillLoadError:
                    raise
                except Exception as e:                   # pragma: no cover — defensive
                    raise SkillLoadError(f"{path}: unexpected load error: {e}") from e
                reg.register(spec)
        return reg


def _walk(root: Path):
    """Shim over os.walk that returns Path tuples sorted for deterministic load order."""
    if not root.exists():
        return
    for base, dirs, files in os.walk(root):
        dirs.sort()
        yield base, dirs, files


def _is_skill_file(name: str) -> bool:
    # One line, so callers reading the loader can see what counts as a skill file.
    return re.fullmatch(_SKILL_GLOB.replace("*", r".+") + "", name) is not None and name.endswith(".md")


def _parse_skill_file(path: Path, root: Path) -> SkillSpec:
    text = path.read_text(encoding="utf-8")
    rel = str(path.relative_to(root)) if path.is_relative_to(root) else str(path)
    front, body = _split_frontmatter(text, rel)
    data = _parse_yaml(front, rel)
    return _build_spec(data, body, rel)


def _split_frontmatter(text: str, rel: str) -> tuple[str, str]:
    # Frontmatter MUST be the first thing in the file; a leading newline/BOM is fine.
    t = text.lstrip("﻿\n\r ")
    if not t.startswith("---"):
        raise SkillLoadError(f"{rel}: missing YAML frontmatter (file must start with '---')")
    # Match the opening '---' line, then everything up to the next '---' on its own line.
    m = re.match(r"^---[ \t]*\n(.*?)\n---[ \t]*\n?", t, flags=re.DOTALL)
    if not m:
        raise SkillLoadError(f"{rel}: unterminated YAML frontmatter (no closing '---')")
    return m.group(1), t[m.end():].strip()


def _parse_yaml(front: str, rel: str) -> dict:
    try:
        data = yaml.safe_load(front) or {}
    except yaml.YAMLError as e:
        raise SkillLoadError(f"{rel}: invalid YAML frontmatter: {e}") from e
    if not isinstance(data, dict):
        raise SkillLoadError(f"{rel}: frontmatter must be a YAML mapping")
    return data


def _as_str_tuple(value, *, field_name: str, rel: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        raise SkillLoadError(f"{rel}: {field_name!r} must be a list of strings")
    out: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise SkillLoadError(f"{rel}: {field_name!r} entries must be non-empty strings")
        out.append(item.strip())
    return tuple(out)


def _build_spec(data: dict, body: str, rel: str) -> SkillSpec:
    required = ("id", "title", "phase", "when_to_use", "tools_available")
    missing = [k for k in required if k not in data]
    if missing:
        raise SkillLoadError(f"{rel}: missing required field(s): {', '.join(missing)}")

    skill_id = str(data["id"]).strip()
    if not _ID_RE.fullmatch(skill_id):
        raise SkillLoadError(
            f"{rel}: id {skill_id!r} must be kebab-case ([a-z][a-z0-9-]*)"
        )

    phase = str(data["phase"]).strip()
    if phase not in _VALID_PHASES:
        raise SkillLoadError(
            f"{rel}: phase {phase!r} is not a valid AgentRole "
            f"(allowed: {sorted(_VALID_PHASES)})"
        )

    tools_available = _as_str_tuple(data["tools_available"], field_name="tools_available", rel=rel)
    if not tools_available:
        raise SkillLoadError(f"{rel}: tools_available must list at least one tool_id")
    known_ids = {s.id for s in REGISTRY.all()}
    unknown = [t for t in tools_available if t not in known_ids]
    if unknown:
        raise SkillLoadError(
            f"{rel}: tools_available references unknown tool_id(s): {unknown}. "
            f"Every skill tool must be a registered vapt_tools.REGISTRY entry."
        )

    target_kinds = _as_str_tuple(data.get("target_kinds"), field_name="target_kinds", rel=rel)
    bad_kinds = [k for k in target_kinds if k not in _VALID_TARGET_KINDS]
    if bad_kinds:
        raise SkillLoadError(
            f"{rel}: target_kinds {bad_kinds} not in {sorted(_VALID_TARGET_KINDS)}"
        )

    confidence = str(data.get("confidence", "medium")).strip().lower()
    if confidence not in _VALID_CONFIDENCE:
        raise SkillLoadError(
            f"{rel}: confidence {confidence!r} must be one of {sorted(_VALID_CONFIDENCE)}"
        )

    version_raw = data.get("version", 1)
    try:
        version = int(version_raw)
    except (TypeError, ValueError) as e:
        raise SkillLoadError(f"{rel}: version must be an integer: {version_raw!r}") from e

    return SkillSpec(
        id=skill_id,
        title=str(data["title"]).strip(),
        phase=phase,
        when_to_use=str(data["when_to_use"]).strip(),
        tools_available=tools_available,
        target_kinds=target_kinds,
        auth_sensitive=bool(data.get("auth_sensitive", False)),
        mitre_attack=_as_str_tuple(data.get("mitre_attack"), field_name="mitre_attack", rel=rel),
        cwe=_as_str_tuple(data.get("cwe"), field_name="cwe", rel=rel),
        owasp=_as_str_tuple(data.get("owasp"), field_name="owasp", rel=rel),
        confidence=confidence,
        version=version,
        body=body,
        source_path=rel,
    )


# --------------------------------------------------------------------------- #
# Retrieval
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class _Match:
    spec: SkillSpec
    score: int


def find_skills(
    *,
    phase: str,
    target_kinds: list[str] | None = None,
    auth_detected: bool | None = None,
    limit: int = 5,
    registry: SkillRegistry | None = None,
) -> list[SkillSpec]:
    """Return up to ``limit`` skills ranked by relevance.

    Ranking is deliberately simple and deterministic:
      * ``phase`` match is required (a mismatch excludes the skill).
      * +2 per overlapping ``target_kinds`` entry.
      * +1 when ``auth_detected`` is True and the skill is auth-sensitive.
      * +1 for ``confidence == "high"``, +0 medium, -1 low (so high-confidence hints
        float up when scores tie).
    """
    reg = registry or SKILL_REGISTRY
    want_kinds = set(target_kinds or ())

    matches: list[_Match] = []
    for spec in reg.all():
        if spec.phase != phase:
            continue
        score = 0
        if spec.target_kinds:
            score += 2 * len(want_kinds.intersection(spec.target_kinds))
        if auth_detected and spec.auth_sensitive:
            score += 1
        score += {"low": -1, "medium": 0, "high": 1}[spec.confidence]
        matches.append(_Match(spec, score))

    # Sort by score desc, then id asc for stability. Reverse-score makes the top skill
    # the most relevant one; equal-score ties are broken alphabetically.
    matches.sort(key=lambda m: (-m.score, m.spec.id))
    return [m.spec for m in matches[: max(0, int(limit))]]


def framework_refs_for_tools(
    tool_ids: list[str] | set[str] | tuple[str, ...],
    *,
    registry: SkillRegistry | None = None,
) -> dict[str, list[str]]:
    """Union MITRE ATT&CK / CWE / OWASP tags from every skill whose
    ``tools_available`` intersects ``tool_ids``.

    Used by the report builder (Phase B): a confirmed finding carries one or
    more observations, each with a `source_tool` id. We look up every skill
    that references that tool and collect its framework tags, giving the
    finding a MITRE/CWE/OWASP mapping without the author having to curate it
    per finding type. The mapping is deterministic and reproducible — same
    tools in, same tags out.

    Returns ``{"mitre_attack": [...], "cwe": [...], "owasp": [...]}`` with
    each list de-duplicated and sorted. Empty lists for keys with no matches
    (never missing keys — callers can render blindly)."""
    reg = registry or SKILL_REGISTRY
    want = {t for t in (tool_ids or []) if t}
    mitre: set[str] = set()
    cwe: set[str] = set()
    owasp: set[str] = set()
    if not want:
        return {"mitre_attack": [], "cwe": [], "owasp": []}
    for spec in reg.all():
        if not want.intersection(spec.tools_available):
            continue
        mitre.update(spec.mitre_attack)
        cwe.update(spec.cwe)
        owasp.update(spec.owasp)
    return {
        "mitre_attack": sorted(mitre),
        "cwe": sorted(cwe),
        "owasp": sorted(owasp),
    }


def format_skill_hints(
    *,
    phase: str,
    target_kinds: list[str] | None = None,
    auth_detected: bool | None = None,
    limit: int = 5,
    registry: SkillRegistry | None = None,
) -> str:
    """Render top-N skill hits as a compact Markdown block the planner can paste into
    its user prompt. Empty string when nothing matches, so callers can concatenate
    unconditionally. The text is STRICTLY advisory — the hint block includes a header
    reminding the model that tool_ids still come from the Available tools catalog."""
    hits = find_skills(
        phase=phase,
        target_kinds=target_kinds,
        auth_detected=auth_detected,
        limit=limit,
        registry=registry,
    )
    if not hits:
        return ""
    lines = [
        "## Reference knowledge (advisory — tool_ids must still come from Available tools):",
    ]
    for s in hits:
        tags = ""
        if s.mitre_attack:
            tags += f" MITRE:{','.join(s.mitre_attack)}"
        if s.cwe:
            tags += f" {','.join(s.cwe)}"
        lines.append(f"- [{s.id}] {s.title}{tags}")
        lines.append(f"  when: {s.when_to_use}")
        lines.append(f"  prefer tools: {', '.join(s.tools_available)}")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Module singleton: parse the shipped library once at import. A load error here
# means the planner cannot start, which is the correct behavior — we don't want a
# half-loaded skill set silently shaping LLM prompts.
# --------------------------------------------------------------------------- #
SKILL_REGISTRY: SkillRegistry = SkillRegistry.load(_LIBRARY_DIR)
