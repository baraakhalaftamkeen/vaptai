"""The declarative pentest-tool catalog: it registers governed tools across all five phases,
with the right policy tiers (passive→P0, active→P1, exploitation→P2 ATTACK-only, MITM/C2→P3),
safe argv building (host-injection rejected), and manifest wiring per agent."""
from __future__ import annotations

import pytest
import vapt_persistence.db as dbmod
from vapt_agents import manifests
from vapt_domain.enums import AgentRole, PolicyClass, PolicyDecision, TestingMode
from vapt_harness import ActionContext, GovernedHarness
from vapt_persistence import Base, init_engine
from vapt_persistence.models import Engagement, Project, Run
from vapt_tools import REGISTRY
from vapt_tools.catalog import CATALOG, tool_ids_for


# -- registration & tiers ----------------------------------------------------
def test_catalog_registers_all_phases():
    ids = {s.id for s in REGISTRY.all()}
    for tid in ("subfinder", "naabu", "nikto", "sqlmap", "netexec_smb"):   # one per phase
        assert tid in ids
    assert len(CATALOG) >= 60


def test_policy_tiers():
    g = REGISTRY.get
    assert g("subfinder").policy_class == PolicyClass.P0_PASSIVE          # passive OSINT
    assert g("naabu").policy_class == PolicyClass.P1_LOW_IMPACT           # active scan
    assert g("masscan").policy_class == PolicyClass.P2_INTRUSIVE          # high-rate → gated
    assert g("sqlmap").policy_class == PolicyClass.P2_INTRUSIVE           # exploitation
    assert g("responder").policy_class == PolicyClass.P3_EXCLUDED         # MITM → never auto-runs


def test_exploitation_is_attack_agent_only():
    # Every P2/P3 exploitation & post-ex tool is ATTACK-agent only, so the scan/validate
    # planner can never schedule it as an auto-allowed step.
    for tid in ("sqlmap", "ghauri", "commix", "netexec_smb", "impacket_secretsdump",
                "responder", "mitm6", "sliver", "certipy_find"):
        assert REGISTRY.get(tid).allowed_agents == [AgentRole.ATTACK], tid


def test_argv_tokens_and_injection():
    assert REGISTRY.get("nikto").build_argv({"target": "10.0.0.47", "port": "8080"})[-1] == "http://10.0.0.47:8080"
    assert REGISTRY.get("subfinder").build_argv({"target": "example.com"})[-1] == "example.com"
    with pytest.raises(ValueError):            # option-like target is rejected
        REGISTRY.get("sqlmap").build_argv({"target": "-oG; rm -rf /"})


def test_binary_env_override(monkeypatch):
    monkeypatch.setenv("VAPT_SQLMAP_BIN", "/opt/sqlmap/sqlmap.py")
    assert REGISTRY.get("sqlmap").build_argv({"target": "h"})[0] == "/opt/sqlmap/sqlmap.py"


# -- manifest wiring ---------------------------------------------------------
def test_manifests_offer_catalog_by_phase():
    assert "nikto" in manifests.SCAN.allowed_tool_ids          # vuln scanner → scan agent
    assert "sslyze" in manifests.VALIDATE.allowed_tool_ids     # config check → validate
    assert "sqlmap" in manifests.ATTACK.allowed_tool_ids       # exploitation → attack
    assert "sqlmap" not in manifests.SCAN.allowed_tool_ids     # NOT available to the scan planner
    assert "whatweb" in manifests.RECON.allowed_tool_ids       # recon fingerprinting


# -- governance through the harness ------------------------------------------
@pytest.fixture()
def db(tmp_path):
    init_engine(f"sqlite:///{tmp_path}/cat.db")
    Base.metadata.create_all(dbmod.get_engine())
    s = dbmod.SessionLocal()
    p = Project(name="P"); s.add(p); s.flush()
    e = Engagement(project_id=p.id, name="L", testing_mode="black_box", target_type="network")
    s.add(e); s.flush()
    r = Run(engagement_id=e.id, thread_id="t", status="running"); s.add(r); s.flush()
    s.commit()
    yield s, r.id
    s.close()


def _ctx(run_id, tool_id, agent):
    return ActionContext(
        run_id=run_id, task_id="t1", agent_role=agent, testing_mode=TestingMode.BLACK_BOX,
        tool_id=tool_id, profile_id="default", target_ref="h", args={"target": "h"},
        allowed_action_classes=[PolicyClass.P0_PASSIVE, PolicyClass.P1_LOW_IMPACT,
                                PolicyClass.P2_INTRUSIVE],
        scope_domains=["h"], scope_ip_cidrs=[], signed_profile=True)


def test_passive_runs_intrusive_gates_excluded_denies(db):
    s, run_id = db
    h = GovernedHarness(REGISTRY)
    # P0 passive OSINT executes with no approval.
    assert h.run_action(s, _ctx(run_id, "subfinder", AgentRole.SCAN)).decision == PolicyDecision.ALLOW
    # P2 exploitation is forced to a human approval even under a signed profile.
    assert h.run_action(s, _ctx(run_id, "sqlmap", AgentRole.ATTACK)).decision == PolicyDecision.REQUIRE_APPROVAL
    # P3 MITM is denied outright — catalogued but never runs.
    assert h.run_action(s, _ctx(run_id, "responder", AgentRole.ATTACK)).decision == PolicyDecision.DENY
    s.commit()
