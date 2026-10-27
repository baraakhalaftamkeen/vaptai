from vapt_domain.enums import PolicyClass, PolicyDecision, TestingMode
from vapt_policy import PolicyEngine, PolicyInput


def _mk(**kw):
    base = dict(
        policy_class=PolicyClass.P0_PASSIVE,
        tool_id="dns_resolve",
        profile_id="default",
        target_ref="example.com",
        testing_mode=TestingMode.BLACK_BOX,
        allowed_action_classes=[PolicyClass.P0_PASSIVE, PolicyClass.P1_LOW_IMPACT],
        in_scope=True,
    )
    base.update(kw)
    return PolicyInput(**base)


def test_out_of_scope_is_denied():
    r = PolicyEngine().evaluate(_mk(in_scope=False))
    assert r.decision == PolicyDecision.DENY


def test_p0_passive_allowed():
    assert PolicyEngine().evaluate(_mk()).decision == PolicyDecision.ALLOW


def test_p1_requires_approval_without_signed_profile():
    r = PolicyEngine().evaluate(_mk(policy_class=PolicyClass.P1_LOW_IMPACT))
    assert r.decision == PolicyDecision.REQUIRE_APPROVAL


def test_p1_allowed_with_signed_profile():
    r = PolicyEngine().evaluate(_mk(policy_class=PolicyClass.P1_LOW_IMPACT, signed_profile=True))
    assert r.decision == PolicyDecision.ALLOW


def test_p2_requires_approval_even_in_white_box():
    r = PolicyEngine().evaluate(
        _mk(
            policy_class=PolicyClass.P2_INTRUSIVE,
            testing_mode=TestingMode.WHITE_BOX,
            allowed_action_classes=[PolicyClass.P2_INTRUSIVE],
        )
    )
    assert r.decision == PolicyDecision.REQUIRE_APPROVAL


def test_p3_always_denied():
    r = PolicyEngine().evaluate(
        _mk(policy_class=PolicyClass.P3_EXCLUDED, allowed_action_classes=[PolicyClass.P3_EXCLUDED])
    )
    assert r.decision == PolicyDecision.DENY


def test_metadata_address_denied():
    r = PolicyEngine().evaluate(_mk(resolved_addresses=["169.254.169.254"]))
    assert r.decision == PolicyDecision.DENY
