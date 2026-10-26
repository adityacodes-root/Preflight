"""Unit tests for deployment policy evaluation."""

from preflight.models import (
    ActionType,
    Finding,
    RiskFactors,
    Severity,
)
from preflight.policy import PolicyEvaluator


def _create_finding(rule_id: str, severity: Severity) -> Finding:
    return Finding(
        rule_id=rule_id,
        rule_name=f"Rule {rule_id}",
        severity=severity,
        resource_address=f"res.{rule_id.lower()}",
        resource_type="aws_resource",
        action=ActionType.UPDATE,
        what_changed="Mock change",
        why_it_matters="Mock reason",
        remediation="Mock remediation",
        risk_factors=RiskFactors(),
        calculated_score=50.0,
    )


def test_policy_no_blocking_conditions() -> None:
    evaluator = PolicyEvaluator()
    findings = [_create_finding("TEST-001", Severity.CRITICAL)]
    # Even with critical finding, if no fail_on or blocked_rules is configured, policy does not block
    result = evaluator.evaluate(findings, overall_risk_score=90.0)
    assert result.blocked is False
    assert len(result.blocking_reasons) == 0


def test_policy_fail_on_severity_threshold() -> None:
    evaluator = PolicyEvaluator(fail_on_severity=Severity.HIGH)

    # Moderate finding does not block
    mod_finding = _create_finding("MOD-001", Severity.MODERATE)
    assert evaluator.evaluate([mod_finding], 30.0).blocked is False

    # High finding blocks
    high_finding = _create_finding("HIGH-001", Severity.HIGH)
    res_high = evaluator.evaluate([high_finding], 60.0)
    assert res_high.blocked is True
    assert "HIGH-001" in res_high.blocked_rule_ids

    # Critical finding blocks
    crit_finding = _create_finding("CRIT-001", Severity.CRITICAL)
    res_crit = evaluator.evaluate([crit_finding], 85.0)
    assert res_crit.blocked is True


def test_policy_blocked_rules() -> None:
    evaluator = PolicyEvaluator(blocked_rules=["AWS-DB-001"])
    f1 = _create_finding("GEN-DEL-001", Severity.LOW)
    f2 = _create_finding("AWS-DB-001", Severity.LOW)

    # Low severity, but rule ID is explicitly blocked
    result = evaluator.evaluate([f1, f2], 20.0)
    assert result.blocked is True
    assert "AWS-DB-001" in result.blocked_rule_ids


def test_policy_allowed_rules_suppression() -> None:
    evaluator = PolicyEvaluator(
        fail_on_severity=Severity.HIGH,
        allowed_rules=["AWS-NET-001"],
    )
    # Finding is CRITICAL, but suppressed in allowed_rules
    finding = _create_finding("AWS-NET-001", Severity.CRITICAL)
    result = evaluator.evaluate([finding], 80.0)
    assert result.blocked is False


def test_policy_max_allowed_score() -> None:
    evaluator = PolicyEvaluator(max_allowed_score=75.0)

    # Below threshold passes
    assert evaluator.evaluate([], 74.9).blocked is False

    # Above threshold blocks
    res = evaluator.evaluate([], 75.1)
    assert res.blocked is True
    assert "exceeds configured maximum allowed score" in res.blocking_reasons[0]
