"""Unit tests for the risk scoring algorithm and risk bands."""

from preflight.models import (
    ActionType,
    Environment,
    Finding,
    ResourceChange,
    RiskCategory,
    RiskFactors,
    Severity,
)
from preflight.scoring import (
    aggregate_resource_risks,
    calculate_factor_score,
    score_finding,
)


def test_calculate_factor_score_all_zeros() -> None:
    score = calculate_factor_score(
        change_impact=0.0,
        security_exposure=0.0,
        reversibility=0.0,
        environment_criticality=0.0,
        uncertainty=0.0,
    )
    assert score == 0.0
    assert RiskCategory.from_score(score) == RiskCategory.LOW


def test_calculate_factor_score_all_maximums() -> None:
    score = calculate_factor_score(
        change_impact=5.0,
        security_exposure=5.0,
        reversibility=5.0,
        environment_criticality=5.0,
        uncertainty=5.0,
    )
    assert score == 100.0
    assert RiskCategory.from_score(score) == RiskCategory.CRITICAL


def test_calculate_factor_score_weighted_components() -> None:
    # 30% on change_impact (5.0/5 = 1.0 -> 30.0)
    score_ci = calculate_factor_score(5.0, 0.0, 0.0, 0.0, 0.0)
    assert score_ci == 30.0

    # 25% on security_exposure (5.0/5 = 1.0 -> 25.0)
    score_se = calculate_factor_score(0.0, 5.0, 0.0, 0.0, 0.0)
    assert score_se == 25.0

    # 20% on reversibility (5.0/5 = 1.0 -> 20.0)
    score_rev = calculate_factor_score(0.0, 0.0, 5.0, 0.0, 0.0)
    assert score_rev == 20.0

    # 15% on environment_criticality (5.0/5 = 1.0 -> 15.0)
    score_ec = calculate_factor_score(0.0, 0.0, 0.0, 5.0, 0.0)
    assert score_ec == 15.0

    # 10% on uncertainty (5.0/5 = 1.0 -> 10.0)
    score_unc = calculate_factor_score(0.0, 0.0, 0.0, 0.0, 5.0)
    assert score_unc == 10.0


def test_calculate_factor_score_clamping() -> None:
    # Values above 5.0 clamped to 5.0, negative clamped to 0.0
    clamped_high = calculate_factor_score(10.0, 10.0, 10.0, 10.0, 10.0)
    assert clamped_high == 100.0

    clamped_low = calculate_factor_score(-5.0, -1.0, 0.0, 0.0, 0.0)
    assert clamped_low == 0.0


def test_risk_category_bands() -> None:
    assert RiskCategory.from_score(0.0) == RiskCategory.LOW
    assert RiskCategory.from_score(24.9) == RiskCategory.LOW
    assert RiskCategory.from_score(25.0) == RiskCategory.MODERATE
    assert RiskCategory.from_score(49.9) == RiskCategory.MODERATE
    assert RiskCategory.from_score(50.0) == RiskCategory.HIGH
    assert RiskCategory.from_score(74.9) == RiskCategory.HIGH
    assert RiskCategory.from_score(75.0) == RiskCategory.CRITICAL
    assert RiskCategory.from_score(100.0) == RiskCategory.CRITICAL


def test_environment_criticality_effect() -> None:
    raw_factors = RiskFactors(
        change_impact=4.0,
        security_exposure=4.0,
        reversibility=3.0,
        uncertainty=1.0,
    )
    # Dev: env_criticality = 1.0/5 -> 15 * 0.2 = 3.0
    _, dev_score = score_finding(raw_factors, Environment.DEVELOPMENT)
    # Staging: env_criticality = 3.0/5 -> 15 * 0.6 = 9.0
    _, stage_score = score_finding(raw_factors, Environment.STAGING)
    # Prod: env_criticality = 5.0/5 -> 15 * 1.0 = 15.0
    _, prod_score = score_finding(raw_factors, Environment.PRODUCTION)

    assert dev_score < stage_score < prod_score
    # Exactly 6.0 point delta between dev and staging (9 - 3), and between staging and prod (15 - 9)
    assert round(stage_score - dev_score, 1) == 6.0
    assert round(prod_score - stage_score, 1) == 6.0


def test_aggregate_resource_risks_maximum_score() -> None:
    res1 = ResourceChange(
        address="aws_security_group.low_risk",
        mode="managed",
        type="aws_security_group",
        name="low_risk",
        provider_name="aws",
        raw_actions=["create"],
        action=ActionType.CREATE,
    )
    res2 = ResourceChange(
        address="aws_db_instance.critical_db",
        mode="managed",
        type="aws_db_instance",
        name="critical_db",
        provider_name="aws",
        raw_actions=["delete"],
        action=ActionType.DELETE,
    )

    finding_low = Finding(
        rule_id="TEST-001",
        rule_name="Test Low",
        severity=Severity.LOW,
        resource_address="aws_security_group.low_risk",
        resource_type="aws_security_group",
        action=ActionType.CREATE,
        what_changed="Created internal SG",
        why_it_matters="Low impact",
        remediation="None",
        risk_factors=RiskFactors(change_impact=1.0, environment_criticality=5.0),
        calculated_score=21.0,
    )

    finding_crit = Finding(
        rule_id="AWS-DB-001",
        rule_name="Database Deletion",
        severity=Severity.CRITICAL,
        resource_address="aws_db_instance.critical_db",
        resource_type="aws_db_instance",
        action=ActionType.DELETE,
        what_changed="Deleted DB",
        why_it_matters="Data loss",
        remediation="Check snapshots",
        risk_factors=RiskFactors(
            change_impact=5.0,
            security_exposure=1.0,
            reversibility=5.0,
            environment_criticality=5.0,
            uncertainty=1.0,
        ),
        calculated_score=72.0,
    )

    resources, overall_score, category, highest_res = aggregate_resource_risks(
        resources=[res1, res2],
        findings=[finding_low, finding_crit],
        environment=Environment.PRODUCTION,
    )

    assert len(resources) == 2
    assert overall_score == 72.0
    assert category == RiskCategory.HIGH
    assert highest_res == "aws_db_instance.critical_db"
