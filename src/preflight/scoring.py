"""Explainable risk scoring engine for Terraform infrastructure changes."""

from preflight.models import (
    Environment,
    Finding,
    ResourceChange,
    ResourceRisk,
    RiskCategory,
    RiskFactors,
)

# Factor weights (sum to 100)
WEIGHT_CHANGE_IMPACT = 30.0
WEIGHT_SECURITY_EXPOSURE = 25.0
WEIGHT_REVERSIBILITY = 20.0
WEIGHT_ENVIRONMENT_CRITICALITY = 15.0
WEIGHT_UNCERTAINTY = 10.0

# Environment criticality mappings (0 to 5)
ENV_CRITICALITY_SCORES: dict[Environment, float] = {
    Environment.DEVELOPMENT: 1.0,
    Environment.STAGING: 3.0,
    Environment.PRODUCTION: 5.0,
}


def calculate_factor_score(
    change_impact: float,
    security_exposure: float,
    reversibility: float,
    environment_criticality: float,
    uncertainty: float,
) -> float:
    """Calculate normalized risk score (0 to 100) from 5 factors scored 0 to 5.

    Formula: Σ(weight * factor_score / 5.0)
    """
    ci = max(0.0, min(5.0, change_impact))
    se = max(0.0, min(5.0, security_exposure))
    rev = max(0.0, min(5.0, reversibility))
    ec = max(0.0, min(5.0, environment_criticality))
    unc = max(0.0, min(5.0, uncertainty))

    score = (
        (WEIGHT_CHANGE_IMPACT * ci / 5.0)
        + (WEIGHT_SECURITY_EXPOSURE * se / 5.0)
        + (WEIGHT_REVERSIBILITY * rev / 5.0)
        + (WEIGHT_ENVIRONMENT_CRITICALITY * ec / 5.0)
        + (WEIGHT_UNCERTAINTY * unc / 5.0)
    )
    return round(score, 1)


def score_finding(
    factors: RiskFactors,
    environment: Environment,
) -> tuple[RiskFactors, float]:
    """Calculate the score for a single finding with environment context."""
    env_crit = ENV_CRITICALITY_SCORES.get(environment, 5.0)
    resolved_factors = RiskFactors(
        change_impact=factors.change_impact,
        security_exposure=factors.security_exposure,
        reversibility=factors.reversibility,
        environment_criticality=env_crit,
        uncertainty=factors.uncertainty,
    )
    score = calculate_factor_score(
        change_impact=resolved_factors.change_impact,
        security_exposure=resolved_factors.security_exposure,
        reversibility=resolved_factors.reversibility,
        environment_criticality=resolved_factors.environment_criticality,
        uncertainty=resolved_factors.uncertainty,
    )
    return resolved_factors, score


def aggregate_resource_risks(
    resources: list[ResourceChange],
    findings: list[Finding],
    environment: Environment,
) -> tuple[list[ResourceRisk], float, RiskCategory, str | None]:
    """Aggregate findings per resource and compute resource and plan-level risk.

    The initial release assigns the maximum resource-level risk score as the
    overall plan risk score.
    """
    findings_by_resource: dict[str, list[Finding]] = {}
    for finding in findings:
        findings_by_resource.setdefault(finding.resource_address, []).append(finding)

    env_crit = ENV_CRITICALITY_SCORES.get(environment, 5.0)
    resource_risks: list[ResourceRisk] = []
    max_score = 0.0
    highest_contributing_resource: str | None = None

    for res in resources:
        res_findings = findings_by_resource.get(res.address, [])
        if res_findings:
            # Resource risk factors take the maximum component across its findings
            max_ci = max(f.risk_factors.change_impact for f in res_findings)
            max_se = max(f.risk_factors.security_exposure for f in res_findings)
            max_rev = max(f.risk_factors.reversibility for f in res_findings)
            max_unc = max(f.risk_factors.uncertainty for f in res_findings)

            res_factors = RiskFactors(
                change_impact=max_ci,
                security_exposure=max_se,
                reversibility=max_rev,
                environment_criticality=env_crit,
                uncertainty=max_unc,
            )
            res_score = calculate_factor_score(max_ci, max_se, max_rev, env_crit, max_unc)
        else:
            res_factors = RiskFactors(
                change_impact=0.0,
                security_exposure=0.0,
                reversibility=0.0,
                environment_criticality=env_crit,
                uncertainty=0.0,
            )
            res_score = 0.0

        res_category = RiskCategory.from_score(res_score)
        resource_risk = ResourceRisk(
            resource_address=res.address,
            resource_type=res.type,
            action=res.action,
            risk_score=res_score,
            risk_category=res_category,
            risk_factors=res_factors,
            findings=res_findings,
        )
        resource_risks.append(resource_risk)

        if res_score > max_score:
            max_score = res_score
            highest_contributing_resource = res.address

    overall_category = RiskCategory.from_score(max_score)
    return resource_risks, max_score, overall_category, highest_contributing_resource
