"""Explainable risk scoring engine for Terraform infrastructure changes."""

import math

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


def calculate_logarithmic_blast_radius(
    base_impact: float,
    affected_count: int = 1,
    scale: float = 1.0,
) -> float:
    if affected_count <= 1:
        return min(5.0, max(0.0, base_impact))
    return min(5.0, max(0.0, round(base_impact + scale * math.log(affected_count), 2)))


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


def compound_risk_factors_logarithmic(
    primary: RiskFactors,
    secondary_findings: list[Finding],
    env_crit: float,
    scale: float = 0.5,
) -> RiskFactors:
    """Blend secondary findings into primary risk factors using logarithmic scaling."""
    if not secondary_findings:
        return RiskFactors(
            change_impact=primary.change_impact,
            security_exposure=primary.security_exposure,
            reversibility=primary.reversibility,
            environment_criticality=env_crit,
            uncertainty=primary.uncertainty,
        )

    def _compound_dim(primary_val: float, sec_attr: str) -> float:
        sec_max = max(getattr(f.risk_factors, sec_attr) for f in secondary_findings)
        delta = max(0.0, sec_max - primary_val)
        if delta <= 0.0:
            return primary_val
        return min(5.0, round(primary_val + scale * math.log(1.0 + delta), 2))

    return RiskFactors(
        change_impact=_compound_dim(primary.change_impact, "change_impact"),
        security_exposure=_compound_dim(primary.security_exposure, "security_exposure"),
        reversibility=_compound_dim(primary.reversibility, "reversibility"),
        environment_criticality=env_crit,
        uncertainty=_compound_dim(primary.uncertainty, "uncertainty"),
    )


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
            sorted_findings = sorted(
                res_findings,
                key=lambda f: (-f.calculated_score, -f.severity.level, f.rule_id),
            )
            primary = sorted_findings[0]
            secondaries = sorted_findings[1:]

            res_factors = compound_risk_factors_logarithmic(
                primary=primary.risk_factors,
                secondary_findings=secondaries,
                env_crit=env_crit,
            )
            res_score = calculate_factor_score(
                change_impact=res_factors.change_impact,
                security_exposure=res_factors.security_exposure,
                reversibility=res_factors.reversibility,
                environment_criticality=res_factors.environment_criticality,
                uncertainty=res_factors.uncertainty,
            )
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
