"""Analysis engine: Coordinates parsing, rule evaluation, scoring, and policy enforcement."""

from datetime import UTC, datetime
from pathlib import Path

from preflight.models import (
    AnalysisResult,
    Environment,
    Finding,
    PlanSummary,
    PolicyEvaluation,
    ResourceChange,
)
from preflight.plan import parse_plan_file, parse_plan_json
from preflight.policy import PolicyEvaluator
from preflight.redaction import redact_sensitive_data
from preflight.rules import Rule, get_default_rules
from preflight.rules.base import RuleContext
from preflight.scoring import aggregate_resource_risks


class PreflightEngine:
    """Core analysis engine orchestrating infrastructure change evaluation."""

    def __init__(self, rules: list[Rule] | None = None) -> None:
        self.rules = rules if rules is not None else get_default_rules()

    def analyze_file(
        self,
        plan_path: str | Path,
        environment: Environment = Environment.PRODUCTION,
        policy_evaluator: PolicyEvaluator | None = None,
    ) -> AnalysisResult:
        """Run analysis directly on a plan file."""
        resource_changes, summary = parse_plan_file(plan_path)
        identifier = "<stdin>" if str(plan_path) == "-" else str(plan_path)
        return self._run_analysis(
            plan_path=identifier,
            resource_changes=resource_changes,
            summary=summary,
            environment=environment,
            policy_evaluator=policy_evaluator,
        )

    def analyze_json(
        self,
        json_content: str,
        plan_identifier: str = "<stdin>",
        environment: Environment = Environment.PRODUCTION,
        policy_evaluator: PolicyEvaluator | None = None,
    ) -> AnalysisResult:
        """Run analysis on an in-memory JSON string."""
        resource_changes, summary = parse_plan_json(json_content)
        return self._run_analysis(
            plan_path=plan_identifier,
            resource_changes=resource_changes,
            summary=summary,
            environment=environment,
            policy_evaluator=policy_evaluator,
        )

    def _run_analysis(
        self,
        plan_path: str,
        resource_changes: list[ResourceChange],
        summary: PlanSummary,
        environment: Environment,
        policy_evaluator: PolicyEvaluator | None,
    ) -> AnalysisResult:
        context = RuleContext(environment=environment)
        all_findings: list[Finding] = []

        # Evaluate rules against each resource change
        for resource in resource_changes:
            for rule in self.rules:
                findings = rule.evaluate(resource, context)
                for f in findings:
                    # Sanitize details using defensive redaction
                    f.details = redact_sensitive_data(f.details)
                    all_findings.append(f)

        # Sort findings deterministically (by severity descending, score descending, address ascending, rule ID ascending)
        all_findings.sort(
            key=lambda x: (-x.severity.level, -x.calculated_score, x.resource_address, x.rule_id)
        )

        # Score and aggregate risks
        resources, overall_score, overall_category, highest_res = aggregate_resource_risks(
            resources=resource_changes,
            findings=all_findings,
            environment=environment,
        )

        # Evaluate deployment policy
        if policy_evaluator is None:
            policy_evaluator = PolicyEvaluator()
        policy_result: PolicyEvaluation = policy_evaluator.evaluate(
            findings=all_findings,
            overall_risk_score=overall_score,
        )

        timestamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

        return AnalysisResult(
            plan_path=plan_path,
            environment=environment,
            summary=summary,
            resources=resources,
            findings=all_findings,
            overall_risk_score=overall_score,
            overall_risk_category=overall_category,
            highest_contributing_resource=highest_res,
            policy_evaluation=policy_result,
            timestamp=timestamp,
        )
