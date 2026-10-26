"""Policy evaluation engine: Enforces configurable deployment gates."""

from preflight.models import Finding, PolicyEvaluation, Severity


class PolicyEvaluator:
    """Evaluates findings and risk scores against configured policy rules."""

    def __init__(
        self,
        fail_on_severity: Severity | None = None,
        blocked_rules: list[str] | None = None,
        allowed_rules: list[str] | None = None,
        max_allowed_score: float | None = None,
    ) -> None:
        self.fail_on_severity = fail_on_severity
        self.blocked_rules = set(blocked_rules or [])
        self.allowed_rules = set(allowed_rules or [])
        self.max_allowed_score = max_allowed_score

    def evaluate(
        self,
        findings: list[Finding],
        overall_risk_score: float,
    ) -> PolicyEvaluation:
        """Evaluate policy gates against discovered findings and overall score."""
        blocking_reasons: list[str] = []
        triggered_rule_ids: set[str] = set()

        # Filter out findings explicitly suppressed by allowed_rules
        active_findings = [f for f in findings if f.rule_id not in self.allowed_rules]

        # 1. Check severity threshold
        if self.fail_on_severity is not None:
            violating_findings = [f for f in active_findings if f.severity >= self.fail_on_severity]
            for f in violating_findings:
                triggered_rule_ids.add(f.rule_id)
                blocking_reasons.append(
                    f"Finding '{f.rule_id}' on '{f.resource_address}' has severity '{f.severity.value}' "
                    f"which meets or exceeds policy threshold '{self.fail_on_severity.value}'."
                )

        # 2. Check explicitly blocked rule IDs
        if self.blocked_rules:
            for f in active_findings:
                if f.rule_id in self.blocked_rules:
                    triggered_rule_ids.add(f.rule_id)
                    reason = f"Rule '{f.rule_id}' on '{f.resource_address}' is explicitly blocked by policy."
                    if reason not in blocking_reasons:
                        blocking_reasons.append(reason)

        # 3. Check maximum allowed score threshold
        if self.max_allowed_score is not None:
            if overall_risk_score > self.max_allowed_score:
                blocking_reasons.append(
                    f"Overall plan risk score ({overall_risk_score:.1f}) exceeds configured "
                    f"maximum allowed score ({self.max_allowed_score:.1f})."
                )

        blocked = len(blocking_reasons) > 0

        return PolicyEvaluation(
            blocked=blocked,
            blocking_reasons=blocking_reasons,
            fail_on_severity=self.fail_on_severity,
            blocked_rule_ids=sorted(triggered_rule_ids),
        )
