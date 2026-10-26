"""Provider-neutral detection rules for Terraform plans."""

from preflight.models import (
    ActionType,
    Finding,
    ResourceChange,
    RiskFactors,
    Severity,
)
from preflight.rules.base import Rule, RuleContext
from preflight.scoring import score_finding

# Types typically representing stateful or persistent resources where forced recreation is high-risk
STATEFUL_PATTERNS = (
    "db",
    "database",
    "cluster",
    "instance",
    "volume",
    "disk",
    "bucket",
    "table",
    "storage",
    "queue",
    "topic",
)


class GenericResourceDeletionRule(Rule):
    rule_id = "GEN-DEL-001"
    name = "Resource Deletion"
    description = "Detects resource deletion in the Terraform plan."
    default_severity = Severity.HIGH

    def evaluate(self, resource: ResourceChange, context: RuleContext) -> list[Finding]:
        if resource.action != ActionType.DELETE:
            return []

        base_factors = RiskFactors(
            change_impact=4.0,
            security_exposure=1.0,
            reversibility=4.5,
            uncertainty=0.0,
        )
        resolved_factors, score = score_finding(base_factors, context.environment)

        return [
            Finding(
                rule_id=self.rule_id,
                rule_name=self.name,
                severity=self.default_severity,
                resource_address=resource.address,
                resource_type=resource.type,
                action=resource.action,
                what_changed=f"Resource '{resource.address}' ({resource.type}) is scheduled for permanent deletion.",
                why_it_matters=(
                    "Deleting infrastructure resources destroys active configuration, "
                    "removes state, and can sever dependencies for other services."
                ),
                remediation=(
                    "Verify this deletion is intended. Ensure dependent workloads have been migrated "
                    "or decommissioned before applying the change."
                ),
                risk_factors=resolved_factors,
                calculated_score=score,
                details={"raw_actions": resource.raw_actions},
            )
        ]


class GenericResourceReplacementRule(Rule):
    rule_id = "GEN-REP-001"
    name = "Resource Replacement"
    description = "Detects resource recreation caused by immutable attribute modifications."
    default_severity = Severity.HIGH

    def evaluate(self, resource: ResourceChange, context: RuleContext) -> list[Finding]:
        if resource.action != ActionType.REPLACE:
            return []

        replace_paths = [str(p) for p in (resource.replace_paths or [])]
        paths_desc = f" due to changes in: {', '.join(replace_paths)}" if replace_paths else ""

        base_factors = RiskFactors(
            change_impact=4.0,
            security_exposure=2.0,
            reversibility=4.0,
            uncertainty=1.0,
        )
        resolved_factors, score = score_finding(base_factors, context.environment)

        return [
            Finding(
                rule_id=self.rule_id,
                rule_name=self.name,
                severity=self.default_severity,
                resource_address=resource.address,
                resource_type=resource.type,
                action=resource.action,
                what_changed=(
                    f"Resource '{resource.address}' ({resource.type}) will be destroyed and recreated{paths_desc}."
                ),
                why_it_matters=(
                    "Resource replacement involves destroying the existing instance before or after creating a new one. "
                    "This causes IP/endpoint changes, state resets, and temporary downtime."
                ),
                remediation=(
                    "Review the attributes triggering replacement in 'replace_paths'. Consider if changes can be performed "
                    "with zero-downtime blue/green patterns or by updating mutable fields in-place."
                ),
                risk_factors=resolved_factors,
                calculated_score=score,
                details={"replace_paths": replace_paths, "raw_actions": resource.raw_actions},
            )
        ]


class GenericUnknownActionRule(Rule):
    rule_id = "GEN-ACT-001"
    name = "Unknown Change Action"
    description = "Detects unsupported or unrecognized action sequences in plan."
    default_severity = Severity.HIGH

    def evaluate(self, resource: ResourceChange, context: RuleContext) -> list[Finding]:
        if resource.action != ActionType.UNKNOWN:
            return []

        base_factors = RiskFactors(
            change_impact=3.0,
            security_exposure=2.0,
            reversibility=3.0,
            uncertainty=5.0,
        )
        resolved_factors, score = score_finding(base_factors, context.environment)

        return [
            Finding(
                rule_id=self.rule_id,
                rule_name=self.name,
                severity=self.default_severity,
                resource_address=resource.address,
                resource_type=resource.type,
                action=resource.action,
                what_changed=(
                    f"Resource '{resource.address}' contains unrecognized action sequence: {resource.raw_actions}."
                ),
                why_it_matters=(
                    "Preflight cannot deterministically predict the lifecycle behavior of unrecognized Terraform actions."
                ),
                remediation=(
                    "Inspect the plan manually using 'terraform show' to confirm the exact operation being performed."
                ),
                risk_factors=resolved_factors,
                calculated_score=score,
                details={"raw_actions": resource.raw_actions},
            )
        ]


class GenericUnknownValuesRule(Rule):
    rule_id = "GEN-UNK-001"
    name = "Unknown Computed Values"
    description = "Detects unknown values that hinder reliable pre-deployment risk assessment."
    default_severity = Severity.MODERATE

    def evaluate(self, resource: ResourceChange, context: RuleContext) -> list[Finding]:
        # Only evaluate on resources being created or updated
        if resource.action not in (ActionType.CREATE, ActionType.UPDATE, ActionType.REPLACE):
            return []

        if not resource.after_unknown:
            return []

        # Filter out standard read-only computed attributes generated by Terraform
        BENIGN_COMPUTED = {
            "id",
            "arn",
            "created_at",
            "updated_at",
            "version_id",
            "tags_all",
            "owner_id",
        }
        unknown_keys = [
            k
            for k, v in resource.after_unknown.items()
            if (
                v is True
                or (isinstance(v, dict) and any(v.values()))
                or (isinstance(v, list) and len(v) > 0)
            )
            and k not in BENIGN_COMPUTED
        ]

        if not unknown_keys:
            return []

        # If after is extensively unknown
        is_extensively_unknown = len(unknown_keys) > 5

        base_factors = RiskFactors(
            change_impact=2.0 if is_extensively_unknown else 1.0,
            security_exposure=2.0 if is_extensively_unknown else 1.0,
            reversibility=1.0,
            uncertainty=4.5 if is_extensively_unknown else 3.0,
        )
        resolved_factors, score = score_finding(base_factors, context.environment)

        return [
            Finding(
                rule_id=self.rule_id,
                rule_name=self.name,
                severity=self.default_severity,
                resource_address=resource.address,
                resource_type=resource.type,
                action=resource.action,
                what_changed=(
                    f"Resource '{resource.address}' has {len(unknown_keys)} attribute(s) computed at apply time: "
                    f"{', '.join(unknown_keys[:5])}{'...' if len(unknown_keys) > 5 else ''}."
                ),
                why_it_matters=(
                    "Unknown computed values cannot be statically verified prior to deployment. "
                    "Rules inspecting these fields may not identify exposure until after application."
                ),
                remediation=(
                    "Where possible, provide explicit values rather than depending on dynamic interpolation "
                    "for sensitive security or routing parameters."
                ),
                risk_factors=resolved_factors,
                calculated_score=score,
                details={"unknown_attributes": unknown_keys[:10]},
            )
        ]


class GenericDestructiveChangeRule(Rule):
    rule_id = "GEN-DST-001"
    name = "Destructive Stateful Resource Change"
    description = "Detects destructive changes to stateful storage, compute, or database resources."
    default_severity = Severity.HIGH

    def evaluate(self, resource: ResourceChange, context: RuleContext) -> list[Finding]:
        if resource.action not in (ActionType.DELETE, ActionType.REPLACE):
            return []

        type_lower = resource.type.lower()
        NON_STATEFUL_SUFFIXES = (
            "_policy",
            "_rule",
            "_attachment",
            "_association",
            "_public_access_block",
            "_metric",
            "_alarm",
        )
        if any(type_lower.endswith(suffix) for suffix in NON_STATEFUL_SUFFIXES):
            return []

        is_stateful = any(pattern in type_lower for pattern in STATEFUL_PATTERNS)
        if not is_stateful:
            return []

        base_factors = RiskFactors(
            change_impact=4.5,
            security_exposure=1.5,
            reversibility=4.5,
            uncertainty=1.0,
        )
        resolved_factors, score = score_finding(base_factors, context.environment)

        action_desc = (
            "replacement (recreation)" if resource.action == ActionType.REPLACE else "deletion"
        )

        return [
            Finding(
                rule_id=self.rule_id,
                rule_name=self.name,
                severity=self.default_severity,
                resource_address=resource.address,
                resource_type=resource.type,
                action=resource.action,
                what_changed=(
                    f"Stateful resource '{resource.address}' ({resource.type}) is scheduled for {action_desc}."
                ),
                why_it_matters=(
                    "Stateful resources store persistent data or maintain state. Destroying or recreating them "
                    "risks unrecoverable data loss and prolonged downtime."
                ),
                remediation=(
                    "Verify that data snapshots exist, ensure deletion protection settings are reviewed, "
                    "and double-check whether replacement can be avoided."
                ),
                risk_factors=resolved_factors,
                calculated_score=score,
                details={"stateful_type": resource.type, "action": resource.action.value},
            )
        ]
