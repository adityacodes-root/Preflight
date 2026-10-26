"""Domain models for Preflight infrastructure change risk analysis."""

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Environment(StrEnum):
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"

    @classmethod
    def from_str(cls, value: str) -> "Environment":
        normalized = value.strip().lower()
        if normalized in ("dev", "development"):
            return cls.DEVELOPMENT
        if normalized in ("stage", "staging"):
            return cls.STAGING
        if normalized in ("prod", "production"):
            return cls.PRODUCTION
        raise ValueError(f"Unknown environment '{value}'. Valid: development, staging, production.")


class ActionType(StrEnum):
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    REPLACE = "replace"
    READ = "read"
    NOOP = "no-op"
    UNKNOWN = "unknown"

    @classmethod
    def from_terraform_actions(cls, actions: list[str]) -> "ActionType":
        if not actions:
            return cls.NOOP
        if actions == ["create"]:
            return cls.CREATE
        if actions == ["update"]:
            return cls.UPDATE
        if actions == ["delete"]:
            return cls.DELETE
        if actions == ["read"]:
            return cls.READ
        if actions == ["no-op"]:
            return cls.NOOP
        if sorted(actions) == ["create", "delete"]:
            return cls.REPLACE
        return cls.UNKNOWN


class Severity(StrEnum):
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def level(self) -> int:
        levels = {
            Severity.LOW: 1,
            Severity.MODERATE: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }
        return levels[self]

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.level >= other.level

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.level > other.level

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.level <= other.level

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.level < other.level

    @classmethod
    def from_str(cls, value: str) -> "Severity":
        normalized = value.strip().lower()
        for member in cls:
            if member.value == normalized:
                return member
        raise ValueError(f"Unknown severity '{value}'. Valid: low, moderate, high, critical.")


class RiskCategory(StrEnum):
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_score(cls, score: float) -> "RiskCategory":
        if score < 25.0:
            return cls.LOW
        if score < 50.0:
            return cls.MODERATE
        if score < 75.0:
            return cls.HIGH
        return cls.CRITICAL


@dataclass(frozen=True)
class RiskFactors:
    change_impact: float = 0.0
    security_exposure: float = 0.0
    reversibility: float = 0.0
    environment_criticality: float = 0.0
    uncertainty: float = 0.0

    def to_dict(self) -> dict[str, float]:
        return {
            "change_impact": round(self.change_impact, 2),
            "security_exposure": round(self.security_exposure, 2),
            "reversibility": round(self.reversibility, 2),
            "environment_criticality": round(self.environment_criticality, 2),
            "uncertainty": round(self.uncertainty, 2),
        }


@dataclass
class Finding:
    rule_id: str
    rule_name: str
    severity: Severity
    resource_address: str
    resource_type: str
    action: ActionType
    what_changed: str
    why_it_matters: str
    remediation: str
    risk_factors: RiskFactors
    calculated_score: float
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity.value,
            "resource_address": self.resource_address,
            "resource_type": self.resource_type,
            "action": self.action.value,
            "what_changed": self.what_changed,
            "why_it_matters": self.why_it_matters,
            "remediation": self.remediation,
            "risk_factors": self.risk_factors.to_dict(),
            "calculated_score": round(self.calculated_score, 1),
            "details": self.details,
        }


@dataclass
class ResourceChange:
    address: str
    mode: str
    type: str
    name: str
    provider_name: str
    raw_actions: list[str]
    action: ActionType
    module_address: str | None = None
    before: dict[str, Any] | None = None
    after: dict[str, Any] | None = None
    after_unknown: dict[str, Any] | None = None
    replace_paths: list[Any] | None = None
    before_sensitive: Any = None
    after_sensitive: Any = None


@dataclass
class ResourceRisk:
    resource_address: str
    resource_type: str
    action: ActionType
    risk_score: float
    risk_category: RiskCategory
    risk_factors: RiskFactors
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "resource_address": self.resource_address,
            "resource_type": self.resource_type,
            "action": self.action.value,
            "risk_score": round(self.risk_score, 1),
            "risk_category": self.risk_category.value,
            "risk_factors": self.risk_factors.to_dict(),
            "findings_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class PlanSummary:
    total_resources: int = 0
    to_create: int = 0
    to_update: int = 0
    to_delete: int = 0
    to_replace: int = 0
    to_read: int = 0
    to_noop: int = 0
    unknown_actions: int = 0
    has_unknown_values: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_resources": self.total_resources,
            "to_create": self.to_create,
            "to_update": self.to_update,
            "to_delete": self.to_delete,
            "to_replace": self.to_replace,
            "to_read": self.to_read,
            "to_noop": self.to_noop,
            "unknown_actions": self.unknown_actions,
            "has_unknown_values": self.has_unknown_values,
        }


@dataclass
class PolicyEvaluation:
    blocked: bool
    blocking_reasons: list[str] = field(default_factory=list)
    fail_on_severity: Severity | None = None
    blocked_rule_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "blocked": self.blocked,
            "blocking_reasons": self.blocking_reasons,
            "fail_on_severity": self.fail_on_severity.value if self.fail_on_severity else None,
            "blocked_rule_ids": self.blocked_rule_ids,
        }


@dataclass
class AnalysisResult:
    plan_path: str
    environment: Environment
    summary: PlanSummary
    resources: list[ResourceRisk]
    findings: list[Finding]
    overall_risk_score: float
    overall_risk_category: RiskCategory
    highest_contributing_resource: str | None
    policy_evaluation: PolicyEvaluation
    timestamp: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan_path": self.plan_path,
            "timestamp": self.timestamp,
            "environment": self.environment.value,
            "overall_risk_score": round(self.overall_risk_score, 1),
            "overall_risk_category": self.overall_risk_category.value,
            "highest_contributing_resource": self.highest_contributing_resource,
            "summary": self.summary.to_dict(),
            "policy_evaluation": self.policy_evaluation.to_dict(),
            "findings_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "resources": [r.to_dict() for r in self.resources],
        }
