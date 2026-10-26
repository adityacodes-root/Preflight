"""Base rule interface and evaluation context."""

from abc import ABC, abstractmethod
from dataclasses import dataclass

from preflight.models import Environment, Finding, ResourceChange, Severity


@dataclass(frozen=True)
class RuleContext:
    environment: Environment


class Rule(ABC):
    """Abstract base class for all Preflight detection rules."""

    rule_id: str
    name: str
    description: str
    default_severity: Severity

    @abstractmethod
    def evaluate(self, resource: ResourceChange, context: RuleContext) -> list[Finding]:
        """Evaluate a resource change against this rule and return any findings."""
