"""Rule packs and registry for Preflight."""

from preflight.rules.aws import (
    AwsDatabaseDeletionReplacementRule,
    AwsIamWildcardRule,
    AwsPublicAdminIngressRule,
    AwsS3PublicAccessBlockRule,
)
from preflight.rules.azure import (
    AzureDatabaseDeletionReplacementRule,
    AzureKeyVaultPurgeProtectionRule,
    AzureNsgPublicAdminIngressRule,
    AzureStoragePublicAccessRule,
)
from preflight.rules.base import Rule, RuleContext
from preflight.rules.gcp import (
    GcpFirewallPublicAdminIngressRule,
    GcpSqlDeletionProtectionRule,
    GcpStoragePublicAccessRule,
)
from preflight.rules.generic import (
    GenericDestructiveChangeRule,
    GenericResourceDeletionRule,
    GenericResourceReplacementRule,
    GenericUnknownActionRule,
    GenericUnknownValuesRule,
)
from preflight.rules.kubernetes import (
    KubernetesClusterAdminBindingRule,
    KubernetesWorkloadSecurityRule,
)


def get_default_rules() -> list[Rule]:
    """Return an instantiated list of all standard detection rules."""
    return [
        # Provider-neutral rules
        GenericResourceDeletionRule(),
        GenericResourceReplacementRule(),
        GenericUnknownActionRule(),
        GenericUnknownValuesRule(),
        GenericDestructiveChangeRule(),
        # AWS rules
        AwsPublicAdminIngressRule(),
        AwsS3PublicAccessBlockRule(),
        AwsIamWildcardRule(),
        AwsDatabaseDeletionReplacementRule(),
        # Azure rules
        AzureNsgPublicAdminIngressRule(),
        AzureStoragePublicAccessRule(),
        AzureKeyVaultPurgeProtectionRule(),
        AzureDatabaseDeletionReplacementRule(),
        # GCP rules
        GcpFirewallPublicAdminIngressRule(),
        GcpStoragePublicAccessRule(),
        GcpSqlDeletionProtectionRule(),
        # Kubernetes rules
        KubernetesWorkloadSecurityRule(),
        KubernetesClusterAdminBindingRule(),
    ]


__all__ = [
    "Rule",
    "RuleContext",
    "get_default_rules",
    "GenericResourceDeletionRule",
    "GenericResourceReplacementRule",
    "GenericUnknownActionRule",
    "GenericUnknownValuesRule",
    "GenericDestructiveChangeRule",
    "AwsPublicAdminIngressRule",
    "AwsS3PublicAccessBlockRule",
    "AwsIamWildcardRule",
    "AwsDatabaseDeletionReplacementRule",
    "AzureNsgPublicAdminIngressRule",
    "AzureStoragePublicAccessRule",
    "AzureKeyVaultPurgeProtectionRule",
    "AzureDatabaseDeletionReplacementRule",
    "GcpFirewallPublicAdminIngressRule",
    "GcpStoragePublicAccessRule",
    "GcpSqlDeletionProtectionRule",
    "KubernetesWorkloadSecurityRule",
    "KubernetesClusterAdminBindingRule",
]
