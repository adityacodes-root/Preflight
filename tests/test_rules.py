"""Comprehensive unit tests for generic, AWS, Azure, GCP, and Kubernetes detection rules."""

from preflight.models import (
    ActionType,
    Environment,
    ResourceChange,
    Severity,
)
from preflight.rules import get_default_rules
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
from preflight.rules.base import RuleContext
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

CTX = RuleContext(environment=Environment.PRODUCTION)


def test_get_default_rules() -> None:
    rules = get_default_rules()
    assert len(rules) == 18
    rule_ids = [r.rule_id for r in rules]
    assert len(rule_ids) == len(set(rule_ids))


# --- GENERIC RULES ---


def test_generic_resource_deletion_rule() -> None:
    rule = GenericResourceDeletionRule()
    res = ResourceChange(
        address="aws_instance.worker",
        mode="managed",
        type="aws_instance",
        name="worker",
        provider_name="aws",
        raw_actions=["delete"],
        action=ActionType.DELETE,
    )
    findings = rule.evaluate(res, CTX)
    assert len(findings) == 1
    assert findings[0].rule_id == "GEN-DEL-001"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].action == ActionType.DELETE


def test_generic_resource_replacement_rule() -> None:
    rule = GenericResourceReplacementRule()
    res = ResourceChange(
        address="aws_instance.worker",
        mode="managed",
        type="aws_instance",
        name="worker",
        provider_name="aws",
        raw_actions=["delete", "create"],
        action=ActionType.REPLACE,
        replace_paths=[["ami"], ["instance_type"]],
    )
    findings = rule.evaluate(res, CTX)
    assert len(findings) == 1
    assert findings[0].rule_id == "GEN-REP-001"
    assert findings[0].severity == Severity.HIGH
    assert "ami" in findings[0].what_changed


def test_generic_unknown_action_rule() -> None:
    rule = GenericUnknownActionRule()
    res = ResourceChange(
        address="aws_instance.worker",
        mode="managed",
        type="aws_instance",
        name="worker",
        provider_name="aws",
        raw_actions=["reprovision_custom"],
        action=ActionType.UNKNOWN,
    )
    findings = rule.evaluate(res, CTX)
    assert len(findings) == 1
    assert findings[0].rule_id == "GEN-ACT-001"
    assert findings[0].severity == Severity.HIGH


def test_generic_unknown_values_rule() -> None:
    rule = GenericUnknownValuesRule()
    res = ResourceChange(
        address="aws_security_group.web",
        mode="managed",
        type="aws_security_group",
        name="web",
        provider_name="aws",
        raw_actions=["create"],
        action=ActionType.CREATE,
        after_unknown={"ingress": True, "egress": True, "vpc_id": True},
    )
    findings = rule.evaluate(res, CTX)
    assert len(findings) == 1
    assert findings[0].rule_id == "GEN-UNK-001"
    assert findings[0].severity == Severity.MODERATE


def test_generic_destructive_change_rule() -> None:
    rule = GenericDestructiveChangeRule()
    db_res = ResourceChange(
        address="aws_db_instance.main",
        mode="managed",
        type="aws_db_instance",
        name="main",
        provider_name="aws",
        raw_actions=["delete"],
        action=ActionType.DELETE,
    )
    findings = rule.evaluate(db_res, CTX)
    assert len(findings) == 1
    assert findings[0].rule_id == "GEN-DST-001"

    cfg_res = ResourceChange(
        address="aws_s3_bucket_public_access_block.pab",
        mode="managed",
        type="aws_s3_bucket_public_access_block",
        name="pab",
        provider_name="aws",
        raw_actions=["delete"],
        action=ActionType.DELETE,
    )
    assert len(rule.evaluate(cfg_res, CTX)) == 0


# --- AWS RULES ---


def test_aws_public_admin_ingress_ssh() -> None:
    rule = AwsPublicAdminIngressRule()
    sg_res = ResourceChange(
        address="aws_security_group.bastion",
        mode="managed",
        type="aws_security_group",
        name="bastion",
        provider_name="aws",
        raw_actions=["create"],
        action=ActionType.CREATE,
        after={
            "ingress": [
                {
                    "from_port": 22,
                    "to_port": 22,
                    "protocol": "tcp",
                    "cidr_blocks": ["0.0.0.0/0"],
                }
            ]
        },
    )
    findings = rule.evaluate(sg_res, CTX)
    assert len(findings) == 1
    assert findings[0].rule_id == "AWS-NET-001"
    assert findings[0].severity == Severity.CRITICAL
    assert "SSH:22" in findings[0].what_changed


def test_aws_public_admin_ingress_rdp_rule() -> None:
    rule = AwsPublicAdminIngressRule()
    sg_rule = ResourceChange(
        address="aws_security_group_rule.rdp",
        mode="managed",
        type="aws_security_group_rule",
        name="rdp",
        provider_name="aws",
        raw_actions=["update"],
        action=ActionType.UPDATE,
        after={
            "type": "ingress",
            "from_port": 3389,
            "to_port": 3389,
            "protocol": "tcp",
            "ipv6_cidr_blocks": ["::/0"],
        },
    )
    findings = rule.evaluate(sg_rule, CTX)
    assert len(findings) == 1
    assert findings[0].rule_id == "AWS-NET-001"
    assert "RDP:3389" in findings[0].what_changed


def test_aws_public_admin_ingress_all_traffic() -> None:
    rule = AwsPublicAdminIngressRule()
    ingress_rule = ResourceChange(
        address="aws_vpc_security_group_ingress_rule.all",
        mode="managed",
        type="aws_vpc_security_group_ingress_rule",
        name="all",
        provider_name="aws",
        raw_actions=["create"],
        action=ActionType.CREATE,
        after={
            "ip_protocol": "-1",
            "cidr_ipv4": "0.0.0.0/0",
        },
    )
    findings = rule.evaluate(ingress_rule, CTX)
    assert len(findings) == 1
    assert findings[0].rule_id == "AWS-NET-001"


def test_aws_public_admin_ingress_safe_internal() -> None:
    rule = AwsPublicAdminIngressRule()
    sg_res = ResourceChange(
        address="aws_security_group.internal",
        mode="managed",
        type="aws_security_group",
        name="internal",
        provider_name="aws",
        raw_actions=["create"],
        action=ActionType.CREATE,
        after={
            "ingress": [
                {
                    "from_port": 22,
                    "to_port": 22,
                    "protocol": "tcp",
                    "cidr_blocks": ["10.0.0.0/16"],
                }
            ]
        },
    )
    assert len(rule.evaluate(sg_res, CTX)) == 0


def test_aws_s3_public_access_block_deletion() -> None:
    rule = AwsS3PublicAccessBlockRule()
    res = ResourceChange(
        address="aws_s3_bucket_public_access_block.data",
        mode="managed",
        type="aws_s3_bucket_public_access_block",
        name="data",
        provider_name="aws",
        raw_actions=["delete"],
        action=ActionType.DELETE,
    )
    findings = rule.evaluate(res, CTX)
    assert len(findings) == 1
    assert findings[0].rule_id == "AWS-S3-001"
    assert findings[0].severity == Severity.CRITICAL


def test_aws_s3_public_access_block_disabled() -> None:
    rule = AwsS3PublicAccessBlockRule()
    res = ResourceChange(
        address="aws_s3_bucket_public_access_block.data",
        mode="managed",
        type="aws_s3_bucket_public_access_block",
        name="data",
        provider_name="aws",
        raw_actions=["update"],
        action=ActionType.UPDATE,
        after={
            "block_public_acls": False,
            "block_public_policy": False,
            "ignore_public_acls": True,
            "restrict_public_buckets": True,
        },
    )
    findings = rule.evaluate(res, CTX)
    assert len(findings) == 1
    assert findings[0].rule_id == "AWS-S3-001"
    assert findings[0].severity == Severity.CRITICAL


def test_aws_s3_bucket_public_acl() -> None:
    rule = AwsS3PublicAccessBlockRule()
    res = ResourceChange(
        address="aws_s3_bucket.static",
        mode="managed",
        type="aws_s3_bucket",
        name="static",
        provider_name="aws",
        raw_actions=["create"],
        action=ActionType.CREATE,
        after={"acl": "public-read"},
    )
    findings = rule.evaluate(res, CTX)
    assert len(findings) == 1
    assert findings[0].rule_id == "AWS-S3-001"
    assert findings[0].severity == Severity.CRITICAL


def test_aws_iam_wildcard_admin() -> None:
    rule = AwsIamWildcardRule()
    policy_doc = '{"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}'
    res = ResourceChange(
        address="aws_iam_policy.admin",
        mode="managed",
        type="aws_iam_policy",
        name="admin",
        provider_name="aws",
        raw_actions=["create"],
        action=ActionType.CREATE,
        after={"policy": policy_doc},
    )
    findings = rule.evaluate(res, CTX)
    assert len(findings) == 1
    assert findings[0].rule_id == "AWS-IAM-001"
    assert findings[0].severity == Severity.CRITICAL


def test_aws_iam_wildcard_broad_action_on_all_resources() -> None:
    rule = AwsIamWildcardRule()
    policy_doc = (
        '{"Statement": [{"Effect": "Allow", "Action": ["s3:*", "kms:*"], "Resource": "*"}]}'
    )
    res = ResourceChange(
        address="aws_iam_role_policy.service",
        mode="managed",
        type="aws_iam_role_policy",
        name="service",
        provider_name="aws",
        raw_actions=["create"],
        action=ActionType.CREATE,
        after={"policy": policy_doc},
    )
    findings = rule.evaluate(res, CTX)
    assert len(findings) == 1
    assert findings[0].rule_id == "AWS-IAM-001"
    assert findings[0].severity == Severity.HIGH


def test_aws_iam_wildcard_scoped_action() -> None:
    rule = AwsIamWildcardRule()
    policy_doc = '{"Statement": [{"Effect": "Allow", "Action": "s3:Get*", "Resource": "arn:aws:s3:::mybucket/*"}]}'
    res = ResourceChange(
        address="aws_iam_policy.reader",
        mode="managed",
        type="aws_iam_policy",
        name="reader",
        provider_name="aws",
        raw_actions=["create"],
        action=ActionType.CREATE,
        after={"policy": policy_doc},
    )
    findings = rule.evaluate(res, CTX)
    assert len(findings) == 1
    assert findings[0].rule_id == "AWS-IAM-001"
    assert findings[0].severity == Severity.MODERATE


def test_aws_database_deletion_and_replacement() -> None:
    rule = AwsDatabaseDeletionReplacementRule()

    del_res = ResourceChange(
        address="aws_db_instance.prod_pg",
        mode="managed",
        type="aws_db_instance",
        name="prod_pg",
        provider_name="aws",
        raw_actions=["delete"],
        action=ActionType.DELETE,
    )
    del_findings = rule.evaluate(del_res, CTX)
    assert len(del_findings) == 1
    assert del_findings[0].rule_id == "AWS-DB-001"
    assert del_findings[0].severity == Severity.CRITICAL

    rep_res = ResourceChange(
        address="aws_rds_cluster.aurora",
        mode="managed",
        type="aws_rds_cluster",
        name="aurora",
        provider_name="aws",
        raw_actions=["create", "delete"],
        action=ActionType.REPLACE,
    )
    rep_findings = rule.evaluate(rep_res, CTX)
    assert len(rep_findings) == 1
    assert rep_findings[0].rule_id == "AWS-DB-001"
    assert rep_findings[0].severity == Severity.CRITICAL


# --- AZURE RULES ---


def test_azure_nsg_public_admin_rule() -> None:
    rule = AzureNsgPublicAdminIngressRule()
    nsg_rule = ResourceChange(
        address="azurerm_network_security_rule.allow_ssh",
        mode="managed",
        type="azurerm_network_security_rule",
        name="allow_ssh",
        provider_name="azurerm",
        raw_actions=["create"],
        action=ActionType.CREATE,
        after={
            "direction": "Inbound",
            "access": "Allow",
            "source_address_prefix": "0.0.0.0/0",
            "destination_port_range": "22",
        },
    )
    findings = rule.evaluate(nsg_rule, CTX)
    assert len(findings) == 1
    assert findings[0].rule_id == "AZR-NET-001"
    assert findings[0].severity == Severity.CRITICAL
    assert "SSH:22" in findings[0].what_changed


def test_azure_nsg_public_admin_group_inline() -> None:
    rule = AzureNsgPublicAdminIngressRule()
    nsg = ResourceChange(
        address="azurerm_network_security_group.public",
        mode="managed",
        type="azurerm_network_security_group",
        name="public",
        provider_name="azurerm",
        raw_actions=["update"],
        action=ActionType.UPDATE,
        after={
            "security_rule": [
                {
                    "direction": "Inbound",
                    "access": "Allow",
                    "source_address_prefix": "Internet",
                    "destination_port_range": "*",
                }
            ]
        },
    )
    findings = rule.evaluate(nsg, CTX)
    assert len(findings) == 1
    assert findings[0].rule_id == "AZR-NET-001"
    assert "all ports (*)" in findings[0].what_changed


def test_azure_nsg_safe_internal() -> None:
    rule = AzureNsgPublicAdminIngressRule()
    nsg_rule = ResourceChange(
        address="azurerm_network_security_rule.safe",
        mode="managed",
        type="azurerm_network_security_rule",
        name="safe",
        provider_name="azurerm",
        raw_actions=["create"],
        action=ActionType.CREATE,
        after={
            "direction": "Inbound",
            "access": "Allow",
            "source_address_prefix": "10.0.0.0/16",
            "destination_port_range": "22",
        },
    )
    assert len(rule.evaluate(nsg_rule, CTX)) == 0


def test_azure_storage_public_access() -> None:
    rule = AzureStoragePublicAccessRule()
    stg = ResourceChange(
        address="azurerm_storage_account.data",
        mode="managed",
        type="azurerm_storage_account",
        name="data",
        provider_name="azurerm",
        raw_actions=["update"],
        action=ActionType.UPDATE,
        after={
            "allow_nested_items_to_be_public": True,
            "network_rules": {"default_action": "Allow"},
        },
    )
    findings = rule.evaluate(stg, CTX)
    assert len(findings) == 1
    assert findings[0].rule_id == "AZR-STG-001"
    assert findings[0].severity == Severity.HIGH


def test_azure_storage_safe() -> None:
    rule = AzureStoragePublicAccessRule()
    stg = ResourceChange(
        address="azurerm_storage_account.data",
        mode="managed",
        type="azurerm_storage_account",
        name="data",
        provider_name="azurerm",
        raw_actions=["create"],
        action=ActionType.CREATE,
        after={
            "allow_nested_items_to_be_public": False,
            "allow_blob_public_access": False,
            "network_rules": {"default_action": "Deny"},
        },
    )
    assert len(rule.evaluate(stg, CTX)) == 0


def test_azure_key_vault_purge_protection_disabled() -> None:
    rule = AzureKeyVaultPurgeProtectionRule()
    kv = ResourceChange(
        address="azurerm_key_vault.vault",
        mode="managed",
        type="azurerm_key_vault",
        name="vault",
        provider_name="azurerm",
        raw_actions=["update"],
        action=ActionType.UPDATE,
        after={
            "purge_protection_enabled": False,
            "soft_delete_retention_days": 5,
        },
    )
    findings = rule.evaluate(kv, CTX)
    assert len(findings) == 1
    assert findings[0].rule_id == "AZR-KV-001"
    assert findings[0].severity == Severity.HIGH


def test_azure_database_deletion_and_replacement() -> None:
    rule = AzureDatabaseDeletionReplacementRule()
    del_res = ResourceChange(
        address="azurerm_postgresql_flexible_server.pg",
        mode="managed",
        type="azurerm_postgresql_flexible_server",
        name="pg",
        provider_name="azurerm",
        raw_actions=["delete"],
        action=ActionType.DELETE,
    )
    del_findings = rule.evaluate(del_res, CTX)
    assert len(del_findings) == 1
    assert del_findings[0].rule_id == "AZR-DB-001"
    assert del_findings[0].severity == Severity.CRITICAL

    rep_res = ResourceChange(
        address="azurerm_cosmosdb_account.nosql",
        mode="managed",
        type="azurerm_cosmosdb_account",
        name="nosql",
        provider_name="azurerm",
        raw_actions=["create", "delete"],
        action=ActionType.REPLACE,
    )
    rep_findings = rule.evaluate(rep_res, CTX)
    assert len(rep_findings) == 1
    assert rep_findings[0].rule_id == "AZR-DB-001"


# --- GCP RULES ---


def test_gcp_firewall_public_admin_ingress() -> None:
    rule = GcpFirewallPublicAdminIngressRule()
    fw = ResourceChange(
        address="google_compute_firewall.allow_ssh",
        mode="managed",
        type="google_compute_firewall",
        name="allow_ssh",
        provider_name="google",
        raw_actions=["create"],
        action=ActionType.CREATE,
        after={
            "direction": "INGRESS",
            "source_ranges": ["0.0.0.0/0"],
            "allow": [{"protocol": "tcp", "ports": ["22"]}],
        },
    )
    findings = rule.evaluate(fw, CTX)
    assert len(findings) == 1
    assert findings[0].rule_id == "GCP-FW-001"
    assert findings[0].severity == Severity.CRITICAL
    assert "SSH:22" in findings[0].what_changed


def test_gcp_firewall_all_traffic_public() -> None:
    rule = GcpFirewallPublicAdminIngressRule()
    fw = ResourceChange(
        address="google_compute_firewall.allow_all",
        mode="managed",
        type="google_compute_firewall",
        name="allow_all",
        provider_name="google",
        raw_actions=["update"],
        action=ActionType.UPDATE,
        after={
            "direction": "INGRESS",
            "source_ranges": ["::/0"],
            "allow": [{"protocol": "all"}],
        },
    )
    findings = rule.evaluate(fw, CTX)
    assert len(findings) == 1
    assert findings[0].rule_id == "GCP-FW-001"


def test_gcp_firewall_safe_internal() -> None:
    rule = GcpFirewallPublicAdminIngressRule()
    fw = ResourceChange(
        address="google_compute_firewall.safe",
        mode="managed",
        type="google_compute_firewall",
        name="safe",
        provider_name="google",
        raw_actions=["create"],
        action=ActionType.CREATE,
        after={
            "direction": "INGRESS",
            "source_ranges": ["10.128.0.0/16"],
            "allow": [{"protocol": "tcp", "ports": ["22"]}],
        },
    )
    assert len(rule.evaluate(fw, CTX)) == 0


def test_gcp_storage_public_access() -> None:
    rule = GcpStoragePublicAccessRule()
    binding = ResourceChange(
        address="google_storage_bucket_iam_binding.public",
        mode="managed",
        type="google_storage_bucket_iam_binding",
        name="public",
        provider_name="google",
        raw_actions=["create"],
        action=ActionType.CREATE,
        after={
            "role": "roles/storage.objectViewer",
            "members": ["allUsers"],
        },
    )
    findings = rule.evaluate(binding, CTX)
    assert len(findings) == 1
    assert findings[0].rule_id == "GCP-IAM-001"
    assert findings[0].severity == Severity.CRITICAL

    member = ResourceChange(
        address="google_storage_bucket_iam_member.auth_users",
        mode="managed",
        type="google_storage_bucket_iam_member",
        name="auth_users",
        provider_name="google",
        raw_actions=["create"],
        action=ActionType.CREATE,
        after={
            "role": "roles/storage.admin",
            "member": "allAuthenticatedUsers",
        },
    )
    member_findings = rule.evaluate(member, CTX)
    assert len(member_findings) == 1
    assert member_findings[0].rule_id == "GCP-IAM-001"


def test_gcp_sql_deletion_and_protection() -> None:
    rule = GcpSqlDeletionProtectionRule()

    del_res = ResourceChange(
        address="google_sql_database_instance.primary",
        mode="managed",
        type="google_sql_database_instance",
        name="primary",
        provider_name="google",
        raw_actions=["delete"],
        action=ActionType.DELETE,
    )
    del_findings = rule.evaluate(del_res, CTX)
    assert len(del_findings) == 1
    assert del_findings[0].rule_id == "GCP-SQL-001"
    assert del_findings[0].severity == Severity.CRITICAL

    prot_res = ResourceChange(
        address="google_sql_database_instance.primary",
        mode="managed",
        type="google_sql_database_instance",
        name="primary",
        provider_name="google",
        raw_actions=["update"],
        action=ActionType.UPDATE,
        after={
            "settings": {"deletion_protection": False},
        },
    )
    prot_findings = rule.evaluate(prot_res, CTX)
    assert len(prot_findings) == 1
    assert prot_findings[0].rule_id == "GCP-SQL-001"
    assert prot_findings[0].severity == Severity.HIGH


# --- KUBERNETES RULES ---


def test_kubernetes_workload_security_privileged() -> None:
    rule = KubernetesWorkloadSecurityRule()
    dep = ResourceChange(
        address="kubernetes_deployment.agent",
        mode="managed",
        type="kubernetes_deployment",
        name="agent",
        provider_name="kubernetes",
        raw_actions=["create"],
        action=ActionType.CREATE,
        after={
            "spec": {
                "template": {
                    "spec": {
                        "container": [
                            {
                                "name": "monitor",
                                "security_context": {"privileged": True},
                            }
                        ]
                    }
                }
            }
        },
    )
    findings = rule.evaluate(dep, CTX)
    assert len(findings) == 1
    assert findings[0].rule_id == "K8S-SEC-001"
    assert findings[0].severity == Severity.HIGH
    assert "privileged=true" in findings[0].what_changed


def test_kubernetes_workload_host_network() -> None:
    rule = KubernetesWorkloadSecurityRule()
    pod = ResourceChange(
        address="kubernetes_pod.node_exporter",
        mode="managed",
        type="kubernetes_pod",
        name="node_exporter",
        provider_name="kubernetes",
        raw_actions=["create"],
        action=ActionType.CREATE,
        after={
            "spec": {
                "host_network": True,
            }
        },
    )
    findings = rule.evaluate(pod, CTX)
    assert len(findings) == 1
    assert findings[0].rule_id == "K8S-SEC-001"
    assert "hostNetwork is enabled" in findings[0].what_changed


def test_kubernetes_helm_release_privileged() -> None:
    rule = KubernetesWorkloadSecurityRule()
    helm = ResourceChange(
        address="helm_release.fluentd",
        mode="managed",
        type="helm_release",
        name="fluentd",
        provider_name="helm",
        raw_actions=["create"],
        action=ActionType.CREATE,
        after={
            "set": [
                {"name": "securityContext.privileged", "value": "true"},
            ]
        },
    )
    findings = rule.evaluate(helm, CTX)
    assert len(findings) == 1
    assert findings[0].rule_id == "K8S-SEC-001"


def test_kubernetes_workload_safe() -> None:
    rule = KubernetesWorkloadSecurityRule()
    dep = ResourceChange(
        address="kubernetes_deployment.web",
        mode="managed",
        type="kubernetes_deployment",
        name="web",
        provider_name="kubernetes",
        raw_actions=["create"],
        action=ActionType.CREATE,
        after={
            "spec": {
                "template": {
                    "spec": {
                        "container": [
                            {
                                "name": "web",
                                "security_context": {"privileged": False},
                            }
                        ]
                    }
                }
            }
        },
    )
    assert len(rule.evaluate(dep, CTX)) == 0


def test_kubernetes_cluster_admin_binding() -> None:
    rule = KubernetesClusterAdminBindingRule()
    crb = ResourceChange(
        address="kubernetes_cluster_role_binding.admin_binding",
        mode="managed",
        type="kubernetes_cluster_role_binding",
        name="admin_binding",
        provider_name="kubernetes",
        raw_actions=["create"],
        action=ActionType.CREATE,
        after={
            "role_ref": {
                "kind": "ClusterRole",
                "name": "cluster-admin",
            },
            "subject": [
                {"kind": "User", "name": "alice"},
            ],
        },
    )
    findings = rule.evaluate(crb, CTX)
    assert len(findings) == 1
    assert findings[0].rule_id == "K8S-RBAC-001"
    assert findings[0].severity == Severity.CRITICAL
    assert "cluster-admin" in findings[0].what_changed


def test_kubernetes_cluster_role_binding_safe() -> None:
    rule = KubernetesClusterAdminBindingRule()
    crb = ResourceChange(
        address="kubernetes_cluster_role_binding.view_binding",
        mode="managed",
        type="kubernetes_cluster_role_binding",
        name="view_binding",
        provider_name="kubernetes",
        raw_actions=["create"],
        action=ActionType.CREATE,
        after={
            "role_ref": {
                "kind": "ClusterRole",
                "name": "view",
            },
            "subject": [
                {"kind": "User", "name": "bob"},
            ],
        },
    )
    assert len(rule.evaluate(crb, CTX)) == 0


def test_azure_nsg_port_range_and_prefixes() -> None:
    rule = AzureNsgPublicAdminIngressRule()
    nsg_rule = ResourceChange(
        address="azurerm_network_security_rule.admin_range",
        mode="managed",
        type="azurerm_network_security_rule",
        name="admin_range",
        provider_name="azurerm",
        raw_actions=["create"],
        action=ActionType.CREATE,
        after={
            "direction": "inbound",
            "access": "allow",
            "source_address_prefixes": ["192.168.1.0/24", "0.0.0.0/0"],
            "destination_port_ranges": ["20-25", "3389"],
        },
    )
    findings = rule.evaluate(nsg_rule, CTX)
    assert len(findings) == 1
    assert "SSH:22" in findings[0].what_changed


def test_azure_storage_blob_public_access() -> None:
    rule = AzureStoragePublicAccessRule()
    stg = ResourceChange(
        address="azurerm_storage_account.blob_pub",
        mode="managed",
        type="azurerm_storage_account",
        name="blob_pub",
        provider_name="azurerm",
        raw_actions=["create"],
        action=ActionType.CREATE,
        after={"allow_blob_public_access": True},
    )
    findings = rule.evaluate(stg, CTX)
    assert len(findings) == 1
    assert findings[0].rule_id == "AZR-STG-001"


def test_gcp_firewall_port_range_and_rdp() -> None:
    rule = GcpFirewallPublicAdminIngressRule()
    fw = ResourceChange(
        address="google_compute_firewall.rdp",
        mode="managed",
        type="google_compute_firewall",
        name="rdp",
        provider_name="google",
        raw_actions=["create"],
        action=ActionType.CREATE,
        after={
            "direction": "INGRESS",
            "source_ranges": ["0.0.0.0/0"],
            "allow": [{"protocol": "tcp", "ports": ["3380-3390"]}],
        },
    )
    findings = rule.evaluate(fw, CTX)
    assert len(findings) == 1
    assert "RDP:3389" in findings[0].what_changed


def test_gcp_storage_access_control_public() -> None:
    rule = GcpStoragePublicAccessRule()
    acl = ResourceChange(
        address="google_storage_bucket_access_control.public",
        mode="managed",
        type="google_storage_bucket_access_control",
        name="public",
        provider_name="google",
        raw_actions=["create"],
        action=ActionType.CREATE,
        after={"role": "READER", "entity": "allUsers"},
    )
    findings = rule.evaluate(acl, CTX)
    assert len(findings) == 1
    assert findings[0].rule_id == "GCP-IAM-001"


def test_gcp_sql_replacement() -> None:
    rule = GcpSqlDeletionProtectionRule()
    db = ResourceChange(
        address="google_sql_database_instance.replica",
        mode="managed",
        type="google_sql_database_instance",
        name="replica",
        provider_name="google",
        raw_actions=["create", "delete"],
        action=ActionType.REPLACE,
    )
    findings = rule.evaluate(db, CTX)
    assert len(findings) == 1
    assert "replaced (destroy and recreate)" in findings[0].what_changed


def test_kubernetes_workload_host_pid_and_ipc() -> None:
    rule = KubernetesWorkloadSecurityRule()
    pod = ResourceChange(
        address="kubernetes_pod.diagnostic",
        mode="managed",
        type="kubernetes_pod",
        name="diagnostic",
        provider_name="kubernetes",
        raw_actions=["create"],
        action=ActionType.CREATE,
        after={
            "spec": {
                "host_pid": True,
                "host_ipc": True,
            }
        },
    )
    findings = rule.evaluate(pod, CTX)
    assert len(findings) == 1
    assert "hostPID is enabled" in findings[0].what_changed
    assert "hostIPC is enabled" in findings[0].what_changed


def test_kubernetes_helm_release_values_yaml() -> None:
    rule = KubernetesWorkloadSecurityRule()
    helm = ResourceChange(
        address="helm_release.agent",
        mode="managed",
        type="helm_release",
        name="agent",
        provider_name="helm",
        raw_actions=["create"],
        action=ActionType.CREATE,
        after={
            "values": [
                "privileged: true\nhostNetwork: true\n",
            ]
        },
    )
    findings = rule.evaluate(helm, CTX)
    assert len(findings) == 1
    assert "helm values contains privileged: true" in findings[0].what_changed
    assert "helm values contains hostNetwork: true" in findings[0].what_changed
