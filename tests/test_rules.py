"""Comprehensive unit tests for generic and AWS detection rules."""

from preflight.models import (
    ActionType,
    Environment,
    ResourceChange,
    Severity,
)
from preflight.rules.aws import (
    AwsDatabaseDeletionReplacementRule,
    AwsIamWildcardRule,
    AwsPublicAdminIngressRule,
    AwsS3PublicAccessBlockRule,
)
from preflight.rules.base import RuleContext
from preflight.rules.generic import (
    GenericDestructiveChangeRule,
    GenericResourceDeletionRule,
    GenericResourceReplacementRule,
    GenericUnknownActionRule,
    GenericUnknownValuesRule,
)

CTX = RuleContext(environment=Environment.PRODUCTION)


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
    # Stateful DB resource scheduled for deletion
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

    # Configuration resource ending with _public_access_block should be excluded
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
    # Inline SG with SSH port 22 open to 0.0.0.0/0
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
    # Security group rule with RDP port 3389
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
    # VPC security group ingress rule allowing all protocols
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
    # Port 22 open only to internal subnet 10.0.0.0/16
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

    # Deletion
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

    # Replacement
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
