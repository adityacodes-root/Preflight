"""AWS-specific detection rules for Terraform plans."""

import json
from typing import Any

from preflight.models import (
    ActionType,
    Finding,
    ResourceChange,
    RiskFactors,
    Severity,
)
from preflight.rules.base import Rule, RuleContext
from preflight.scoring import score_finding

PUBLIC_CIDRS = {"0.0.0.0/0", "::/0"}
ADMIN_PORTS = {22, 3389}

AWS_DATABASE_TYPES = {
    "aws_db_instance",
    "aws_rds_cluster",
    "aws_rds_cluster_instance",
    "aws_dynamodb_table",
    "aws_elasticache_cluster",
    "aws_elasticache_replication_group",
    "aws_redshift_cluster",
    "aws_docdb_cluster",
    "aws_neptune_cluster",
}


def _ports_include_admin(
    from_port: int | None, to_port: int | None, protocol: str | None
) -> tuple[bool, str]:
    """Determine if a port range or protocol includes SSH (22) or RDP (3389)."""
    if protocol in ("-1", "all"):
        return True, "all traffic (including SSH:22 and RDP:3389)"

    if from_port is None or to_port is None:
        return False, ""

    if from_port <= 0 and to_port <= 0:
        return True, "all traffic (ports 0-65535)"

    low = min(from_port, to_port)
    high = max(from_port, to_port)

    included = []
    if low <= 22 <= high:
        included.append("SSH:22")
    if low <= 3389 <= high:
        included.append("RDP:3389")

    if included:
        return True, ", ".join(included)
    return False, ""


def _extract_cidrs(rule_data: dict[str, Any]) -> tuple[set[str], bool]:
    """Extract IPv4 and IPv6 CIDRs from an ingress definition, noting if computed."""
    cidrs: set[str] = set()
    is_unknown = False

    # Check cidr_blocks
    raw_blocks = rule_data.get("cidr_blocks")
    if isinstance(raw_blocks, list):
        for b in raw_blocks:
            if isinstance(b, str):
                cidrs.add(b.strip())
    elif isinstance(raw_blocks, str):
        cidrs.add(raw_blocks.strip())

    # Check ipv6_cidr_blocks
    raw_v6 = rule_data.get("ipv6_cidr_blocks")
    if isinstance(raw_v6, list):
        for b in raw_v6:
            if isinstance(b, str):
                cidrs.add(b.strip())
    elif isinstance(raw_v6, str):
        cidrs.add(raw_v6.strip())

    # Check vpc security group rule single cidr attributes
    cidr_ipv4 = rule_data.get("cidr_ipv4")
    if isinstance(cidr_ipv4, str):
        cidrs.add(cidr_ipv4.strip())
    cidr_ipv6 = rule_data.get("cidr_ipv6")
    if isinstance(cidr_ipv6, str):
        cidrs.add(cidr_ipv6.strip())

    return cidrs, is_unknown


class AwsPublicAdminIngressRule(Rule):
    rule_id = "AWS-NET-001"
    name = "Public SSH/RDP Security Group Ingress"
    description = (
        "Detects security group rules exposing SSH (22) or RDP (3389) to 0.0.0.0/0 or ::/0."
    )
    default_severity = Severity.CRITICAL

    def evaluate(self, resource: ResourceChange, context: RuleContext) -> list[Finding]:
        if resource.action not in (ActionType.CREATE, ActionType.UPDATE, ActionType.REPLACE):
            return []

        findings: list[Finding] = []
        after = resource.after or {}

        # 1. aws_security_group (inline ingress rules)
        if resource.type == "aws_security_group":
            ingress_list = after.get("ingress", [])
            if isinstance(ingress_list, list):
                for idx, ing in enumerate(ingress_list):
                    if not isinstance(ing, dict):
                        continue
                    cidrs, _ = _extract_cidrs(ing)
                    public_cidrs = cidrs.intersection(PUBLIC_CIDRS)
                    from_p = ing.get("from_port")
                    to_p = ing.get("to_port")
                    proto = str(ing.get("protocol", "")).lower()

                    matches_admin, port_desc = _ports_include_admin(from_p, to_p, proto)
                    if matches_admin and public_cidrs:
                        findings.append(
                            self._create_finding(
                                resource=resource,
                                context=context,
                                port_desc=port_desc,
                                exposed_cidrs=sorted(public_cidrs),
                                detail=f"inline ingress rule #{idx}",
                            )
                        )

        # 2. aws_security_group_rule
        elif resource.type == "aws_security_group_rule":
            rule_type = str(after.get("type", "")).lower()
            if rule_type == "ingress":
                cidrs, _ = _extract_cidrs(after)
                public_cidrs = cidrs.intersection(PUBLIC_CIDRS)
                from_p = after.get("from_port")
                to_p = after.get("to_port")
                proto = str(after.get("protocol", "")).lower()

                matches_admin, port_desc = _ports_include_admin(from_p, to_p, proto)
                if matches_admin and public_cidrs:
                    findings.append(
                        self._create_finding(
                            resource=resource,
                            context=context,
                            port_desc=port_desc,
                            exposed_cidrs=sorted(public_cidrs),
                            detail="standalone security group ingress rule",
                        )
                    )

        # 3. aws_vpc_security_group_ingress_rule
        elif resource.type == "aws_vpc_security_group_ingress_rule":
            cidrs, _ = _extract_cidrs(after)
            public_cidrs = cidrs.intersection(PUBLIC_CIDRS)
            from_p = after.get("from_port")
            to_p = after.get("to_port")
            proto = str(after.get("ip_protocol", "")).lower()

            matches_admin, port_desc = _ports_include_admin(from_p, to_p, proto)
            if matches_admin and public_cidrs:
                findings.append(
                    self._create_finding(
                        resource=resource,
                        context=context,
                        port_desc=port_desc,
                        exposed_cidrs=sorted(public_cidrs),
                        detail="aws_vpc_security_group_ingress_rule",
                    )
                )

        return findings

    def _create_finding(
        self,
        resource: ResourceChange,
        context: RuleContext,
        port_desc: str,
        exposed_cidrs: list[str],
        detail: str,
    ) -> Finding:
        base_factors = RiskFactors(
            change_impact=3.5,
            security_exposure=5.0,
            reversibility=1.0,
            uncertainty=0.5,
        )
        resolved_factors, score = score_finding(base_factors, context.environment)

        return Finding(
            rule_id=self.rule_id,
            rule_name=self.name,
            severity=self.default_severity,
            resource_address=resource.address,
            resource_type=resource.type,
            action=resource.action,
            what_changed=(
                f"Ingress rule on '{resource.address}' exposes {port_desc} to public internet ({', '.join(exposed_cidrs)})."
            ),
            why_it_matters=(
                "Exposing management ports (SSH/RDP) to 0.0.0.0/0 invites brute-force credential stuffing, "
                "automated vulnerability scans, and potential unauthorized system access."
            ),
            remediation=(
                "Restrict ingress CIDRs to a corporate VPN, trusted bastion host, or migrate to "
                "AWS Systems Manager Session Manager for credential-free, portless shell access."
            ),
            risk_factors=resolved_factors,
            calculated_score=score,
            details={
                "exposed_ports": port_desc,
                "exposed_cidrs": exposed_cidrs,
                "rule_context": detail,
            },
        )


class AwsS3PublicAccessBlockRule(Rule):
    rule_id = "AWS-S3-001"
    name = "S3 Public Access Block Disabled or Removed"
    description = (
        "Detects removal, disabling, or permissive changes to S3 bucket public access blocks."
    )
    default_severity = Severity.CRITICAL

    def evaluate(self, resource: ResourceChange, context: RuleContext) -> list[Finding]:
        findings: list[Finding] = []

        # 1. aws_s3_bucket_public_access_block deletion or replacement
        if resource.type == "aws_s3_bucket_public_access_block":
            if resource.action in (ActionType.DELETE, ActionType.REPLACE):
                action_text = "deleted" if resource.action == ActionType.DELETE else "recreated"
                base_factors = RiskFactors(
                    change_impact=4.0,
                    security_exposure=5.0,
                    reversibility=2.0,
                    uncertainty=0.5,
                )
                resolved_factors, score = score_finding(base_factors, context.environment)
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        rule_name=self.name,
                        severity=Severity.CRITICAL,
                        resource_address=resource.address,
                        resource_type=resource.type,
                        action=resource.action,
                        what_changed=(
                            f"S3 Public Access Block configuration '{resource.address}' is being {action_text}."
                        ),
                        why_it_matters=(
                            "Removing the bucket-level Public Access Block allows bucket policies or object ACLs "
                            "to make bucket contents publicly accessible to the internet."
                        ),
                        remediation=(
                            "Retain the aws_s3_bucket_public_access_block resource to ensure public access "
                            "remains unconditionally blocked."
                        ),
                        risk_factors=resolved_factors,
                        calculated_score=score,
                        details={"action": resource.action.value},
                    )
                )

            # Check for block settings set to False
            elif resource.action in (ActionType.CREATE, ActionType.UPDATE):
                after = resource.after or {}
                disabled_flags = [
                    flag
                    for flag in (
                        "block_public_acls",
                        "block_public_policy",
                        "ignore_public_acls",
                        "restrict_public_buckets",
                    )
                    if after.get(flag) is False
                ]

                if disabled_flags:
                    severity = Severity.CRITICAL if len(disabled_flags) >= 2 else Severity.HIGH
                    base_factors = RiskFactors(
                        change_impact=3.5,
                        security_exposure=4.5 if severity == Severity.HIGH else 5.0,
                        reversibility=2.0,
                        uncertainty=0.5,
                    )
                    resolved_factors, score = score_finding(base_factors, context.environment)
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            rule_name=self.name,
                            severity=severity,
                            resource_address=resource.address,
                            resource_type=resource.type,
                            action=resource.action,
                            what_changed=(
                                f"S3 Public Access Block '{resource.address}' has protective controls disabled: "
                                f"{', '.join(disabled_flags)}."
                            ),
                            why_it_matters=(
                                "Disabling public access block settings leaves the bucket vulnerable to unintended "
                                "data exposure through permissive object ACLs or misconfigured bucket policies."
                            ),
                            remediation=(
                                "Set block_public_acls, block_public_policy, ignore_public_acls, and "
                                "restrict_public_buckets to true."
                            ),
                            risk_factors=resolved_factors,
                            calculated_score=score,
                            details={"disabled_flags": disabled_flags},
                        )
                    )

        # 2. aws_s3_bucket with public ACL
        elif resource.type == "aws_s3_bucket":
            after = resource.after or {}
            acl = str(after.get("acl", "")).lower()
            if acl in ("public-read", "public-read-write", "website"):
                base_factors = RiskFactors(
                    change_impact=3.5,
                    security_exposure=5.0,
                    reversibility=1.5,
                    uncertainty=0.5,
                )
                resolved_factors, score = score_finding(base_factors, context.environment)
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        rule_name=self.name,
                        severity=Severity.CRITICAL,
                        resource_address=resource.address,
                        resource_type=resource.type,
                        action=resource.action,
                        what_changed=(
                            f"S3 bucket '{resource.address}' is configured with public ACL: '{acl}'."
                        ),
                        why_it_matters=(
                            f"Setting ACL to '{acl}' enables unauthenticated public read or write access."
                        ),
                        remediation=(
                            "Change the bucket ACL to 'private' and ensure bucket policies enforce access restrictions."
                        ),
                        risk_factors=resolved_factors,
                        calculated_score=score,
                        details={"acl": acl},
                    )
                )

        return findings


class AwsIamWildcardRule(Rule):
    rule_id = "AWS-IAM-001"
    name = "IAM Policy Wildcard Actions or Resources"
    description = "Detects overly permissive IAM policies granting wildcard actions or resources."
    default_severity = Severity.HIGH

    IAM_POLICY_TYPES = {
        "aws_iam_policy",
        "aws_iam_role_policy",
        "aws_iam_user_policy",
        "aws_iam_group_policy",
    }

    def evaluate(self, resource: ResourceChange, context: RuleContext) -> list[Finding]:
        if resource.type not in self.IAM_POLICY_TYPES:
            return []
        if resource.action not in (ActionType.CREATE, ActionType.UPDATE, ActionType.REPLACE):
            return []

        after = resource.after or {}
        policy_raw = after.get("policy")
        if not policy_raw:
            return []

        doc = self._parse_policy_doc(policy_raw)
        if not doc:
            return []

        statements = doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
        if not isinstance(statements, list):
            return []

        findings: list[Finding] = []
        for idx, stmt in enumerate(statements):
            if not isinstance(stmt, dict):
                continue
            if str(stmt.get("Effect", "")).lower() != "allow":
                continue

            actions = self._normalize_list(stmt.get("Action"))
            resources = self._normalize_list(stmt.get("Resource"))

            # Condition 1: Full Administrator (Action: * and Resource: *)
            if "*" in actions and "*" in resources:
                base_factors = RiskFactors(
                    change_impact=4.5,
                    security_exposure=5.0,
                    reversibility=1.5,
                    uncertainty=0.5,
                )
                resolved_factors, score = score_finding(base_factors, context.environment)
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        rule_name=self.name,
                        severity=Severity.CRITICAL,
                        resource_address=resource.address,
                        resource_type=resource.type,
                        action=resource.action,
                        what_changed=(
                            f"IAM policy on '{resource.address}' statement #{idx} grants full admin access ('Action': '*', 'Resource': '*')."
                        ),
                        why_it_matters=(
                            "Granting unrestricted '*' on all resources provides full administrative privileges, "
                            "bypassing least-privilege boundaries and enabling full account compromise."
                        ),
                        remediation=(
                            "Replace wildcards with explicit service actions and target resource ARNs."
                        ),
                        risk_factors=resolved_factors,
                        calculated_score=score,
                        details={
                            "statement_index": idx,
                            "actions": actions,
                            "resources": resources,
                        },
                    )
                )

            # Condition 2: Broad action wildcards on Resource: * (e.g., iam:*, s3:*, etc.)
            elif "*" in resources and any("*" in a for a in actions):
                broad_actions = [a for a in actions if "*" in a]
                base_factors = RiskFactors(
                    change_impact=3.5,
                    security_exposure=4.0,
                    reversibility=1.5,
                    uncertainty=0.5,
                )
                resolved_factors, score = score_finding(base_factors, context.environment)
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        rule_name=self.name,
                        severity=Severity.HIGH,
                        resource_address=resource.address,
                        resource_type=resource.type,
                        action=resource.action,
                        what_changed=(
                            f"IAM policy on '{resource.address}' statement #{idx} grants broad wildcard actions ({', '.join(broad_actions)}) on all resources ('*')."
                        ),
                        why_it_matters=(
                            "Wildcard service actions on all resources allow unintended high-risk operations "
                            "(e.g., privilege escalation, data exfiltration, or configuration tampering)."
                        ),
                        remediation=(
                            "Scope IAM actions to specific verbs (e.g., 's3:GetObject' instead of 's3:*') "
                            "and restrict resource ARNs."
                        ),
                        risk_factors=resolved_factors,
                        calculated_score=score,
                        details={
                            "statement_index": idx,
                            "broad_actions": broad_actions,
                            "resources": resources,
                        },
                    )
                )

            # Condition 3: Wildcard action on scoped resource or vice versa
            elif any("*" in a for a in actions):
                wildcard_actions = [a for a in actions if "*" in a]
                base_factors = RiskFactors(
                    change_impact=2.5,
                    security_exposure=3.0,
                    reversibility=1.0,
                    uncertainty=0.5,
                )
                resolved_factors, score = score_finding(base_factors, context.environment)
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        rule_name=self.name,
                        severity=Severity.MODERATE,
                        resource_address=resource.address,
                        resource_type=resource.type,
                        action=resource.action,
                        what_changed=(
                            f"IAM policy on '{resource.address}' statement #{idx} contains wildcard actions: {', '.join(wildcard_actions)}."
                        ),
                        why_it_matters=(
                            "Wildcard actions may grant new permissions unintentionally as AWS adds API actions to the service."
                        ),
                        remediation=(
                            "Explicitly enumerate required IAM actions instead of using prefix wildcards."
                        ),
                        risk_factors=resolved_factors,
                        calculated_score=score,
                        details={"statement_index": idx, "wildcard_actions": wildcard_actions},
                    )
                )

        return findings

    def _parse_policy_doc(self, policy: Any) -> dict[str, Any] | None:
        if isinstance(policy, dict):
            return policy
        if isinstance(policy, str):
            try:
                data = json.loads(policy)
                return data if isinstance(data, dict) else None
            except json.JSONDecodeError:
                return None
        return None

    def _normalize_list(self, value: Any) -> list[str]:
        if isinstance(value, str):
            return [value]
        if isinstance(value, list):
            return [str(v) for v in value]
        return []


class AwsDatabaseDeletionReplacementRule(Rule):
    rule_id = "AWS-DB-001"
    name = "AWS Database Deletion or Replacement"
    description = "Detects destructive deletion or replacement of AWS database resources."
    default_severity = Severity.CRITICAL

    def evaluate(self, resource: ResourceChange, context: RuleContext) -> list[Finding]:
        if resource.type not in AWS_DATABASE_TYPES:
            return []
        if resource.action not in (ActionType.DELETE, ActionType.REPLACE):
            return []

        action_desc = (
            "replacement (recreation)" if resource.action == ActionType.REPLACE else "deletion"
        )

        base_factors = RiskFactors(
            change_impact=5.0,
            security_exposure=1.0,
            reversibility=5.0,
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
                    f"AWS database resource '{resource.address}' ({resource.type}) is scheduled for {action_desc}."
                ),
                why_it_matters=(
                    "Destroying or replacing a managed database causes service outage and permanent data loss "
                    "unless an automated point-in-time snapshot or replication cluster is ready to take over."
                ),
                remediation=(
                    "Verify deletion_protection is active, ensure a recent final snapshot exists, and inspect "
                    "'replace_paths' to determine whether the change can be applied in-place without recreation."
                ),
                risk_factors=resolved_factors,
                calculated_score=score,
                details={
                    "database_type": resource.type,
                    "action": resource.action.value,
                    "replace_paths": [str(p) for p in (resource.replace_paths or [])],
                },
            )
        ]
