"""GCP specific rules."""

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
PUBLIC_IDENTITIES = {"allusers", "allauthenticatedusers"}


def _gcp_firewall_allows_admin(allow_blocks: list[Any]) -> tuple[bool, str]:
    for block in allow_blocks:
        if not isinstance(block, dict):
            continue
        proto = str(block.get("protocol", "")).lower()
        ports = block.get("ports", [])

        if proto in ("all", "-1") or (proto == "tcp" and not ports):
            return True, f"all traffic ({proto})"

        port_list = [str(p) for p in ports] if isinstance(ports, list) else []
        found_ports: list[str] = []
        for p in port_list:
            if p == "22":
                found_ports.append("SSH:22")
            elif p == "3389":
                found_ports.append("RDP:3389")
            elif "-" in p:
                parts = p.split("-", 1)
                try:
                    low, high = int(parts[0]), int(parts[1])
                    if low <= 22 <= high:
                        found_ports.append("SSH:22")
                    if low <= 3389 <= high:
                        found_ports.append("RDP:3389")
                except ValueError:
                    pass
        if found_ports:
            return True, ", ".join(found_ports)

    return False, ""


class GcpFirewallPublicAdminIngressRule(Rule):
    rule_id = "GCP-FW-001"
    name = "GCP Firewall Public Administrative Ingress"
    description = "Detects compute firewall rules exposing management ports (22, 3389) or all traffic to 0.0.0.0/0."
    default_severity = Severity.CRITICAL

    def evaluate(self, resource: ResourceChange, context: RuleContext) -> list[Finding]:
        if resource.type != "google_compute_firewall" or resource.action == ActionType.DELETE:
            return []

        after = resource.after or {}
        direction = str(after.get("direction", "INGRESS")).upper()
        if direction != "INGRESS":
            return []

        ranges = after.get("source_ranges") or []
        range_set = {str(r).strip() for r in ranges} if isinstance(ranges, list) else set()
        matched_cidrs = range_set.intersection(PUBLIC_CIDRS)
        if not matched_cidrs:
            return []

        allow_blocks = after.get("allow") or []
        if not isinstance(allow_blocks, list):
            return []

        matches_admin, port_desc = _gcp_firewall_allows_admin(allow_blocks)
        if not matches_admin:
            return []

        base_factors = RiskFactors(
            change_impact=3.5,
            security_exposure=5.0,
            reversibility=1.0,
            uncertainty=0.5,
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
                    f"Firewall rule '{resource.address}' allows ingress {port_desc} "
                    f"from public internet ({', '.join(sorted(matched_cidrs))})."
                ),
                why_it_matters="Exposing SSH or RDP to all internet IP addresses exposes instances to automated port scanning and brute force attacks.",
                remediation="Restrict source_ranges to trusted corporate CIDRs, bastion IPs, or use Identity-Aware Proxy (IAP) for TCP forwarding.",
                risk_factors=resolved_factors,
                calculated_score=score,
                details={"source_ranges": sorted(matched_cidrs), "exposed_ports": port_desc},
            )
        ]


class GcpStoragePublicAccessRule(Rule):
    rule_id = "GCP-IAM-001"
    name = "GCP Cloud Storage Public IAM Grant"
    description = "Detects storage bucket IAM bindings or members that grant access to allUsers or allAuthenticatedUsers."
    default_severity = Severity.CRITICAL

    def evaluate(self, resource: ResourceChange, context: RuleContext) -> list[Finding]:
        if resource.action == ActionType.DELETE or not resource.after:
            return []

        public_members: list[str] = []

        if resource.type in (
            "google_storage_bucket_iam_binding",
            "google_storage_bucket_iam_policy",
        ):
            members = resource.after.get("members") or []
            if isinstance(members, list):
                public_members = [
                    str(m) for m in members if str(m).strip().lower() in PUBLIC_IDENTITIES
                ]

        elif resource.type == "google_storage_bucket_iam_member":
            member = str(resource.after.get("member", "")).strip().lower()
            if member in PUBLIC_IDENTITIES:
                public_members = [member]

        elif resource.type == "google_storage_bucket_access_control":
            entity = str(resource.after.get("entity", "")).strip().lower()
            if entity in PUBLIC_IDENTITIES:
                public_members = [entity]

        if not public_members:
            return []

        role = str(resource.after.get("role", "custom"))
        base_factors = RiskFactors(
            change_impact=4.0,
            security_exposure=5.0,
            reversibility=2.0,
            uncertainty=0.5,
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
                    f"Storage IAM resource '{resource.address}' grants role '{role}' "
                    f"to public identities ({', '.join(public_members)})."
                ),
                why_it_matters="Granting storage bucket permissions to allUsers or allAuthenticatedUsers exposes data publicly without authentication.",
                remediation="Remove public identity grants and enforce uniform bucket-level access with targeted service account or user bindings.",
                risk_factors=resolved_factors,
                calculated_score=score,
                details={"role": role, "public_members": public_members},
            )
        ]


class GcpSqlDeletionProtectionRule(Rule):
    rule_id = "GCP-SQL-001"
    name = "Cloud SQL Deletion or Deletion Protection Disabled"
    description = "Detects deletion or forced replacement of Cloud SQL instances, or disabling instance deletion protection."
    default_severity = Severity.CRITICAL

    def evaluate(self, resource: ResourceChange, context: RuleContext) -> list[Finding]:
        if resource.type != "google_sql_database_instance":
            return []

        # 1. Instance Deletion or Recreation
        if resource.action in (ActionType.DELETE, ActionType.REPLACE):
            base_factors = RiskFactors(
                change_impact=5.0,
                security_exposure=1.0,
                reversibility=5.0,
                uncertainty=1.0,
            )
            resolved_factors, score = score_finding(base_factors, context.environment)
            action_label = (
                "deleted"
                if resource.action == ActionType.DELETE
                else "replaced (destroy and recreate)"
            )

            return [
                Finding(
                    rule_id=self.rule_id,
                    rule_name=self.name,
                    severity=Severity.CRITICAL,
                    resource_address=resource.address,
                    resource_type=resource.type,
                    action=resource.action,
                    what_changed=f"Cloud SQL instance '{resource.address}' is scheduled to be {action_label}.",
                    why_it_matters="Destroying or replacing a managed database causes downtime and irreversible data loss unless failover replicas exist.",
                    remediation="Verify immutable configuration parameters causing replacement, ensure automated backups are current, and confirm deletion intent.",
                    risk_factors=resolved_factors,
                    calculated_score=score,
                    details={"action": resource.action.value},
                )
            ]

        # 2. Deletion Protection Disabled
        after = resource.after or {}
        settings = after.get("settings") if isinstance(after.get("settings"), dict) else {}
        deletion_prot = after.get("deletion_protection")
        if deletion_prot is None and settings:
            deletion_prot = settings.get("deletion_protection")

        if deletion_prot is False:
            base_factors = RiskFactors(
                change_impact=3.0,
                security_exposure=1.0,
                reversibility=3.5,
                uncertainty=0.5,
            )
            resolved_factors, score = score_finding(base_factors, context.environment)

            return [
                Finding(
                    rule_id=self.rule_id,
                    rule_name=self.name,
                    severity=Severity.HIGH,
                    resource_address=resource.address,
                    resource_type=resource.type,
                    action=resource.action,
                    what_changed=f"Cloud SQL instance '{resource.address}' has deletion_protection set to false.",
                    why_it_matters="Disabling deletion protection leaves production databases vulnerable to accidental deletion via Terraform or API calls.",
                    remediation="Set deletion_protection = true to safeguard against inadvertent database destruction.",
                    risk_factors=resolved_factors,
                    calculated_score=score,
                    details={"deletion_protection": False},
                )
            ]

        return []
