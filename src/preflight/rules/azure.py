"""Azure-specific rules"""

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

PUBLIC_SOURCES = {"*", "0.0.0.0/0", "::/0", "internet"}
ADMIN_PORTS = {22, 3389}

AZURE_DATABASE_TYPES = {
    "azurerm_mssql_database",
    "azurerm_mssql_server",
    "azurerm_cosmosdb_account",
    "azurerm_postgresql_flexible_server",
    "azurerm_postgresql_server",
    "azurerm_mysql_flexible_server",
    "azurerm_mysql_server",
    "azurerm_mariadb_server",
    "azurerm_redis_cache",
}


def _port_spec_matches_admin(port_spec: Any) -> tuple[bool, str]:
    if port_spec is None:
        return False, ""
    spec_str = str(port_spec).strip()
    if spec_str == "*":
        return True, "all ports (*)"
    if "-" in spec_str:
        parts = spec_str.split("-", 1)
        try:
            low, high = int(parts[0]), int(parts[1])
            found: list[str] = []
            if low <= 22 <= high:
                found.append("SSH:22")
            if low <= 3389 <= high:
                found.append("RDP:3389")
            if found:
                return True, ", ".join(found)
        except ValueError:
            pass
    else:
        try:
            val = int(spec_str)
            if val == 22:
                return True, "SSH:22"
            if val == 3389:
                return True, "RDP:3389"
        except ValueError:
            pass
    return False, ""


def _check_azure_nsg_rule(rule_data: dict[str, Any]) -> tuple[bool, str, list[str]]:
    direction = str(rule_data.get("direction", "")).lower()
    access = str(rule_data.get("access", "")).lower()
    if direction != "inbound" or access != "allow":
        return False, "", []

    sources: list[str] = []
    src = rule_data.get("source_address_prefix")
    if src:
        sources.append(str(src))
    src_list = rule_data.get("source_address_prefixes")
    if isinstance(src_list, list):
        sources.extend(str(s) for s in src_list)

    matched_sources = [s for s in sources if s.strip().lower() in PUBLIC_SOURCES]
    if not matched_sources:
        return False, "", []

    ports: list[Any] = []
    port = rule_data.get("destination_port_range")
    if port is not None:
        ports.append(port)
    port_list = rule_data.get("destination_port_ranges")
    if isinstance(port_list, list):
        ports.extend(port_list)

    for p in ports:
        matches, desc = _port_spec_matches_admin(p)
        if matches:
            return True, desc, matched_sources

    return False, "", []


class AzureNsgPublicAdminIngressRule(Rule):
    rule_id = "AZR-NET-001"
    name = "Azure NSG Public Administrative Ingress"
    description = "Detects NSG rules allowing Internet access to administrative ports (22, 3389) or wildcard ports."
    default_severity = Severity.CRITICAL

    def evaluate(self, resource: ResourceChange, context: RuleContext) -> list[Finding]:
        if resource.action == ActionType.DELETE or not resource.after:
            return []

        findings: list[Finding] = []

        if resource.type == "azurerm_network_security_rule":
            matches, port_desc, sources = _check_azure_nsg_rule(resource.after)
            if matches:
                findings.append(self._build_finding(resource, context, port_desc, sources))

        elif resource.type == "azurerm_network_security_group":
            rules = resource.after.get("security_rule", [])
            if isinstance(rules, list):
                for rule in rules:
                    if isinstance(rule, dict):
                        matches, port_desc, sources = _check_azure_nsg_rule(rule)
                        if matches:
                            findings.append(
                                self._build_finding(resource, context, port_desc, sources)
                            )

        return findings

    def _build_finding(
        self,
        resource: ResourceChange,
        context: RuleContext,
        port_desc: str,
        sources: list[str],
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
            what_changed=f"NSG rule on '{resource.address}' allows inbound {port_desc} from public source ({', '.join(sources)}).",
            why_it_matters="Exposing SSH or RDP to the public internet enables brute force credential attacks and automated compromise.",
            remediation="Restrict NSG source prefixes to corporate VPNs, Azure Bastion, or private virtual network IP ranges.",
            risk_factors=resolved_factors,
            calculated_score=score,
            details={"sources": sources, "ports": port_desc},
        )


class AzureStoragePublicAccessRule(Rule):
    rule_id = "AZR-STG-001"
    name = "Azure Storage Account Public Access"
    description = (
        "Detects storage accounts with public network access or nested blob public access enabled."
    )
    default_severity = Severity.HIGH

    def evaluate(self, resource: ResourceChange, context: RuleContext) -> list[Finding]:
        if resource.type != "azurerm_storage_account" or resource.action == ActionType.DELETE:
            return []

        after = resource.after or {}
        reasons: list[str] = []

        if after.get("allow_nested_items_to_be_public") is True:
            reasons.append("allow_nested_items_to_be_public is enabled")
        if after.get("allow_blob_public_access") is True:
            reasons.append("allow_blob_public_access is enabled")

        network_rules = after.get("network_rules")
        if isinstance(network_rules, dict):
            if str(network_rules.get("default_action", "")).lower() == "allow":
                ip_rules = network_rules.get("ip_rules") or []
                subnet_ids = network_rules.get("virtual_network_subnet_ids") or []
                if not ip_rules and not subnet_ids:
                    reasons.append(
                        "network_rules default_action is Allow without network restrictions"
                    )

        if not reasons:
            return []

        base_factors = RiskFactors(
            change_impact=3.5,
            security_exposure=4.5,
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
                what_changed=f"Storage account '{resource.address}' enables public access: {'; '.join(reasons)}.",
                why_it_matters="Public access on storage accounts risks accidental data leaks and sensitive blob exposure.",
                remediation="Set allow_nested_items_to_be_public to false and restrict network_rules default_action to Deny.",
                risk_factors=resolved_factors,
                calculated_score=score,
                details={"reasons": reasons},
            )
        ]


class AzureKeyVaultPurgeProtectionRule(Rule):
    rule_id = "AZR-KV-001"
    name = "Azure Key Vault Purge Protection Disabled"
    description = (
        "Detects Key Vaults created or updated without purge protection or soft delete enabled."
    )
    default_severity = Severity.HIGH

    def evaluate(self, resource: ResourceChange, context: RuleContext) -> list[Finding]:
        if resource.type != "azurerm_key_vault" or resource.action == ActionType.DELETE:
            return []

        after = resource.after or {}
        purge_enabled = after.get("purge_protection_enabled")
        soft_delete_days = after.get("soft_delete_retention_days")

        disabled_reasons: list[str] = []
        if purge_enabled is False:
            disabled_reasons.append("purge_protection_enabled is false")
        if soft_delete_days is not None and soft_delete_days < 7:
            disabled_reasons.append(
                f"soft_delete_retention_days is {soft_delete_days} (less than 7)"
            )

        if not disabled_reasons:
            return []

        base_factors = RiskFactors(
            change_impact=4.0,
            security_exposure=3.5,
            reversibility=4.5,
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
                what_changed=f"Key Vault '{resource.address}' lacks protection: {'; '.join(disabled_reasons)}.",
                why_it_matters="Without purge protection, secrets, keys, and certificates can be permanently purged immediately without recovery.",
                remediation="Enable purge_protection_enabled = true and configure adequate soft delete retention.",
                risk_factors=resolved_factors,
                calculated_score=score,
                details={"reasons": disabled_reasons},
            )
        ]


class AzureDatabaseDeletionReplacementRule(Rule):
    rule_id = "AZR-DB-001"
    name = "Azure Database Deletion or Replacement"
    description = (
        "Detects deletion or forced replacement of stateful Azure database and cache services."
    )
    default_severity = Severity.CRITICAL

    def evaluate(self, resource: ResourceChange, context: RuleContext) -> list[Finding]:
        if resource.type not in AZURE_DATABASE_TYPES:
            return []

        if resource.action not in (ActionType.DELETE, ActionType.REPLACE):
            return []

        base_factors = RiskFactors(
            change_impact=5.0,
            security_exposure=1.0,
            reversibility=5.0,
            uncertainty=1.0,
        )
        resolved_factors, score = score_finding(base_factors, context.environment)

        action_label = (
            "deleted" if resource.action == ActionType.DELETE else "replaced (destroy and recreate)"
        )
        return [
            Finding(
                rule_id=self.rule_id,
                rule_name=self.name,
                severity=self.default_severity,
                resource_address=resource.address,
                resource_type=resource.type,
                action=resource.action,
                what_changed=f"Azure database resource '{resource.address}' ({resource.type}) is scheduled to be {action_label}.",
                why_it_matters="Deleting or replacing databases risks data loss and extended downtime unless failover replicas exist.",
                remediation="Review immutable attribute modifications causing recreation, ensure recent backups exist, and verify deletion intentions.",
                risk_factors=resolved_factors,
                calculated_score=score,
                details={"resource_type": resource.type, "action": resource.action.value},
            )
        ]
