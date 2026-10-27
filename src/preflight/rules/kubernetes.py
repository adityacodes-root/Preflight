"""K8S specific detection rules"""

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

K8S_WORKLOAD_TYPES = {
    "kubernetes_deployment",
    "kubernetes_deployment_v1",
    "kubernetes_daemonset",
    "kubernetes_daemon_set",
    "kubernetes_daemon_set_v1",
    "kubernetes_stateful_set",
    "kubernetes_stateful_set_v1",
    "kubernetes_job",
    "kubernetes_job_v1",
    "kubernetes_cron_job",
    "kubernetes_cron_job_v1",
    "kubernetes_pod",
    "kubernetes_pod_v1",
    "kubernetes_replication_controller",
    "kubernetes_replication_controller_v1",
}

K8S_BINDING_TYPES = {
    "kubernetes_cluster_role_binding",
    "kubernetes_cluster_role_binding_v1",
    "kubernetes_role_binding",
    "kubernetes_role_binding_v1",
}


def _is_truthy(val: Any) -> bool:
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.strip().lower() in ("true", "1", "yes")
    return False


def _check_container_list(containers: Any) -> list[str]:
    violations: list[str] = []
    if isinstance(containers, dict):
        containers = [containers]
    if not isinstance(containers, list):
        return violations

    for c in containers:
        if not isinstance(c, dict):
            continue
        c_name = c.get("name") or "unnamed"
        sec_ctx = c.get("security_context") or c.get("securityContext")
        if isinstance(sec_ctx, list) and sec_ctx:
            sec_ctx = sec_ctx[0]
        if isinstance(sec_ctx, dict) and _is_truthy(sec_ctx.get("privileged")):
            violations.append(f"container '{c_name}' has privileged=true")

    return violations


def _find_k8s_workload_violations(data: Any) -> list[str]:
    violations: list[str] = []

    def _traverse(node: Any) -> None:
        if isinstance(node, dict):
            if _is_truthy(node.get("host_network")) or _is_truthy(node.get("hostNetwork")):
                violations.append("hostNetwork is enabled")
            if _is_truthy(node.get("host_pid")) or _is_truthy(node.get("hostPID")):
                violations.append("hostPID is enabled")
            if _is_truthy(node.get("host_ipc")) or _is_truthy(node.get("hostIPC")):
                violations.append("hostIPC is enabled")

            for key in ("container", "containers", "init_container", "init_containers"):
                if key in node:
                    violations.extend(_check_container_list(node[key]))

            for v in node.values():
                if isinstance(v, (dict, list)):
                    _traverse(v)
        elif isinstance(node, list):
            for item in node:
                if isinstance(item, (dict, list)):
                    _traverse(item)

    _traverse(data)

    seen: set[str] = set()
    deduped: list[str] = []
    for v in violations:
        if v not in seen:
            seen.add(v)
            deduped.append(v)
    return deduped


def _check_helm_release(after: dict[str, Any]) -> list[str]:
    violations: list[str] = []
    set_blocks = after.get("set") or []
    if isinstance(set_blocks, list):
        for item in set_blocks:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name", "")).lower()
            val = item.get("value")
            if not _is_truthy(val):
                continue
            if "privileged" in name:
                violations.append(f"helm value '{item.get('name')}' enables privileged mode")
            elif "hostnetwork" in name:
                violations.append(f"helm value '{item.get('name')}' enables hostNetwork")

    values_raw = after.get("values")
    if isinstance(values_raw, list):
        for raw in values_raw:
            if not isinstance(raw, str):
                continue
            raw_lower = raw.lower()
            if "privileged: true" in raw_lower:
                violations.append("helm values contains privileged: true")
            if "hostnetwork: true" in raw_lower:
                violations.append("helm values contains hostNetwork: true")

    return violations


class KubernetesWorkloadSecurityRule(Rule):
    rule_id = "K8S-SEC-001"
    name = "Kubernetes Workload Privileged or Host Access"
    description = "Detects Kubernetes pods and workloads running in privileged mode or with host network/PID/IPC namespaces."
    default_severity = Severity.HIGH

    def evaluate(self, resource: ResourceChange, context: RuleContext) -> list[Finding]:
        if resource.action == ActionType.DELETE or not resource.after:
            return []

        violations: list[str] = []

        if resource.type in K8S_WORKLOAD_TYPES or resource.type.startswith("kubernetes_"):
            violations.extend(_find_k8s_workload_violations(resource.after))
        elif resource.type == "helm_release":
            violations.extend(_check_helm_release(resource.after))

        if not violations:
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
                    f"Kubernetes workload '{resource.address}' enables privileged or host access: "
                    f"{'; '.join(violations)}."
                ),
                why_it_matters=(
                    "Privileged containers and host namespace sharing compromise node boundary isolation, "
                    "enabling container breakout, host filesystem tampering, and cluster-wide node takeover."
                ),
                remediation=(
                    "Disable privileged container mode (privileged = false) and avoid hostNetwork, hostPID, "
                    "or hostIPC unless strictly required by node-level daemon plugins."
                ),
                risk_factors=resolved_factors,
                calculated_score=score,
                details={"violations": violations},
            )
        ]


class KubernetesClusterAdminBindingRule(Rule):
    rule_id = "K8S-RBAC-001"
    name = "Kubernetes ClusterRoleBinding to cluster-admin"
    description = (
        "Detects RoleBindings and ClusterRoleBindings granting superuser cluster-admin privileges."
    )
    default_severity = Severity.CRITICAL

    def evaluate(self, resource: ResourceChange, context: RuleContext) -> list[Finding]:
        if resource.action == ActionType.DELETE or not resource.after:
            return []

        if resource.type not in K8S_BINDING_TYPES:
            return []

        role_ref = resource.after.get("role_ref")
        if isinstance(role_ref, list) and role_ref:
            role_ref = role_ref[0]

        if not isinstance(role_ref, dict):
            return []

        role_name = str(role_ref.get("name", "")).strip()
        if role_name.lower() != "cluster-admin":
            return []

        subjects = resource.after.get("subject") or resource.after.get("subjects") or []
        if isinstance(subjects, dict):
            subjects = [subjects]
        subject_descs: list[str] = []
        if isinstance(subjects, list):
            for s in subjects:
                if isinstance(s, dict):
                    s_kind = s.get("kind", "Subject")
                    s_name = s.get("name", "unnamed")
                    s_ns = s.get("namespace")
                    if s_ns:
                        subject_descs.append(f"{s_kind}:{s_ns}/{s_name}")
                    else:
                        subject_descs.append(f"{s_kind}:{s_name}")

        subjects_str = ", ".join(subject_descs) if subject_descs else "unspecified subjects"

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
                    f"RBAC binding '{resource.address}' binds subject(s) [{subjects_str}] "
                    f"to superuser role 'cluster-admin'."
                ),
                why_it_matters=(
                    "The cluster-admin role grants unconditional control over every API resource across all "
                    "namespaces in the cluster. Misconfigurations allow lateral movement and full cluster compromise."
                ),
                remediation=(
                    "Define least-privilege Roles or ClusterRoles granting only the specific API groups, "
                    "resources, and verbs needed by the workload or user."
                ),
                risk_factors=resolved_factors,
                calculated_score=score,
                details={"role": role_name, "subjects": subject_descs},
            )
        ]
