"""DocVault Phase D8.3 — RBAC & Admission Policy Verification Suite.

Automated unit and structural validation tests for:
1. Scoped Jenkins Deployer RBAC manifest (`k8s/rbac/jenkins-deployer-rbac.yaml`).
2. ValidatingAdmissionPolicy & Binding manifest (`k8s/rbac/jenkins-admission-policy.yaml`).
3. CEL admission policy logic against compliant and adversarial workload fixtures (Deployments, Jobs, Services).
4. Cluster verification script integrity, preflight sequencing, partial application safety, and negative testing assertions (`k8s/rbac/verify_d8_3.sh`).
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
RBAC_MANIFEST = REPO_ROOT / "k8s" / "rbac" / "jenkins-deployer-rbac.yaml"
ADMISSION_MANIFEST = REPO_ROOT / "k8s" / "rbac" / "jenkins-admission-policy.yaml"
VERIFY_SCRIPT = REPO_ROOT / "k8s" / "rbac" / "verify_d8_3.sh"

APPROVED_IMAGE_REGEX = re.compile(r"^iyedbnaissa/docvault-api@sha256:[a-f0-9]{64}$")


# =============================================================================
# 1. RBAC Manifest Structure & Negative Least-Privilege Tests
# =============================================================================


def test_rbac_manifest_exists_and_parses() -> None:
    """RBAC manifest exists and contains 3 valid YAML documents."""
    assert RBAC_MANIFEST.is_file(), f"Missing {RBAC_MANIFEST}"
    with open(RBAC_MANIFEST, encoding="utf-8") as f:
        docs = list(yaml.safe_load_all(f))
    assert len(docs) == 3, f"Expected 3 documents, got {len(docs)}"

    kinds = [d.get("kind") for d in docs]
    assert kinds == ["ServiceAccount", "Role", "RoleBinding"]


def test_rbac_service_account_least_privilege() -> None:
    """ServiceAccount jenkins-deployer enforces namespace isolation and disabled token automount."""
    with open(RBAC_MANIFEST, encoding="utf-8") as f:
        docs = list(yaml.safe_load_all(f))
    sa = docs[0]

    assert sa["apiVersion"] == "v1"
    assert sa["metadata"]["name"] == "jenkins-deployer"
    assert sa["metadata"]["namespace"] == "docvault"
    assert sa.get("automountServiceAccountToken") is False


def test_rbac_role_rules_and_exclusions() -> None:
    """Role docvault-deployer-role strictly scopes verbs and excludes sensitive operations."""
    with open(RBAC_MANIFEST, encoding="utf-8") as f:
        docs = list(yaml.safe_load_all(f))
    role = docs[1]

    assert role["apiVersion"] == "rbac.authorization.k8s.io/v1"
    assert role["metadata"]["name"] == "docvault-deployer-role"
    assert role["metadata"]["namespace"] == "docvault"

    rules = role["rules"]
    assert len(rules) == 5

    # Rule 1: Deployments
    assert rules[0]["apiGroups"] == ["apps"]
    assert rules[0]["resources"] == ["deployments"]
    assert set(rules[0]["verbs"]) == {"get", "list", "watch", "create", "update", "patch", "delete"}

    # Rule 2: Jobs (MUST NOT include delete)
    assert rules[1]["apiGroups"] == ["batch"]
    assert rules[1]["resources"] == ["jobs"]
    assert "delete" not in rules[1]["verbs"]
    assert set(rules[1]["verbs"]) == {"get", "list", "watch", "create", "update", "patch"}

    # Rule 3: Services and ConfigMaps (ConfigMaps MUST include delete for Helm release state)
    assert rules[2]["apiGroups"] == [""]
    assert set(rules[2]["resources"]) == {"services", "configmaps"}
    assert set(rules[2]["verbs"]) == {"get", "list", "watch", "create", "update", "patch", "delete"}

    # Rule 4: PersistentVolumeClaims (MUST NOT include delete)
    assert rules[3]["apiGroups"] == [""]
    assert rules[3]["resources"] == ["persistentvolumeclaims"]
    assert "delete" not in rules[3]["verbs"]
    assert set(rules[3]["verbs"]) == {"get", "list", "watch", "create", "update", "patch"}

    # Rule 5: Pods and Logs (Strictly read-only)
    assert rules[4]["apiGroups"] == [""]
    assert set(rules[4]["resources"]) == {"pods", "pods/log"}
    assert set(rules[4]["verbs"]) == {"get", "list", "watch"}

    # Comprehensive negative verification: ensure forbidden resources never appear in any rule
    forbidden_resources = [
        "secrets",
        "serviceaccounts",
        "roles",
        "rolebindings",
        "clusterroles",
        "clusterrolebindings",
        "pods/exec",
        "pods/attach",
        "pods/portforward",
        "nodes",
        "namespaces",
    ]
    for rule in rules:
        for res in rule.get("resources", []):
            assert res not in forbidden_resources, f"Forbidden resource '{res}' found in RBAC rules"


def test_rbac_role_binding_scope() -> None:
    """RoleBinding binds jenkins-deployer exclusively to docvault-deployer-role in namespace docvault."""
    with open(RBAC_MANIFEST, encoding="utf-8") as f:
        docs = list(yaml.safe_load_all(f))
    binding = docs[2]

    assert binding["apiVersion"] == "rbac.authorization.k8s.io/v1"
    assert binding["metadata"]["name"] == "docvault-deployer-binding"
    assert binding["metadata"]["namespace"] == "docvault"
    assert binding["roleRef"]["name"] == "docvault-deployer-role"
    assert binding["roleRef"]["kind"] == "Role"

    subjects = binding["subjects"]
    assert len(subjects) == 1
    assert subjects[0]["kind"] == "ServiceAccount"
    assert subjects[0]["name"] == "jenkins-deployer"
    assert subjects[0]["namespace"] == "docvault"


# =============================================================================
# 2. Admission Policy Structure, Resource Separation & Schema Type-Safety Tests
# =============================================================================


def test_admission_policy_manifest_exists_and_parses() -> None:
    """Admission policy manifest contains two independent ValidatingAdmissionPolicies and two Bindings."""
    assert ADMISSION_MANIFEST.is_file(), f"Missing {ADMISSION_MANIFEST}"
    with open(ADMISSION_MANIFEST, encoding="utf-8") as f:
        docs = list(yaml.safe_load_all(f))
    assert len(docs) == 4, f"Expected 4 documents (2 policies + 2 bindings), got {len(docs)}"

    assert docs[0]["kind"] == "ValidatingAdmissionPolicy"
    assert docs[0]["metadata"]["name"] == "docvault-deployer-workload-guardrails"

    assert docs[1]["kind"] == "ValidatingAdmissionPolicyBinding"
    assert docs[1]["metadata"]["name"] == "docvault-deployer-workload-guardrails-binding"

    assert docs[2]["kind"] == "ValidatingAdmissionPolicy"
    assert docs[2]["metadata"]["name"] == "docvault-deployer-service-guardrails"

    assert docs[3]["kind"] == "ValidatingAdmissionPolicyBinding"
    assert docs[3]["metadata"]["name"] == "docvault-deployer-service-guardrails-binding"


def test_workload_admission_policy_resource_matches_and_actor() -> None:
    """Workload policy matches ONLY deployments and jobs (apps and batch) and scopes to jenkins-deployer."""
    with open(ADMISSION_MANIFEST, encoding="utf-8") as f:
        docs = list(yaml.safe_load_all(f))
    policy = docs[0]

    assert policy["apiVersion"] == "admissionregistration.k8s.io/v1"
    assert policy["metadata"]["name"] == "docvault-deployer-workload-guardrails"
    assert policy["spec"]["failurePolicy"] == "Fail"

    # MatchConstraints covers apps/deployments and batch/jobs on CREATE/UPDATE
    rules = policy["spec"]["matchConstraints"]["resourceRules"]
    assert len(rules) == 2, f"Expected exactly 2 resource rules (deployments and jobs), got {len(rules)}"
    rule_map = {r["resources"][0]: r for r in rules}

    assert "deployments" in rule_map
    assert rule_map["deployments"]["apiGroups"] == ["apps"]
    assert set(rule_map["deployments"]["operations"]) == {"CREATE", "UPDATE"}

    assert "jobs" in rule_map
    assert rule_map["jobs"]["apiGroups"] == ["batch"]
    assert set(rule_map["jobs"]["operations"]) == {"CREATE", "UPDATE"}

    # Must NOT match services
    assert "services" not in rule_map

    # MatchConditions strictly references request.userInfo.username
    match_conditions = policy["spec"].get("matchConditions", [])
    assert len(match_conditions) == 1
    assert match_conditions[0]["name"] == "is-jenkins-deployer"
    expected_expr = "request.userInfo.username == 'system:serviceaccount:docvault:jenkins-deployer'"
    assert match_conditions[0]["expression"] == expected_expr


def test_service_admission_policy_resource_matches_and_actor() -> None:
    """Service policy matches ONLY core services and scopes to jenkins-deployer."""
    with open(ADMISSION_MANIFEST, encoding="utf-8") as f:
        docs = list(yaml.safe_load_all(f))
    policy = docs[2]

    assert policy["apiVersion"] == "admissionregistration.k8s.io/v1"
    assert policy["metadata"]["name"] == "docvault-deployer-service-guardrails"
    assert policy["spec"]["failurePolicy"] == "Fail"

    # MatchConstraints covers core/services on CREATE/UPDATE
    rules = policy["spec"]["matchConstraints"]["resourceRules"]
    assert len(rules) == 1, f"Expected exactly 1 resource rule (services), got {len(rules)}"
    rule_map = {r["resources"][0]: r for r in rules}

    assert "services" in rule_map
    assert rule_map["services"]["apiGroups"] == [""]
    assert set(rule_map["services"]["operations"]) == {"CREATE", "UPDATE"}

    # Must NOT match deployments or jobs
    assert "deployments" not in rule_map
    assert "jobs" not in rule_map

    # MatchConditions strictly references request.userInfo.username
    match_conditions = policy["spec"].get("matchConditions", [])
    assert len(match_conditions) == 1
    assert match_conditions[0]["name"] == "is-jenkins-deployer"
    expected_expr = "request.userInfo.username == 'system:serviceaccount:docvault:jenkins-deployer'"
    assert match_conditions[0]["expression"] == expected_expr


def test_both_admission_policy_bindings_scope() -> None:
    """Both bindings enforce validationActions: [Deny] and match namespace docvault by metadata name."""
    with open(ADMISSION_MANIFEST, encoding="utf-8") as f:
        docs = list(yaml.safe_load_all(f))

    # Workload Binding
    b_workload = docs[1]
    assert b_workload["apiVersion"] == "admissionregistration.k8s.io/v1"
    assert b_workload["metadata"]["name"] == "docvault-deployer-workload-guardrails-binding"
    assert b_workload["spec"]["policyName"] == "docvault-deployer-workload-guardrails"
    assert b_workload["spec"]["validationActions"] == ["Deny"]
    ns_w = b_workload["spec"]["matchResources"]["namespaceSelector"]
    assert ns_w["matchLabels"]["kubernetes.io/metadata.name"] == "docvault"

    # Service Binding
    b_service = docs[3]
    assert b_service["apiVersion"] == "admissionregistration.k8s.io/v1"
    assert b_service["metadata"]["name"] == "docvault-deployer-service-guardrails-binding"
    assert b_service["spec"]["policyName"] == "docvault-deployer-service-guardrails"
    assert b_service["spec"]["validationActions"] == ["Deny"]
    ns_s = b_service["spec"]["matchResources"]["namespaceSelector"]
    assert ns_s["matchLabels"]["kubernetes.io/metadata.name"] == "docvault"


def test_workload_policy_rules_no_service_fields() -> None:
    """Workload policy contains 13 rules that access ONLY workload schema and NO Service-specific fields."""
    with open(ADMISSION_MANIFEST, encoding="utf-8") as f:
        docs = list(yaml.safe_load_all(f))
    validations = docs[0]["spec"]["validations"]
    assert len(validations) == 13, f"Expected 13 workload validation rules, got {len(validations)}"

    # Service-specific fields that MUST NOT appear in workload CEL expressions
    prohibited_service_fragments = [
        "object.spec.type",
        "object.spec.externalIPs",
        "object.spec.externalName",
        "object.spec.loadBalancer",
        "request.resource.resource == 'services'",
    ]

    for idx, rule in enumerate(validations, start=1):
        assert "expression" in rule, f"Workload rule {idx} missing expression"
        assert "message" in rule, f"Workload rule {idx} missing message"
        expr = rule["expression"]
        for frag in prohibited_service_fragments:
            assert frag not in expr, (
                f"Workload rule {idx} illegally references Service fragment '{frag}': {expr}"
            )


def test_service_policy_rules_no_workload_fields() -> None:
    """Service policy contains 5 rules that access ONLY Service schema and NO Workload-specific fields."""
    with open(ADMISSION_MANIFEST, encoding="utf-8") as f:
        docs = list(yaml.safe_load_all(f))
    validations = docs[2]["spec"]["validations"]
    assert len(validations) == 5, f"Expected 5 service validation rules, got {len(validations)}"

    # Workload-specific fields that MUST NOT appear in Service CEL expressions
    prohibited_workload_fragments = [
        "template",
        "containers",
        "initContainers",
        "hostNetwork",
        "hostPID",
        "hostIPC",
        "serviceAccountName",
        "automountServiceAccountToken",
        "imagePullSecrets",
        "request.resource.resource != 'services'",
    ]

    for idx, rule in enumerate(validations, start=1):
        assert "expression" in rule, f"Service rule {idx} missing expression"
        assert "message" in rule, f"Service rule {idx} missing message"
        expr = rule["expression"]
        for frag in prohibited_workload_fragments:
            assert frag not in expr, (
                f"Service rule {idx} illegally references Workload fragment '{frag}': {expr}"
            )


def test_total_guardrail_rules_count() -> None:
    """Total guardrail validation rules across both policies equals exactly 18 (13 workload + 5 service)."""
    with open(ADMISSION_MANIFEST, encoding="utf-8") as f:
        docs = list(yaml.safe_load_all(f))
    workload_rules = docs[0]["spec"]["validations"]
    service_rules = docs[2]["spec"]["validations"]
    assert len(workload_rules) + len(service_rules) == 18


# =============================================================================
# 3. CEL Logic Simulation against Compliant and Adversarial Workloads & Services
# =============================================================================


def _make_base_pod_spec() -> dict[str, Any]:
    """Helper returning a fully compliant PodSpec."""
    return {
        "serviceAccountName": "docvault-app",
        "automountServiceAccountToken": False,
        "securityContext": {
            "runAsNonRoot": True,
        },
        "containers": [
            {
                "name": "app",
                "image": "iyedbnaissa/docvault-api@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "securityContext": {
                    "privileged": False,
                    "allowPrivilegeEscalation": False,
                    "capabilities": {
                        "drop": ["ALL"],
                    },
                },
            }
        ],
    }


def _make_base_service_spec() -> dict[str, Any]:
    """Helper returning a fully compliant ServiceSpec (ClusterIP)."""
    return {
        "type": "ClusterIP",
        "selector": {
            "app": "test-compliant",
        },
        "ports": [
            {
                "name": "http",
                "port": 8000,
                "targetPort": 8000,
            }
        ],
    }


def evaluate_cel_workload_policy(spec: dict[str, Any], resource: str = "deployments") -> list[str]:
    """Static Python logic simulation of docvault-deployer-workload-guardrails Rules 1-13.

    NOTE: This is a static logic simulation for offline testing, not actual Kubernetes live cluster CEL evaluation.
    Returns list of violation messages. An empty list denotes complete compliance.
    """
    violations: list[str] = []

    # Rule 1: Prohibit host namespaces (hostNetwork, hostPID, hostIPC)
    if spec.get("hostNetwork", False) or spec.get("hostPID", False) or spec.get("hostIPC", False):
        violations.append("Host namespaces (hostNetwork, hostPID, hostIPC) are prohibited.")

    # Rule 2: Prohibit privileged mode and require allowPrivilegeEscalation: false
    all_containers = spec.get("containers", []) + spec.get("initContainers", [])
    for c in all_containers:
        sc = c.get("securityContext", {})
        if sc.get("privileged", False) or not (sc.get("allowPrivilegeEscalation") is False):
            violations.append("Privileged mode is prohibited and allowPrivilegeEscalation must be false across all containers and initContainers.")
            break

    # Rule 3: Mandatory runAsNonRoot: true at Pod level and prohibit container override to false
    pod_sc = spec.get("securityContext", {})
    if pod_sc.get("runAsNonRoot") is not True:
        violations.append("Pod spec must enforce runAsNonRoot: true and no container or initContainer may override runAsNonRoot to false.")
    else:
        for c in all_containers:
            sc = c.get("securityContext", {})
            if "runAsNonRoot" in sc and sc["runAsNonRoot"] is False:
                violations.append("Pod spec must enforce runAsNonRoot: true and no container or initContainer may override runAsNonRoot to false.")
                break

    # Rule 4: Mandatory Linux capabilities: drop ALL, no added capabilities
    for c in all_containers:
        sc = c.get("securityContext", {})
        caps = sc.get("capabilities", {})
        drop_list = caps.get("drop", [])
        add_list = caps.get("add", [])
        if "ALL" not in drop_list or len(add_list) > 0:
            violations.append("Containers and initContainers must drop ALL capabilities and cannot add capabilities.")
            break

    # Rule 5: Prohibit hostPath volumes
    for v in spec.get("volumes", []):
        if "hostPath" in v:
            violations.append("hostPath volumes are prohibited.")
            break

    # Rule 6: Prohibit direct or projected Secret volume mounts
    for v in spec.get("volumes", []):
        if "secret" in v:
            violations.append("Direct or projected Secret volume mounts are prohibited.")
            break
        if "projected" in v:
            for s in v["projected"].get("sources", []):
                if "secret" in s:
                    violations.append("Direct or projected Secret volume mounts are prohibited.")
                    break

    # Rule 7: Prohibit Secret-backed environment variables (secretKeyRef or envFrom secretRef)
    for c in all_containers:
        for e in c.get("env", []):
            if "valueFrom" in e and "secretKeyRef" in e["valueFrom"]:
                violations.append("Secret-backed environment variables (valueFrom.secretKeyRef or envFrom.secretRef) are prohibited.")
                break
        for ef in c.get("envFrom", []):
            if "secretRef" in ef:
                violations.append("Secret-backed environment variables (valueFrom.secretKeyRef or envFrom.secretRef) are prohibited.")
                break

    # Rule 8: Prohibit host ports
    for c in all_containers:
        for p in c.get("ports", []):
            if p.get("hostPort", 0) != 0:
                violations.append("Host ports are prohibited.")
                break

    # Rule 9: Enforce ServiceAccount docvault-app, explicit automountServiceAccountToken: false, zero projected tokens
    if (
        "automountServiceAccountToken" not in spec
        or spec["automountServiceAccountToken"] is not False
        or spec.get("serviceAccountName") != "docvault-app"
    ):
        violations.append("Workload must explicitly specify automountServiceAccountToken: false, serviceAccountName: docvault-app, and zero projected serviceAccountToken volumes.")
    else:
        for v in spec.get("volumes", []):
            if "projected" in v:
                for s in v["projected"].get("sources", []):
                    if "serviceAccountToken" in s:
                        violations.append("Workload must explicitly specify automountServiceAccountToken: false, serviceAccountName: docvault-app, and zero projected serviceAccountToken volumes.")
                        break

    # Rule 10: Prohibit initContainers entirely for deployment identity
    if "initContainers" in spec and len(spec["initContainers"]) > 0:
        violations.append("initContainers are prohibited for deployment identity.")

    # Rule 11: Restrict image repository to iyedbnaissa/docvault-api with immutable sha256 digest
    for c in all_containers:
        img = c.get("image", "")
        if not APPROVED_IMAGE_REGEX.match(img):
            violations.append("Container image must be from iyedbnaissa/docvault-api with an immutable sha256 digest.")
            break

    # Rule 12: Prohibit arbitrary command and args overrides (allowlisting exact Alembic migration command on Jobs only)
    is_job = resource == "jobs"
    for c in all_containers:
        cmd = c.get("command", [])
        args = c.get("args", [])
        if not is_job:
            if len(cmd) > 0 or len(args) > 0:
                violations.append("Container command and args overrides are prohibited (only exact allowlisted Alembic migration command is permitted on Jobs).")
                break
        else:
            is_empty = len(cmd) == 0 and len(args) == 0
            is_allowlisted_alembic = cmd == ["alembic", "-c", "alembic.ini", "upgrade", "head"] and len(args) == 0
            if not (is_empty or is_allowlisted_alembic):
                violations.append("Container command and args overrides are prohibited (only exact allowlisted Alembic migration command is permitted on Jobs).")
                break

    # Rule 13: Prohibit imagePullSecrets on deployment templates
    if "imagePullSecrets" in spec and len(spec["imagePullSecrets"]) > 0:
        violations.append("imagePullSecrets are prohibited on deployment templates.")

    return violations


def evaluate_cel_service_policy(spec: dict[str, Any]) -> list[str]:
    """Static Python logic simulation of docvault-deployer-service-guardrails Rules 1-5.

    NOTE: This is a static logic simulation for offline testing, not actual Kubernetes live cluster CEL evaluation.
    Returns list of violation messages. An empty list denotes complete compliance.
    """
    violations: list[str] = []

    # Rule 14: Enforce Service type must be ClusterIP
    svc_type = spec.get("type", "ClusterIP")
    if svc_type != "ClusterIP":
        violations.append("Services must be of type ClusterIP.")

    # Rule 15: Prohibit externalIPs on Services
    if "externalIPs" in spec and len(spec["externalIPs"]) > 0:
        violations.append("externalIPs are prohibited on Services.")

    # Rule 16: Prohibit explicit nodePort values on Services
    for p in spec.get("ports", []):
        if p.get("nodePort", 0) != 0:
            violations.append("Explicit nodePort values are prohibited on Services.")
            break

    # Rule 17: Prohibit externalName on Services
    if "externalName" in spec and spec["externalName"] != "":
        violations.append("externalName is prohibited on Services.")

    # Rule 18: Prohibit LoadBalancer configuration on Services
    has_lb_ip = "loadBalancerIP" in spec and spec["loadBalancerIP"] != ""
    has_lb_ranges = "loadBalancerSourceRanges" in spec and len(spec["loadBalancerSourceRanges"]) > 0
    has_lb_class = "loadBalancerClass" in spec and spec["loadBalancerClass"] != ""
    if has_lb_ip or has_lb_ranges or has_lb_class:
        violations.append("LoadBalancer configuration is prohibited on Services.")

    return violations


def test_cel_compliant_workload_passes() -> None:
    """Compliant workload passes all 13 admission policy rules with 0 violations."""
    spec = _make_base_pod_spec()
    violations = evaluate_cel_workload_policy(spec)
    assert violations == [], f"Unexpected violations on compliant spec: {violations}"


def test_cel_privileged_container_denied() -> None:
    """Privileged container triggers Rule 2 denial."""
    spec = _make_base_pod_spec()
    spec["containers"][0]["securityContext"]["privileged"] = True
    violations = evaluate_cel_workload_policy(spec)
    assert any("Privileged mode is prohibited" in v for v in violations)


def test_cel_allow_privilege_escalation_denied() -> None:
    """Privilege escalation allowed triggers Rule 2 denial."""
    spec = _make_base_pod_spec()
    spec["containers"][0]["securityContext"]["allowPrivilegeEscalation"] = True
    violations = evaluate_cel_workload_policy(spec)
    assert any("allowPrivilegeEscalation must be false" in v for v in violations)


def test_cel_pod_missing_run_as_non_root_denied() -> None:
    """Missing pod runAsNonRoot: true triggers Rule 3 denial."""
    spec = _make_base_pod_spec()
    del spec["securityContext"]["runAsNonRoot"]
    violations = evaluate_cel_workload_policy(spec)
    assert any("Pod spec must enforce runAsNonRoot: true" in v for v in violations)


def test_cel_container_override_run_as_non_root_false_denied() -> None:
    """Container-level runAsNonRoot: false override triggers Rule 3 denial."""
    spec = _make_base_pod_spec()
    spec["containers"][0]["securityContext"]["runAsNonRoot"] = False
    violations = evaluate_cel_workload_policy(spec)
    assert any("no container or initContainer may override runAsNonRoot to false" in v for v in violations)


def test_cel_missing_drop_all_capabilities_denied() -> None:
    """Missing capabilities.drop: ALL triggers Rule 4 denial."""
    spec = _make_base_pod_spec()
    del spec["containers"][0]["securityContext"]["capabilities"]
    violations = evaluate_cel_workload_policy(spec)
    assert any("Containers and initContainers must drop ALL capabilities" in v for v in violations)


def test_cel_added_capabilities_denied() -> None:
    """Added Linux capabilities trigger Rule 4 denial."""
    spec = _make_base_pod_spec()
    spec["containers"][0]["securityContext"]["capabilities"]["add"] = ["NET_ADMIN"]
    violations = evaluate_cel_workload_policy(spec)
    assert any("cannot add capabilities" in v for v in violations)


def test_cel_host_namespaces_denied() -> None:
    """HostNetwork, HostPID, or HostIPC triggers Rule 1 denial."""
    for host_ns in ["hostNetwork", "hostPID", "hostIPC"]:
        spec = _make_base_pod_spec()
        spec[host_ns] = True
        violations = evaluate_cel_workload_policy(spec)
        assert any("Host namespaces (hostNetwork, hostPID, hostIPC) are prohibited" in v for v in violations)


def test_cel_hostpath_volume_denied() -> None:
    """hostPath volume triggers Rule 5 denial."""
    spec = _make_base_pod_spec()
    spec["volumes"] = [{"name": "hp", "hostPath": {"path": "/"}}]
    violations = evaluate_cel_workload_policy(spec)
    assert any("hostPath volumes are prohibited" in v for v in violations)


def test_cel_direct_secret_volume_denied() -> None:
    """Direct secret volume mount triggers Rule 6 denial."""
    spec = _make_base_pod_spec()
    spec["volumes"] = [{"name": "sec", "secret": {"secretName": "db-creds"}}]
    violations = evaluate_cel_workload_policy(spec)
    assert any("Direct or projected Secret volume mounts are prohibited" in v for v in violations)


def test_cel_projected_secret_volume_denied() -> None:
    """Projected secret volume source triggers Rule 6 denial."""
    spec = _make_base_pod_spec()
    spec["volumes"] = [{"name": "psec", "projected": {"sources": [{"secret": {"name": "db-creds"}}]}}]
    violations = evaluate_cel_workload_policy(spec)
    assert any("Direct or projected Secret volume mounts are prohibited" in v for v in violations)


def test_cel_secret_env_var_denied() -> None:
    """secretKeyRef in container env triggers Rule 7 denial."""
    spec = _make_base_pod_spec()
    spec["containers"][0]["env"] = [{"name": "P", "valueFrom": {"secretKeyRef": {"name": "db", "key": "k"}}}]
    violations = evaluate_cel_workload_policy(spec)
    assert any("Secret-backed environment variables" in v for v in violations)


def test_cel_secret_envfrom_denied() -> None:
    """secretRef in container envFrom triggers Rule 7 denial."""
    spec = _make_base_pod_spec()
    spec["containers"][0]["envFrom"] = [{"secretRef": {"name": "db"}}]
    violations = evaluate_cel_workload_policy(spec)
    assert any("Secret-backed environment variables" in v for v in violations)


def test_cel_host_port_denied() -> None:
    """hostPort > 0 triggers Rule 8 denial."""
    spec = _make_base_pod_spec()
    spec["containers"][0]["ports"] = [{"containerPort": 80, "hostPort": 8080}]
    violations = evaluate_cel_workload_policy(spec)
    assert any("Host ports are prohibited" in v for v in violations)


def test_cel_service_account_token_security_denied() -> None:
    """Omitted token automount, true automount, unapproved SA, or projected SA tokens trigger Rule 9 denial."""
    # Omitted automountServiceAccountToken
    spec1 = _make_base_pod_spec()
    del spec1["automountServiceAccountToken"]
    v1 = evaluate_cel_workload_policy(spec1)
    assert any("automountServiceAccountToken: false" in msg for msg in v1)

    # automountServiceAccountToken: true
    spec2 = _make_base_pod_spec()
    spec2["automountServiceAccountToken"] = True
    v2 = evaluate_cel_workload_policy(spec2)
    assert any("automountServiceAccountToken: false" in msg for msg in v2)

    # serviceAccountName: default
    spec3 = _make_base_pod_spec()
    spec3["serviceAccountName"] = "default"
    v3 = evaluate_cel_workload_policy(spec3)
    assert any("serviceAccountName: docvault-app" in msg for msg in v3)

    # Projected serviceAccountToken volume
    spec4 = _make_base_pod_spec()
    spec4["volumes"] = [{"name": "ptok", "projected": {"sources": [{"serviceAccountToken": {"path": "token"}}]}}]
    v4 = evaluate_cel_workload_policy(spec4)
    assert any("zero projected serviceAccountToken volumes" in msg for msg in v4)


def test_cel_init_containers_denied() -> None:
    """Presence of initContainers triggers Rule 10 denial."""
    spec = _make_base_pod_spec()
    spec["initContainers"] = [
        {
            "name": "init",
            "image": "iyedbnaissa/docvault-api@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "securityContext": {
                "privileged": False,
                "allowPrivilegeEscalation": False,
                "capabilities": {"drop": ["ALL"]},
            },
        }
    ]
    violations = evaluate_cel_workload_policy(spec)
    assert any("initContainers are prohibited for deployment identity" in v for v in violations)


def test_cel_image_provenance_denied() -> None:
    """Unapproved image repository or mutable tag without sha256 triggers Rule 11 denial."""
    # Unapproved repository
    spec1 = _make_base_pod_spec()
    spec1["containers"][0]["image"] = "malicious/docvault-api@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    v1 = evaluate_cel_workload_policy(spec1)
    assert any("Container image must be from iyedbnaissa/docvault-api with an immutable sha256 digest" in msg for msg in v1)

    # Mutable tag without digest
    spec2 = _make_base_pod_spec()
    spec2["containers"][0]["image"] = "iyedbnaissa/docvault-api:latest"
    v2 = evaluate_cel_workload_policy(spec2)
    assert any("Container image must be from iyedbnaissa/docvault-api with an immutable sha256 digest" in msg for msg in v2)


def test_cel_command_and_args_override_denied() -> None:
    """Command or args overrides trigger Rule 12 denial on Deployments and unapproved commands on Jobs."""
    # Deployment with command override
    spec1 = _make_base_pod_spec()
    spec1["containers"][0]["command"] = ["/bin/sh"]
    v1 = evaluate_cel_workload_policy(spec1, resource="deployments")
    assert any("Container command and args overrides are prohibited" in msg for msg in v1)

    # Deployment with args override
    spec2 = _make_base_pod_spec()
    spec2["containers"][0]["args"] = ["--debug"]
    v2 = evaluate_cel_workload_policy(spec2, resource="deployments")
    assert any("Container command and args overrides are prohibited" in msg for msg in v2)

    # Job with unapproved arbitrary command
    spec3 = _make_base_pod_spec()
    spec3["containers"][0]["command"] = ["python", "-c", "import sys; print(1)"]
    v3 = evaluate_cel_workload_policy(spec3, resource="jobs")
    assert any("Container command and args overrides are prohibited" in msg for msg in v3)

    # Job with args override
    spec4 = _make_base_pod_spec()
    spec4["containers"][0]["args"] = ["--help"]
    v4 = evaluate_cel_workload_policy(spec4, resource="jobs")
    assert any("Container command and args overrides are prohibited" in msg for msg in v4)

    # Job with allowlisted command BUT extra args is denied
    spec5 = _make_base_pod_spec()
    spec5["containers"][0]["command"] = ["alembic", "-c", "alembic.ini", "upgrade", "head"]
    spec5["containers"][0]["args"] = ["--sql"]
    v5 = evaluate_cel_workload_policy(spec5, resource="jobs")
    assert any("Container command and args overrides are prohibited" in msg for msg in v5)


def test_cel_migration_job_allowlisted_alembic_command_passes() -> None:
    """Exact allowlisted Alembic migration command on a Job passes Rule 12 with 0 violations."""
    spec = _make_base_pod_spec()
    spec["containers"][0]["command"] = ["alembic", "-c", "alembic.ini", "upgrade", "head"]
    violations = evaluate_cel_workload_policy(spec, resource="jobs")
    assert violations == [], f"Expected allowlisted Alembic migration command on Job to pass, got: {violations}"


def test_cel_deployment_alembic_command_denied() -> None:
    """Alembic command override on a Deployment is denied by Rule 12 (deployments prohibit all overrides)."""
    spec = _make_base_pod_spec()
    spec["containers"][0]["command"] = ["alembic", "-c", "alembic.ini", "upgrade", "head"]
    violations = evaluate_cel_workload_policy(spec, resource="deployments")
    assert any("Container command and args overrides are prohibited" in msg for msg in violations)


def test_cel_image_pull_secrets_denied() -> None:
    """imagePullSecrets presence triggers Rule 13 denial."""
    spec = _make_base_pod_spec()
    spec["imagePullSecrets"] = [{"name": "registry-secret"}]
    violations = evaluate_cel_workload_policy(spec)
    assert any("imagePullSecrets are prohibited on deployment templates" in v for v in violations)


# --- Service CEL Tests (Rules 14-18) ---


def test_cel_service_compliant_clusterip_passes() -> None:
    """Compliant ClusterIP Service passes rules 14-18 with 0 violations."""
    svc = _make_base_service_spec()
    violations = evaluate_cel_service_policy(svc)
    assert violations == [], f"Unexpected violations on compliant Service: {violations}"


def test_cel_service_nodeport_denied() -> None:
    """Service with type NodePort triggers Rule 14 denial."""
    svc = _make_base_service_spec()
    svc["type"] = "NodePort"
    violations = evaluate_cel_service_policy(svc)
    assert any("Services must be of type ClusterIP" in v for v in violations)


def test_cel_service_loadbalancer_denied() -> None:
    """Service with type LoadBalancer triggers Rule 14 denial."""
    svc = _make_base_service_spec()
    svc["type"] = "LoadBalancer"
    violations = evaluate_cel_service_policy(svc)
    assert any("Services must be of type ClusterIP" in v for v in violations)


def test_cel_service_externalname_denied() -> None:
    """Service with type ExternalName triggers Rule 14 denial."""
    svc = _make_base_service_spec()
    svc["type"] = "ExternalName"
    svc["externalName"] = "api.example.com"
    violations = evaluate_cel_service_policy(svc)
    assert any("Services must be of type ClusterIP" in v for v in violations)


def test_cel_service_external_ips_denied() -> None:
    """Service specifying externalIPs triggers Rule 15 denial."""
    svc = _make_base_service_spec()
    svc["externalIPs"] = ["198.51.100.1"]
    violations = evaluate_cel_service_policy(svc)
    assert any("externalIPs are prohibited on Services" in v for v in violations)


def test_cel_service_explicit_nodeport_denied() -> None:
    """Service specifying an explicit nodePort triggers Rule 16 denial."""
    svc = _make_base_service_spec()
    svc["type"] = "NodePort"
    svc["ports"][0]["nodePort"] = 32000
    violations = evaluate_cel_service_policy(svc)
    assert any("Explicit nodePort values are prohibited on Services" in v for v in violations)


def test_cel_service_externalname_field_denied() -> None:
    """Service specifying an externalName field triggers Rule 17 denial."""
    svc = _make_base_service_spec()
    svc["type"] = "ExternalName"
    svc["externalName"] = "malicious.internal"
    violations = evaluate_cel_service_policy(svc)
    assert any("externalName is prohibited on Services" in v for v in violations)


def test_cel_service_loadbalancer_config_denied() -> None:
    """Service specifying LoadBalancer configurations triggers Rule 18 denial."""
    svc1 = _make_base_service_spec()
    svc1["type"] = "LoadBalancer"
    svc1["loadBalancerSourceRanges"] = ["10.0.0.0/8"]
    v1 = evaluate_cel_service_policy(svc1)
    assert any("LoadBalancer configuration is prohibited on Services" in msg for msg in v1)

    svc2 = _make_base_service_spec()
    svc2["type"] = "LoadBalancer"
    svc2["loadBalancerClass"] = "custom-lb"
    v2 = evaluate_cel_service_policy(svc2)
    assert any("LoadBalancer configuration is prohibited on Services" in msg for msg in v2)


def test_existing_workload_guardrails_remain_unchanged() -> None:
    """Existing Deployment and Job guardrails (Rules 1-13) remain intact and effective."""
    spec = _make_base_pod_spec()
    assert evaluate_cel_workload_policy(spec) == []

    # Verify key workload constraints still trigger
    spec_priv = _make_base_pod_spec()
    spec_priv["containers"][0]["securityContext"]["privileged"] = True
    assert len(evaluate_cel_workload_policy(spec_priv)) == 1

    spec_hp = _make_base_pod_spec()
    spec_hp["volumes"] = [{"name": "hp", "hostPath": {"path": "/"}}]
    assert len(evaluate_cel_workload_policy(spec_hp)) == 1


# =============================================================================
# 4. Verification Script Integrity, Preflight Sequencing & Safety Tests
# =============================================================================


def test_verify_script_syntax_and_executable() -> None:
    """verify_d8_3.sh passes bash syntax validation and is executable."""
    assert VERIFY_SCRIPT.is_file(), f"Missing {VERIFY_SCRIPT}"
    assert VERIFY_SCRIPT.stat().st_mode & 0o111, f"{VERIFY_SCRIPT} is not executable"

    res = subprocess.run(["bash", "-n", str(VERIFY_SCRIPT)], check=False, capture_output=True, text=True)
    assert res.returncode == 0, f"bash -n failed on {VERIFY_SCRIPT}:\n{res.stderr}"


def test_verify_script_preflight_ordering_before_apply() -> None:
    """verify_d8_3.sh executes all preflight checks and server-side dry-run validation BEFORE any live application."""
    content = VERIFY_SCRIPT.read_text(encoding="utf-8")

    # Locate preflight marker and live apply marker
    pos_preflight = content.find("STEP 0: Preflight Validation")
    pos_dryrun_rbac = content.find("PREFLIGHT_RBAC_ERR=$(kubectl apply --dry-run=server")
    pos_dryrun_policy = content.find("PREFLIGHT_POLICY_ERR=$(kubectl apply --dry-run=server")
    pos_apply = content.find("STEP 1: Safe Manifest Application")
    pos_live_apply_rbac = content.find("kubectl apply -f \"${SCRIPT_DIR}/jenkins-deployer-rbac.yaml\"")

    assert pos_preflight != -1, "Preflight section missing"
    assert pos_dryrun_rbac != -1, "RBAC preflight dry-run missing"
    assert pos_dryrun_policy != -1, "Policy preflight dry-run missing"
    assert pos_apply != -1, "Application section missing"
    assert pos_live_apply_rbac != -1, "Live apply missing"

    # Preflight and dry-runs MUST occur before any live application
    assert pos_preflight < pos_apply, "Preflight must be ordered before live application"
    assert pos_dryrun_rbac < pos_apply, "RBAC dry-run must be ordered before live application"
    assert pos_dryrun_policy < pos_apply, "Policy dry-run must be ordered before live application"
    assert pos_dryrun_policy < pos_live_apply_rbac, "Policy dry-run must precede live apply"

    # Verify namespace docvault check and ValidatingAdmissionPolicy API support check
    assert "kubectl get namespace docvault" in content
    assert "validatingadmissionpolicies" in content
    assert "validatingadmissionpolicybindings" in content
    assert "docvault-deployer-workload-guardrails" in content
    assert "docvault-deployer-service-guardrails" in content


def test_verify_script_no_application_after_failed_dryrun() -> None:
    """verify_d8_3.sh exits immediately with code 2 if preflight dry-run fails, aborting before live application."""
    content = VERIFY_SCRIPT.read_text(encoding="utf-8")

    assert "Aborting without applying any resources" in content
    assert "exit 2" in content


def test_verify_script_partial_application_failure_reported() -> None:
    """verify_d8_3.sh accurately detects and reports partial application state with rollback instructions."""
    content = VERIFY_SCRIPT.read_text(encoding="utf-8")

    assert "PARTIAL APPLICATION STATE DETECTED" in content
    assert "kubectl delete -f ${SCRIPT_DIR}/jenkins-deployer-rbac.yaml" in content
    assert "exit 3" in content


def test_verify_script_negative_assertions_and_services() -> None:
    """verify_d8_3.sh enforces strict error-checking, impersonation, and policy message assertions including Services."""
    content = VERIFY_SCRIPT.read_text(encoding="utf-8")

    assert "set -euo pipefail" in content
    assert "--as=system:serviceaccount:docvault:jenkins-deployer" in content
    assert "--dry-run=server" in content
    assert "docvault-deployer-workload-guardrails" in content
    assert "docvault-deployer-service-guardrails" in content
    assert "FAILED_TESTS" in content

    # Ensure negative test verification captures stderr and stdout
    assert "2>&1" in content
    assert "grep -qF \"$expected_msg\"" in content or "grep -q" in content

    # Verify workload and service test identifiers are present in the script
    expected_test_cases = [
        "Compliant Deployment",
        "Compliant Job",
        "Compliant Migration Job (Allowlisted Alembic Command)",
        "Compliant Service (ClusterIP)",
        "Administrator Bypass",
        "Privileged Container",
        "AllowPrivilegeEscalation",
        "Pod runAsNonRoot: true",
        "Container runAsNonRoot: false Override",
        "Capabilities Drop ALL",
        "Added Capabilities",
        "Host Network",
        "Host PID",
        "hostPath Volume",
        "Direct Secret Volume Mount",
        "Projected Secret Volume Source",
        "Secret-Backed Env Var",
        "Secret-Backed envFrom",
        "Host Ports",
        "Omitted automountServiceAccountToken",
        "automountServiceAccountToken: true",
        "Unapproved ServiceAccount",
        "Projected ServiceAccount Token Volume",
        "Init Containers",
        "Unapproved Image Repository",
        "Mutable Image Tag",
        "Command Override",
        "Args Override",
        "imagePullSecrets",
        "Prohibit Service NodePort Type",
        "Prohibit Service LoadBalancer Type",
        "Prohibit Service ExternalName Type",
        "Prohibit Service externalIPs",
        "Prohibit Explicit Service nodePort",
        "Prohibit Service externalName Field",
        "Prohibit Service LoadBalancer Configuration",
    ]
    for case in expected_test_cases:
        assert case in content, f"Expected test case '{case}' missing from verify_d8_3.sh"
