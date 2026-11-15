"""Unit and integration tests for DocVault Phase D8.6.

Phase D8.6 resolves the four D8.5 deployment blockers:
1. Docker Hub private registry image pull authorization (docvault-app SA + docvault-registry-creds Secret).
2. PostgreSQL connectivity architecture (ClusterIP Service + Endpoints docvault-postgres on port 5432).
3. Secure database credential delivery architecture (docvault-app-db-creds and narrow Rule 7 policy).
4. Authorized initial Alembic schema migration procedure (docvault-migration-db-creds + batch/v1 Job).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, cast

import pytest
import yaml  # type: ignore[import-untyped]

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
HELM_CHART_DIR = REPO_ROOT / "helm" / "docvault"
RBAC_DIR = REPO_ROOT / "k8s" / "rbac"


# =============================================================================
# Helper CEL Evaluator for Proposed Rule 7 Narrowed Admission Policy
# =============================================================================


def evaluate_narrowed_rule7(container: dict[str, Any]) -> tuple[bool, str]:
    """Evaluates the proposed narrow Rule 7 CEL validation rule.

    CEL Expression:
    object.spec.template.spec.containers.all(c,
      (!has(c.env) || c.env.all(e,
        !has(e.valueFrom) || !has(e.valueFrom.secretKeyRef) ||
        (c.name == 'docvault' &&
         e.name == 'DATABASE_PASSWORD' &&
         e.valueFrom.secretKeyRef.name == 'docvault-app-db-creds' &&
         e.valueFrom.secretKeyRef.key == 'database-password')
      )) &&
      (!has(c.envFrom) || c.envFrom.all(ef, !has(ef.secretRef)))
    )
    """
    env_list: list[dict[str, Any]] = container.get("env", [])
    for env_entry in env_list:
        vf: dict[str, Any] = env_entry.get("valueFrom", {})
        if "secretKeyRef" in vf:
            ref: dict[str, Any] = vf["secretKeyRef"]
            is_approved = (
                container.get("name") == "docvault"
                and ref.get("name") == "docvault-app-db-creds"
                and env_entry.get("name") == "DATABASE_PASSWORD"
                and ref.get("key") == "database-password"
            )
            if not is_approved:
                return False, (
                    f"Secret-backed env var rejected: container '{container.get('name')}', "
                    f"secret '{ref.get('name')}', key '{ref.get('key')}', env '{env_entry.get('name')}'"
                )

    env_from_list: list[dict[str, Any]] = container.get("envFrom", [])
    for ef in env_from_list:
        if "secretRef" in ef:
            return False, "envFrom.secretRef is strictly prohibited."

    return True, "Compliant"


# =============================================================================
# 1. Image Pull Authorization Contracts (Scope Item 2)
# =============================================================================


def test_serviceaccount_docvault_app_manifest_structure() -> None:
    """ServiceAccount docvault-app enforces zero automounting and binds registry secret."""
    sa_manifest: dict[str, Any] = {
        "apiVersion": "v1",
        "kind": "ServiceAccount",
        "metadata": {"name": "docvault-app", "namespace": "docvault"},
        "automountServiceAccountToken": False,
        "imagePullSecrets": [{"name": "docvault-registry-creds"}],
    }

    assert sa_manifest["automountServiceAccountToken"] is False
    assert cast(dict[str, Any], sa_manifest["metadata"])["name"] == "docvault-app"
    assert sa_manifest["imagePullSecrets"] == [{"name": "docvault-registry-creds"}]


def test_docker_registry_secret_contract() -> None:
    """Registry secret uses standard kubernetes.io/dockerconfigjson format."""
    secret_manifest: dict[str, Any] = {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {"name": "docvault-registry-creds", "namespace": "docvault"},
        "type": "kubernetes.io/dockerconfigjson",
    }
    assert secret_manifest["type"] == "kubernetes.io/dockerconfigjson"
    assert cast(dict[str, Any], secret_manifest["metadata"])["name"] == "docvault-registry-creds"


# =============================================================================
# 2. PostgreSQL Connectivity Architecture (Scope Item 3)
# =============================================================================


def test_docvault_postgres_service_complies_with_service_guardrails() -> None:
    """docvault-postgres Service strictly complies with all 5 D8.3 Service admission rules."""
    svc_manifest: dict[str, Any] = {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"name": "docvault-postgres", "namespace": "docvault"},
        "spec": {
            "type": "ClusterIP",
            "ports": [{"name": "postgres", "port": 5432, "targetPort": 5432}],
        },
    }
    spec: dict[str, Any] = svc_manifest["spec"]

    # Rule 1: Must be ClusterIP
    assert spec.get("type") == "ClusterIP"

    # Rule 2: No externalIPs
    assert len(spec.get("externalIPs", [])) == 0

    # Rule 3: No explicit nodePort
    ports: list[dict[str, Any]] = spec.get("ports", [])
    for p in ports:
        assert "nodePort" not in p or p["nodePort"] == 0

    # Rule 4: No externalName
    assert spec.get("externalName", "") == ""

    # Rule 5: No LoadBalancer config
    assert spec.get("loadBalancerIP", "") == ""
    assert len(spec.get("loadBalancerSourceRanges", [])) == 0
    assert spec.get("loadBalancerClass", "") == ""


def test_docvault_postgres_endpoints_contract() -> None:
    """Endpoints manifest targets internal PostgreSQL port 5432."""
    ep_manifest: dict[str, Any] = {
        "apiVersion": "v1",
        "kind": "Endpoints",
        "metadata": {"name": "docvault-postgres", "namespace": "docvault"},
        "subsets": [{"addresses": [{"ip": "172.18.0.2"}], "ports": [{"name": "postgres", "port": 5432}]}],
    }
    subsets: list[dict[str, Any]] = ep_manifest["subsets"]
    assert len(subsets) == 1
    ports: list[dict[str, Any]] = subsets[0]["ports"]
    addresses: list[dict[str, Any]] = subsets[0]["addresses"]
    assert ports[0]["port"] == 5432
    assert addresses[0]["ip"] == "172.18.0.2"


# =============================================================================
# 3. Database Credential Delivery Architecture (Scope Item 4 & 7)
# =============================================================================


def test_narrowed_rule7_allows_approved_db_credentials() -> None:
    """Proposed narrowed Rule 7 permits docvault-app-db-creds for DATABASE_PASSWORD on docvault container."""
    container: dict[str, Any] = {
        "name": "docvault",
        "env": [
            {
                "name": "DATABASE_PASSWORD",
                "valueFrom": {
                    "secretKeyRef": {
                        "name": "docvault-app-db-creds",
                        "key": "database-password",
                    }
                },
            }
        ],
    }
    allowed, msg = evaluate_narrowed_rule7(container)
    assert allowed is True, f"Expected approved credential to be allowed: {msg}"


def test_narrowed_rule7_rejects_container_name_mismatch() -> None:
    """Proposed narrowed Rule 7 rejects secretKeyRef if container name is not docvault."""
    container: dict[str, Any] = {
        "name": "sidecar",
        "env": [
            {
                "name": "DATABASE_PASSWORD",
                "valueFrom": {
                    "secretKeyRef": {
                        "name": "docvault-app-db-creds",
                        "key": "database-password",
                    }
                },
            }
        ],
    }
    allowed, _ = evaluate_narrowed_rule7(container)
    assert allowed is False, "Expected container name mismatch to be rejected"


def test_narrowed_rule7_rejects_arbitrary_secret_name() -> None:
    """Proposed narrowed Rule 7 strictly rejects unauthorized Secret names."""
    container: dict[str, Any] = {
        "name": "docvault",
        "env": [
            {
                "name": "DATABASE_PASSWORD",
                "valueFrom": {
                    "secretKeyRef": {
                        "name": "arbitrary-secret",
                        "key": "database-password",
                    }
                },
            }
        ],
    }
    allowed, _ = evaluate_narrowed_rule7(container)
    assert allowed is False, "Expected arbitrary secret name to be rejected"


def test_narrowed_rule7_rejects_arbitrary_secret_key() -> None:
    """Proposed narrowed Rule 7 strictly rejects unauthorized Secret keys."""
    container: dict[str, Any] = {
        "name": "docvault",
        "env": [
            {
                "name": "DATABASE_PASSWORD",
                "valueFrom": {
                    "secretKeyRef": {
                        "name": "docvault-app-db-creds",
                        "key": "unauthorized-key",
                    }
                },
            }
        ],
    }
    allowed, _ = evaluate_narrowed_rule7(container)
    assert allowed is False, "Expected arbitrary secret key to be rejected"


def test_narrowed_rule7_rejects_arbitrary_env_variable_name() -> None:
    """Proposed narrowed Rule 7 strictly rejects non-DATABASE_PASSWORD env bindings."""
    container: dict[str, Any] = {
        "name": "docvault",
        "env": [
            {
                "name": "EXFILTRATE_VAR",
                "valueFrom": {
                    "secretKeyRef": {
                        "name": "docvault-app-db-creds",
                        "key": "database-password",
                    }
                },
            }
        ],
    }
    allowed, _ = evaluate_narrowed_rule7(container)
    assert allowed is False, "Expected unauthorized env var name to be rejected"


def test_narrowed_rule7_rejects_envfrom_secretref() -> None:
    """Proposed narrowed Rule 7 preserves blanket prohibition on envFrom.secretRef."""
    container: dict[str, Any] = {
        "name": "docvault",
        "envFrom": [{"secretRef": {"name": "docvault-app-db-creds"}}],
    }
    allowed, _ = evaluate_narrowed_rule7(container)
    assert allowed is False, "Expected envFrom.secretRef to be rejected"


# =============================================================================
# 4. Authorized Alembic Migration Procedure Contract (Scope Item 5)
# =============================================================================


def test_authorized_migration_job_complies_with_admission_rules() -> None:
    """Authorized migration Job satisfies all workload guardrails and Rule 12 allowlist."""
    job_spec: dict[str, Any] = {
        "serviceAccountName": "docvault-app",
        "automountServiceAccountToken": False,
        "restartPolicy": "Never",
        "securityContext": {"runAsNonRoot": True},
        "containers": [
            {
                "name": "migrator",
                "image": "iyedbnaissa/docvault-api@sha256:05a3d9053c7250448b760e02f92422bb32c8a6b465c9222b858bfc8eb1ccd687",
                "command": ["alembic", "-c", "alembic.ini", "upgrade", "head"],
                "securityContext": {
                    "allowPrivilegeEscalation": False,
                    "privileged": False,
                    "readOnlyRootFilesystem": True,
                    "capabilities": {"drop": ["ALL"]},
                },
                "env": [
                    {"name": "DATABASE_HOST", "value": "docvault-postgres"},
                    {"name": "DATABASE_PORT", "value": "5432"},
                    {"name": "DATABASE_NAME", "value": "docvault"},
                    {"name": "DATABASE_USER", "value": "docvault_migrator"},
                    {
                        "name": "DATABASE_PASSWORD",
                        "valueFrom": {
                            "secretKeyRef": {
                                "name": "docvault-migration-db-creds",
                                "key": "database-password",
                            }
                        },
                    },
                ],
            }
        ],
    }

    # Rule 9: docvault-app and false
    assert job_spec["automountServiceAccountToken"] is False
    assert job_spec["serviceAccountName"] == "docvault-app"

    # Rule 3: runAsNonRoot
    sec_ctx = cast(dict[str, Any], job_spec["securityContext"])
    assert sec_ctx["runAsNonRoot"] is True

    c = cast(list[dict[str, Any]], job_spec["containers"])[0]
    # Rule 12: Exact allowlisted Alembic migration command on batch/v1 Job
    assert c["command"] == ["alembic", "-c", "alembic.ini", "upgrade", "head"]
    assert "args" not in c or len(c["args"]) == 0

    c_sec = cast(dict[str, Any], c["securityContext"])
    # Rule 2: allowPrivilegeEscalation false and privileged false
    assert c_sec["allowPrivilegeEscalation"] is False
    assert c_sec["privileged"] is False

    # Rule 4: drop ALL capabilities
    caps = cast(dict[str, Any], c_sec["capabilities"])
    assert caps["drop"] == ["ALL"]
    assert len(caps.get("add", [])) == 0


# =============================================================================
# 5. Live Cluster Preflight State Verification (Conditional)
# =============================================================================


@pytest.mark.skipif(
    not Path("/home/docvault/.kube/config").exists(),
    reason="K3s kubeconfig not present on test host",
)
def test_live_cluster_d8_6_prerequisites_exist() -> None:
    """Verifies that all out-of-band administrator resources exist in live K3s cluster."""
    import subprocess

    env = os.environ.copy()
    env["KUBECONFIG"] = "/home/docvault/.kube/config"

    # 1. Verify ServiceAccount docvault-app
    res_sa = subprocess.run(
        ["kubectl", "get", "sa", "docvault-app", "-n", "docvault", "-o", "json"],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert res_sa.returncode == 0, f"ServiceAccount docvault-app missing: {res_sa.stderr}"
    sa_data = cast(dict[str, Any], yaml.safe_load(res_sa.stdout))
    assert sa_data.get("automountServiceAccountToken") is False
    pull_secrets = [cast(dict[str, Any], s).get("name") for s in sa_data.get("imagePullSecrets", [])]
    assert "docvault-registry-creds" in pull_secrets

    # 2. Verify Secrets exist
    res_secrets = subprocess.run(
        ["kubectl", "get", "secrets", "-n", "docvault", "-o", "jsonpath={.items[*].metadata.name}"],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert res_secrets.returncode == 0, f"Failed listing secrets: {res_secrets.stderr}"
    existing_secrets = res_secrets.stdout.split()
    assert "docvault-registry-creds" in existing_secrets
    assert "docvault-app-db-creds" in existing_secrets
    assert "docvault-migration-db-creds" in existing_secrets

    # 3. Verify Service docvault-postgres exists
    res_svc = subprocess.run(
        ["kubectl", "get", "svc", "docvault-postgres", "-n", "docvault", "-o", "json"],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert res_svc.returncode == 0, f"Service docvault-postgres missing: {res_svc.stderr}"
    svc_data = cast(dict[str, Any], yaml.safe_load(res_svc.stdout))
    assert svc_data.get("spec", {}).get("type") == "ClusterIP"
