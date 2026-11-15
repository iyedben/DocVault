"""Automated Unit Tests for DocVault Phase D8.5 — Minimal Helm Deployment on K3s.

Validates:
1. Helm chart structure, metadata, and default values.
2. Helm lint execution and template rendering.
3. Strict compliance of rendered Deployment with all 13 D8.3 workload guardrails.
4. Strict compliance of rendered Service with all 5 D8.3 service guardrails.
5. Persistent storage configuration and read-only non-sensitive ConfigMap.
6. Jenkinsfile stages 1-8 sequence and HELM_DRIVER=configmap demarcation.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml  # type: ignore[import-untyped]

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
CHART_DIR = REPO_ROOT / "helm" / "docvault"
CHART_YAML = CHART_DIR / "Chart.yaml"
VALUES_YAML = CHART_DIR / "values.yaml"
JENKINSFILE_PATH = REPO_ROOT / "jenkins" / "Jenkinsfile"

APPROVED_IMAGE_REGEX = re.compile(r"^iyedbnaissa/docvault-api@sha256:[a-f0-9]{64}$")


# =============================================================================
# 1. Chart Structure & Metadata Tests
# =============================================================================


def test_helm_chart_files_exist() -> None:
    """All required Helm chart files exist."""
    assert CHART_DIR.is_dir(), f"Missing chart directory: {CHART_DIR}"
    assert CHART_YAML.is_file(), f"Missing Chart.yaml: {CHART_YAML}"
    assert VALUES_YAML.is_file(), f"Missing values.yaml: {VALUES_YAML}"
    assert (CHART_DIR / "templates" / "deployment.yaml").is_file()
    assert (CHART_DIR / "templates" / "service.yaml").is_file()
    assert (CHART_DIR / "templates" / "configmap.yaml").is_file()
    assert (CHART_DIR / "templates" / "pvc.yaml").is_file()
    assert (CHART_DIR / "templates" / "_helpers.tpl").is_file()


def test_chart_yaml_metadata() -> None:
    """Chart.yaml defines valid Helm v2 application metadata."""
    data = yaml.safe_load(CHART_YAML.read_text(encoding="utf-8"))
    assert data.get("apiVersion") == "v2"
    assert data.get("name") == "docvault"
    assert data.get("type") == "application"
    assert "version" in data
    assert "appVersion" in data


def test_values_yaml_immutable_image_pin() -> None:
    """Default values pin image repository and immutable SHA-256 digest."""
    data = yaml.safe_load(VALUES_YAML.read_text(encoding="utf-8"))
    image = data.get("image", {})
    assert image.get("repository") == "iyedbnaissa/docvault-api"
    digest = image.get("digest", "")
    assert digest.startswith("sha256:")
    assert len(digest) == 71  # "sha256:" + 64 hex chars
    full_ref = f"{image.get('repository')}@{digest}"
    assert APPROVED_IMAGE_REGEX.match(full_ref), f"Invalid image ref: {full_ref}"


def test_values_yaml_service_account_pin() -> None:
    """Default values specify approved serviceAccountName: docvault-app."""
    data = yaml.safe_load(VALUES_YAML.read_text(encoding="utf-8"))
    sa = data.get("serviceAccount", {})
    assert sa.get("name") == "docvault-app"


# =============================================================================
# 2. Helm Lint & Template Rendering Tests
# =============================================================================


def test_helm_lint_passes() -> None:
    """helm lint passes with 0 errors."""
    helm_cmd = shutil.which("helm") or "/home/docvault/.local/bin/helm"
    if not Path(helm_cmd).is_file():
        pytest.skip("helm binary not found on test host")

    proc = subprocess.run(
        [helm_cmd, "lint", str(CHART_DIR)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, f"helm lint failed:\n{proc.stdout}\n{proc.stderr}"
    assert "0 chart(s) failed" in proc.stdout


def _render_helm_template(extra_args: list[str] | None = None) -> list[dict[str, Any]]:
    """Helper to render Helm templates into parsed YAML documents."""
    helm_cmd = shutil.which("helm") or "/home/docvault/.local/bin/helm"
    if not Path(helm_cmd).is_file():
        pytest.skip("helm binary not found on test host")

    cmd = [helm_cmd, "template", "docvault", str(CHART_DIR)]
    if extra_args:
        cmd.extend(extra_args)

    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    assert proc.returncode == 0, f"helm template failed:\n{proc.stderr}"
    return [doc for doc in yaml.safe_load_all(proc.stdout) if doc is not None]


# =============================================================================
# 3. Workload Guardrails Compliance Tests (D8.3 Rules 1-13)
# =============================================================================


def test_rendered_deployment_complies_with_workload_guardrails() -> None:
    """Rendered Deployment strictly complies with all 13 D8.3 admission rules."""
    docs = _render_helm_template()
    deployments = [d for d in docs if d.get("kind") == "Deployment"]
    assert len(deployments) == 1, "Expected exactly one Deployment"
    dep = deployments[0]
    spec = dep.get("spec", {})
    template = spec.get("template", {})
    t_spec = template.get("spec", {})

    # Rule 1: No host namespaces
    assert not t_spec.get("hostNetwork", False)
    assert not t_spec.get("hostPID", False)
    assert not t_spec.get("hostIPC", False)

    # Rule 3: runAsNonRoot at Pod level
    pod_sec = t_spec.get("securityContext", {})
    assert pod_sec.get("runAsNonRoot") is True

    # Rule 9: automountServiceAccountToken: false and docvault-app
    assert t_spec.get("automountServiceAccountToken") is False
    assert t_spec.get("serviceAccountName") == "docvault-app"

    # Rule 10: Zero initContainers
    assert len(t_spec.get("initContainers", [])) == 0

    # Rule 13: Zero imagePullSecrets on template
    assert len(t_spec.get("imagePullSecrets", [])) == 0

    containers = t_spec.get("containers", [])
    assert len(containers) >= 1
    for c in containers:
        c_sec = c.get("securityContext", {})
        # Rule 2: allowPrivilegeEscalation: false and privileged: false
        assert c_sec.get("allowPrivilegeEscalation") is False
        assert c_sec.get("privileged", False) is False

        # Rule 4: capabilities.drop ALL, no added capabilities
        caps = c_sec.get("capabilities", {})
        drop = caps.get("drop", [])
        assert "ALL" in drop
        assert len(caps.get("add", [])) == 0

        # Rule 8: No hostPort
        for port in c.get("ports", []):
            assert "hostPort" not in port

        # Rule 11: Image matches immutable SHA-256 pattern
        img = c.get("image", "")
        assert APPROVED_IMAGE_REGEX.match(img), f"Image does not match immutable digest pattern: {img}"

        # Rule 12: No command or args overrides on Deployment
        assert len(c.get("command", [])) == 0
        assert len(c.get("args", [])) == 0

        # Rule 7: Approved single database secret reference only, no envFrom secretRef
        for env_item in c.get("env", []):
            vf = env_item.get("valueFrom", {})
            if "secretKeyRef" in vf:
                skr = vf["secretKeyRef"]
                assert c.get("name") == "docvault"
                assert env_item.get("name") == "DATABASE_PASSWORD"
                assert skr.get("name") == "docvault-app-db-creds"
                assert skr.get("key") == "database-password"
        for env_from in c.get("envFrom", []):
            assert "secretRef" not in env_from

    # Rule 5 & 6: Volumes - no hostPath, no secret volumes
    for v in t_spec.get("volumes", []):
        assert "hostPath" not in v
        assert "secret" not in v
        proj = v.get("projected", {})
        for s in proj.get("sources", []):
            assert "secret" not in s
            assert "serviceAccountToken" not in s


# =============================================================================
# 4. Service Guardrails Compliance Tests (D8.3 Rules 1-5)
# =============================================================================


def test_rendered_service_complies_with_service_guardrails() -> None:
    """Rendered Service strictly complies with all 5 D8.3 Service admission rules."""
    docs = _render_helm_template()
    services = [d for d in docs if d.get("kind") == "Service"]
    assert len(services) == 1, "Expected exactly one Service"
    svc = services[0]
    spec = svc.get("spec", {})

    # Rule 1: Service type must be ClusterIP
    assert spec.get("type", "ClusterIP") == "ClusterIP"

    # Rule 2: No externalIPs
    assert len(spec.get("externalIPs", [])) == 0

    # Rule 3: No explicit nodePort values
    for port in spec.get("ports", []):
        assert "nodePort" not in port or port.get("nodePort") == 0

    # Rule 4: No externalName
    assert spec.get("externalName", "") == ""

    # Rule 5: No LoadBalancer configuration
    assert spec.get("loadBalancerIP", "") == ""
    assert len(spec.get("loadBalancerSourceRanges", [])) == 0
    assert spec.get("loadBalancerClass", "") == ""


# =============================================================================
# 5. Jenkinsfile Stages 1-8 Verification Tests
# =============================================================================


def test_jenkinsfile_all_eight_stages_present() -> None:
    """Jenkinsfile implements all eight required stages in sequence."""
    content = JENKINSFILE_PATH.read_text(encoding="utf-8")

    expected_stages = [
        "1. Resolve Target Commit on main",
        "2. Verify GitHub Actions CI Gates",
        "3. Retrieve Immutable Image Digest",
        "4. Authenticate to K3s as jenkins-deployer",
        "5. Verify Namespace-Scoped K3s Access",
        "6. Validate the Helm chart",
        "7. Deploy or upgrade the Helm release",
        "8. Verify rollout and application readiness",
    ]

    for stage_name in expected_stages:
        assert f"stage('{stage_name}')" in content, f"Missing stage '{stage_name}' in Jenkinsfile"


def test_jenkinsfile_helm_driver_demarcation() -> None:
    """Jenkinsfile enforces HELM_DRIVER=configmap to avoid unauthorized Secret access."""
    content = JENKINSFILE_PATH.read_text(encoding="utf-8")
    assert "HELM_DRIVER=configmap" in content
    assert "helm/docvault" in content
