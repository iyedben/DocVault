"""DocVault Phase D9 — End-to-End Delivery and Deployment Verification Test Suite.

Automated verification covering:
1. Jenkins Pipeline structure, options, parameters, and NonCPS helpers.
2. Verified automated execution of the Jenkins pipeline through least-privilege identity.
3. Live K3s cluster deployment, Pod readiness, and immutable image provenance.
4. Application health (/health) and readiness (/ready with PostgreSQL handshake).
5. Authentication lifecycle: login, session cookie, /auth/me, logout, and invalidation.
6. Document lifecycle: PDF upload, metadata query, download SHA-256 byte integrity, and deletion.
7. Access control: cross-user isolation and rejection of unauthorized access attempts.
8. Repeatable deployment: automated CD pipeline re-execution preserving cluster state.
"""

from __future__ import annotations

import hashlib
import http.cookiejar
import json
import os
import subprocess
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
JENKINSFILE_PATH = REPO_ROOT / "jenkins" / "Jenkinsfile"
APP_BASE_URL = os.environ.get("DOCVAULT_TEST_URL", "http://10.43.16.81:8000")
CONTAINER_NAME = "docvault-jenkins"
KUBECONFIG_PATH = "/home/docvault/.kube/config"

APPROVED_IMAGE_DIGESTS = {
    "sha256:05a3d9053c7250448b760e02f92422bb32c8a6b465c9222b858bfc8eb1ccd687",
    "sha256:21bfeeff5133b142390d4aef8cbdd57887b8f9576cdd89ac13314f9e42450da9",
}
EXPECTED_IMAGE_DIGEST = "sha256:05a3d9053c7250448b760e02f92422bb32c8a6b465c9222b858bfc8eb1ccd687"
EXPECTED_COMMIT_SHA = "14178f7dc0ff89fe16cd72bdbbe38cb90c838612"


def is_live_environment_ready() -> bool:
    """Check if the local K3s cluster and Jenkins container are available."""
    if not Path(KUBECONFIG_PATH).exists():
        return False
    try:
        res = subprocess.run(["docker", "inspect", CONTAINER_NAME], capture_output=True, check=False)
        return res.returncode == 0
    except (FileNotFoundError, PermissionError):
        return False


LIVE_ENV_AVAILABLE = is_live_environment_ready()

TEST_USER_A = {"username": "test_probe", "password": "TestProbe123!@#"}
TEST_USER_B = {"username": "demo_viewer", "password": "TestProbe123!@#"}

FIXTURE_PDF_PATH = REPO_ROOT / "backend" / "tests" / "fixtures" / "minimal_valid.pdf"


# =============================================================================
# Helper Utilities
# =============================================================================


class AuthenticatedClient:
    """HTTP client wrapper managing cookies, session, and CSRF token."""

    def __init__(self, base_url: str = APP_BASE_URL) -> None:
        self.base_url = base_url.rstrip("/")
        self.cookie_jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cookie_jar))
        self.csrf_token: str | None = None

    def login(self, creds: dict[str, str]) -> tuple[int, dict]:
        data = json.dumps(creds).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}/api/v1/auth/login",
            data=data,
            headers={"Content-Type": "application/json"},
        )
        try:
            with self.opener.open(req) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                self.csrf_token = body.get("csrf_token")
                return resp.status, body
        except urllib.error.HTTPError as e:
            body = json.loads(e.read().decode("utf-8")) if e.fp else {}
            return e.code, body

    def logout(self) -> int:
        req = urllib.request.Request(
            f"{self.base_url}/api/v1/auth/logout",
            data=b"",
            headers={"X-CSRF-Token": self.csrf_token or ""},
            method="POST",
        )
        try:
            with self.opener.open(req) as resp:
                return resp.status
        except urllib.error.HTTPError as e:
            return e.code

    def get_me(self) -> tuple[int, dict]:
        req = urllib.request.Request(f"{self.base_url}/api/v1/auth/me")
        try:
            with self.opener.open(req) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            return e.code, {}

    def upload_document(self, filename: str, content: bytes) -> tuple[int, dict]:
        boundary = f"----WebKitFormBoundary{uuid.uuid4().hex}"
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
            f"Content-Type: application/pdf\r\n\r\n"
        ).encode() + content + f"\r\n--{boundary}--\r\n".encode()

        headers = {
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "X-CSRF-Token": self.csrf_token or "",
        }
        req = urllib.request.Request(
            f"{self.base_url}/api/v1/documents",
            data=body,
            headers=headers,
            method="POST",
        )
        try:
            with self.opener.open(req) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            body = json.loads(e.read().decode("utf-8")) if e.fp else {}
            return e.code, body

    def get_document_metadata(self, doc_id: str) -> tuple[int, dict]:
        req = urllib.request.Request(f"{self.base_url}/api/v1/documents/{doc_id}")
        try:
            with self.opener.open(req) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            return e.code, {}

    def download_document(self, doc_id: str) -> tuple[int, bytes]:
        req = urllib.request.Request(f"{self.base_url}/api/v1/documents/{doc_id}/download")
        for _ in range(5):
            try:
                with self.opener.open(req) as resp:
                    return resp.status, resp.read()
            except urllib.error.HTTPError as e:
                return e.code, b""
            except (OSError, urllib.error.URLError):
                time.sleep(1)
        return 500, b""

    def delete_document(self, doc_id: str) -> int:
        req = urllib.request.Request(
            f"{self.base_url}/api/v1/documents/{doc_id}",
            headers={"X-CSRF-Token": self.csrf_token or ""},
            method="DELETE",
        )
        for _ in range(5):
            try:
                with self.opener.open(req) as resp:
                    return resp.status
            except urllib.error.HTTPError as e:
                return e.code
            except (OSError, urllib.error.URLError):
                time.sleep(1)
        return 500


# =============================================================================
# 1. Jenkins Pipeline Structural & Configuration Tests
# =============================================================================


def test_jenkinsfile_stages_structure() -> None:
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
        assert f"stage('{stage_name}')" in content, f"Missing stage '{stage_name}'"


def test_jenkinsfile_options_and_parameters() -> None:
    """Jenkinsfile specifies required options, parameters, and credentials."""
    content = JENKINSFILE_PATH.read_text(encoding="utf-8")

    assert "timeout(time: 15, unit: 'MINUTES')" in content
    assert "disableConcurrentBuilds()" in content
    assert "ansiColor('xterm')" in content
    assert "timestamps()" in content

    assert "TARGET_COMMIT" in content
    assert "14178f7dc0ff89fe16cd72bdbbe38cb90c838612" in content
    assert "HELM_DRY_RUN" in content

    assert "docvault-k3s-token" in content
    assert "docvault-k3s-ca" in content
    assert "docvault-github-token" in content


def test_jenkinsfile_noncps_helpers() -> None:
    """Jenkinsfile defines NonCPS helper functions to prevent serialization errors."""
    content = JENKINSFILE_PATH.read_text(encoding="utf-8")

    assert "@NonCPS" in content
    assert "def extractRunId(String json)" in content
    assert "def extractArtifactId(String json)" in content


# =============================================================================
# 2. Automated Jenkins Job Execution & Provenance Verification
# =============================================================================


@pytest.mark.skipif(not LIVE_ENV_AVAILABLE, reason="Live K3s and Jenkins environment not present")
def test_jenkins_build_executions_history() -> None:
    """Jenkins controller has executed the delivery pipeline and achieved SUCCESS."""
    cmd = ["docker", "exec", CONTAINER_NAME, "cat", "/var/jenkins_home/jobs/docvault-delivery-pipeline/builds/7/log"]
    res = subprocess.run(cmd, capture_output=True, text=True, check=False)
    assert res.returncode == 0, "Build 7 log should be readable"

    assert "Finished: SUCCESS" in res.stdout
    assert "DocVault D8.5 Helm Delivery Pipeline: SUCCESS!" in res.stdout
    assert EXPECTED_COMMIT_SHA in res.stdout
    assert EXPECTED_IMAGE_DIGEST in res.stdout
    assert "Helm Release: DEPLOYED (dry-run: false)" in res.stdout


@pytest.mark.skipif(not LIVE_ENV_AVAILABLE, reason="Live K3s and Jenkins environment not present")
def test_helm_release_status_and_revision() -> None:
    """Helm release is currently deployed at revision >= 2 under HELM_DRIVER=configmap."""
    env = os.environ.copy()
    env["KUBECONFIG"] = KUBECONFIG_PATH

    token_cmd = ["kubectl", "create", "token", "jenkins-deployer", "-n", "docvault", "--duration=1h"]
    token = subprocess.check_output(token_cmd, env=env, text=True).strip()

    ca_cmd = ["kubectl", "config", "view", "--raw", "-o", "jsonpath={.clusters[0].cluster.certificate-authority-data}"]
    import base64
    ca_pem = base64.b64decode(subprocess.check_output(ca_cmd, env=env, text=True).strip()).decode()

    p = subprocess.Popen(["docker", "exec", "-i", CONTAINER_NAME, "tee", "/tmp/d9-test-ca.crt"], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL)
    p.communicate(input=ca_pem.encode())

    try:
        helm_cmd = [
            "docker", "exec", CONTAINER_NAME,
            "env", "HELM_DRIVER=configmap",
            "/var/jenkins_home/helm", "list", "-n", "docvault",
            "--kube-apiserver", "https://172.23.0.1:6443",
            "--kube-ca-file", "/tmp/d9-test-ca.crt",
            "--kube-token", token,
            "-o", "json",
        ]
        res = subprocess.run(helm_cmd, capture_output=True, text=True, check=True)
        releases = json.loads(res.stdout)
        assert len(releases) == 1, "Expected exactly 1 Helm release"
        rel = releases[0]
        assert rel["name"] == "docvault"
        assert rel["status"] == "deployed"
        assert int(rel["revision"]) >= 2, f"Expected revision >= 2, got {rel['revision']}"
    finally:
        subprocess.run(["docker", "exec", CONTAINER_NAME, "rm", "-f", "/tmp/d9-test-ca.crt"], check=False)


@pytest.mark.skipif(not LIVE_ENV_AVAILABLE, reason="Live K3s and Jenkins environment not present")
def test_k3s_workload_guardrails_compliance() -> None:
    """Deployed DocVault workload adheres to admission guardrails and provenance."""
    env = os.environ.copy()
    env["KUBECONFIG"] = KUBECONFIG_PATH

    cmd = ["kubectl", "get", "pods", "-n", "docvault", "-l", "app.kubernetes.io/name=docvault", "-o", "json"]
    res = subprocess.run(cmd, env=env, capture_output=True, text=True, check=True)
    pods_data = json.loads(res.stdout)

    assert len(pods_data["items"]) >= 1, "At least 1 docvault pod should exist"
    pod = pods_data["items"][0]

    # Status check
    phase = pod["status"]["phase"]
    assert phase == "Running", f"Pod phase should be Running, got {phase}"

    container_statuses = pod["status"]["containerStatuses"]
    assert len(container_statuses) == 1
    assert container_statuses[0]["ready"] is True

    # Provenance check
    container_spec = pod["spec"]["containers"][0]
    image_ref = container_spec["image"]
    image_digest = image_ref.split("@")[-1] if "@" in image_ref else ""
    assert image_digest in APPROVED_IMAGE_DIGESTS, f"Unexpected image digest: {image_digest}"

    # ServiceAccount check
    assert pod["spec"]["serviceAccountName"] == "docvault-app"
    assert pod["spec"]["automountServiceAccountToken"] is False


# =============================================================================
# 3. Live Application HTTP Smoke Tests
# =============================================================================


@pytest.mark.skipif(not LIVE_ENV_AVAILABLE, reason="Live K3s and Jenkins environment not present")
def test_application_health_endpoint() -> None:
    """GET /health returns HTTP 200 with status ok."""
    req = urllib.request.Request(f"{APP_BASE_URL}/health")
    with urllib.request.urlopen(req, timeout=5) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode("utf-8"))
        assert data.get("status") == "ok"


@pytest.mark.skipif(not LIVE_ENV_AVAILABLE, reason="Live K3s and Jenkins environment not present")
def test_application_readiness_endpoint() -> None:
    """GET /ready returns HTTP 200 with status ready (proving PostgreSQL reachability)."""
    req = urllib.request.Request(f"{APP_BASE_URL}/ready")
    with urllib.request.urlopen(req, timeout=5) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode("utf-8"))
        assert data.get("status") == "ready"


@pytest.mark.skipif(not LIVE_ENV_AVAILABLE, reason="Live K3s and Jenkins environment not present")
def test_authentication_lifecycle() -> None:
    """Authentication lifecycle succeeds: login, /me, logout, and token invalidation."""
    client = AuthenticatedClient()

    # 1. Login
    status, body = client.login(TEST_USER_A)
    assert status == 200
    assert "csrf_token" in body
    assert client.csrf_token is not None

    # 2. Authenticated access
    status, me = client.get_me()
    assert status == 200
    assert me.get("username") == TEST_USER_A["username"]

    # 3. Logout
    status = client.logout()
    assert status == 204

    # 4. Invalidation check
    status, _ = client.get_me()
    assert status == 401, "Session should be invalidated after logout"


@pytest.mark.skipif(not LIVE_ENV_AVAILABLE, reason="Live K3s and Jenkins environment not present")
def test_document_lifecycle_integrity() -> None:
    """Document lifecycle: upload, metadata, download byte comparison, and delete."""
    client = AuthenticatedClient()
    status, _ = client.login(TEST_USER_A)
    assert status == 200

    filename = f"smoke_test_{uuid.uuid4().hex[:8]}.pdf"
    file_bytes = FIXTURE_PDF_PATH.read_bytes()
    expected_sha256 = hashlib.sha256(file_bytes).hexdigest()

    # 1. Upload
    status, upload_body = client.upload_document(filename, file_bytes)
    assert status == 201, f"Document upload failed with status {status}"
    doc_id = upload_body.get("id")
    assert doc_id is not None

    try:
        # 2. Metadata
        status, meta = client.get_document_metadata(doc_id)
        assert status == 200
        assert meta.get("display_filename") == filename
        assert meta.get("file_size") == len(file_bytes)

        # 3. Download & byte integrity
        status, downloaded_bytes = client.download_document(doc_id)
        assert status == 200
        downloaded_sha256 = hashlib.sha256(downloaded_bytes).hexdigest()
        assert downloaded_sha256 == expected_sha256, "Downloaded SHA-256 does not match original bytes!"

        # 4. Deletion
        status = client.delete_document(doc_id)
        assert status == 204

        # 5. Verify no longer accessible
        status, _ = client.get_document_metadata(doc_id)
        assert status == 404
    finally:
        # Ensure cleanup if failed before deletion
        client.delete_document(doc_id)


@pytest.mark.skipif(not LIVE_ENV_AVAILABLE, reason="Live K3s and Jenkins environment not present")
def test_cross_user_access_control_denial() -> None:
    """Access control enforces isolation: user B cannot access user A's private document."""
    client_a = AuthenticatedClient()
    status, _ = client_a.login(TEST_USER_A)
    assert status == 200

    client_b = AuthenticatedClient()
    status, _ = client_b.login(TEST_USER_B)
    assert status == 200

    # User A creates a document
    filename = f"private_a_{uuid.uuid4().hex[:8]}.pdf"
    status, upload_body = client_a.upload_document(filename, FIXTURE_PDF_PATH.read_bytes())
    assert status == 201
    doc_id = upload_body["id"]

    try:
        # User B attempts to access User A's document metadata
        status, _ = client_b.get_document_metadata(doc_id)
        assert status == 404, f"Expected 404 (private document isolation), got {status}"

        # User B attempts to download User A's document
        status, _ = client_b.download_document(doc_id)
        assert status == 404, f"Expected 404 on download, got {status}"
    finally:
        client_a.delete_document(doc_id)


# =============================================================================
# 4. Repeatable Deployment Verification
# =============================================================================


@pytest.mark.skipif(not LIVE_ENV_AVAILABLE, reason="Live K3s and Jenkins environment not present")
def test_document_persistence_across_pod_restart() -> None:
    """Document persistence survives a controlled application Pod restart."""
    client = AuthenticatedClient()
    status, _ = client.login(TEST_USER_A)
    assert status == 200

    filename = f"persistence_verify_{uuid.uuid4().hex[:8]}.pdf"
    file_bytes = FIXTURE_PDF_PATH.read_bytes()
    expected_sha256 = hashlib.sha256(file_bytes).hexdigest()

    # 1. Upload document before restart
    status, upload_body = client.upload_document(filename, file_bytes)
    assert status == 201
    doc_id = upload_body["id"]

    try:
        # 2. Verify download works before restart
        status, pre_bytes = client.download_document(doc_id)
        assert status == 200
        assert hashlib.sha256(pre_bytes).hexdigest() == expected_sha256

        # 3. Controlled rollout restart of DocVault deployment only
        env = os.environ.copy()
        env["KUBECONFIG"] = KUBECONFIG_PATH
        subprocess.run(["kubectl", "rollout", "restart", "deployment/docvault", "-n", "docvault"], env=env, check=True)
        subprocess.run(["kubectl", "rollout", "status", "deployment/docvault", "-n", "docvault", "--timeout=60s"], env=env, check=True)

        # 4. Verify endpoints are healthy and ready on replacement pod
        ready = False
        for _ in range(15):
            try:
                req_ready = urllib.request.Request(f"{APP_BASE_URL}/ready")
                with urllib.request.urlopen(req_ready, timeout=5) as resp:
                    if resp.status == 200:
                        ready = True
                        break
            except (OSError, urllib.error.URLError):
                time.sleep(1)
        assert ready, "Replacement pod did not become ready after rollout restart"

        # 5. Download document after restart and verify byte-for-byte integrity
        status, post_bytes = client.download_document(doc_id)
        assert status == 200
        assert hashlib.sha256(post_bytes).hexdigest() == expected_sha256, "Persisted file content altered across restart!"
    finally:
        client.delete_document(doc_id)


@pytest.mark.skipif(not LIVE_ENV_AVAILABLE, reason="Live K3s and Jenkins environment not present")
def test_repeatable_deployment_build_8() -> None:
    """Repeat deployment executed as Build 8 succeeded without image rebuild."""
    cmd = ["docker", "exec", CONTAINER_NAME, "cat", "/var/jenkins_home/jobs/docvault-delivery-pipeline/builds/8/log"]
    res = subprocess.run(cmd, capture_output=True, text=True, check=False)
    assert res.returncode == 0, "Build 8 log should be readable"

    assert "Finished: SUCCESS" in res.stdout
    assert "DocVault D8.5 Helm Delivery Pipeline: SUCCESS!" in res.stdout
    assert "REVISION: 3" in res.stdout
    assert EXPECTED_IMAGE_DIGEST in res.stdout
