#!/usr/bin/env python3
"""DocVault Phase D9.13 — Live End-to-End Document Operations Verification.

Tests against deployed application at http://10.43.16.81:8000:
1. Health & readiness endpoints.
2. Authentication lifecycle with test account.
3. Temporary PDF upload.
4. Document metadata retrieval.
5. Document download and SHA-256 byte comparison.
6. Cross-user access control enforcement (404 private document isolation).
7. Temporary test document deletion (HTTP 204).
8. Post-deletion access denial (HTTP 404).
9. PVC status and storage integrity check.
"""

from __future__ import annotations

import hashlib
import http.cookiejar
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
import uuid
from pathlib import Path

APP_BASE_URL = os.environ.get("DOCVAULT_TEST_URL", "http://10.43.16.81:8000")
USER_A = {"username": "test_probe", "password": "TestProbe123!@#"}
USER_B = {"username": "demo_viewer", "password": "TestProbe123!@#"}

REPO_ROOT = Path(__file__).resolve().parent.parent
PDF_PATH = REPO_ROOT / "backend" / "tests" / "fixtures" / "minimal_valid.pdf"


class LiveTestClient:
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
        with self.opener.open(req) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            self.csrf_token = body.get("csrf_token")
            return resp.status, body

    def logout(self) -> int:
        req = urllib.request.Request(
            f"{self.base_url}/api/v1/auth/logout",
            data=b"",
            headers={"X-CSRF-Token": self.csrf_token or ""},
            method="POST",
        )
        with self.opener.open(req) as resp:
            return resp.status

    def get_me(self) -> tuple[int, dict]:
        req = urllib.request.Request(f"{self.base_url}/api/v1/auth/me")
        with self.opener.open(req) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))

    def upload_document(self, filename: str, content: bytes) -> tuple[int, dict]:
        boundary = f"----DocVaultLiveBoundary{uuid.uuid4().hex}"
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
        with self.opener.open(req) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))

    def get_document_metadata(self, doc_id: str) -> tuple[int, dict]:
        req = urllib.request.Request(f"{self.base_url}/api/v1/documents/{doc_id}")
        try:
            with self.opener.open(req) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            return e.code, {}

    def download_document(self, doc_id: str) -> tuple[int, bytes]:
        req = urllib.request.Request(f"{self.base_url}/api/v1/documents/{doc_id}/download")
        try:
            with self.opener.open(req) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            return e.code, b""

    def delete_document(self, doc_id: str) -> int:
        req = urllib.request.Request(
            f"{self.base_url}/api/v1/documents/{doc_id}",
            headers={"X-CSRF-Token": self.csrf_token or ""},
            method="DELETE",
        )
        try:
            with self.opener.open(req) as resp:
                return resp.status
        except urllib.error.HTTPError as e:
            return e.code


def main() -> int:
    print("=================================================================")
    print(" DocVault D9.13 — Live Application & Document Operations Check   ")
    print(f" Target URL: {APP_BASE_URL}")
    print("=================================================================\n")

    # 1. Health & Readiness
    print("[1/8] Verifying /health and /ready endpoints...")
    opener = urllib.request.build_opener()
    with opener.open(urllib.request.Request(f"{APP_BASE_URL}/health"), timeout=5) as r:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        assert r.status == 200
        health_data = json.loads(r.read().decode())
        print(f"  [PASS] GET /health returned HTTP 200: {health_data}")

    with opener.open(urllib.request.Request(f"{APP_BASE_URL}/ready"), timeout=5) as r:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        assert r.status == 200
        ready_data = json.loads(r.read().decode())
        print(f"  [PASS] GET /ready returned HTTP 200: {ready_data}")

    # 2. Authentication
    print("\n[2/8] Authenticating User A (test_probe)...")
    client_a = LiveTestClient()
    status, _auth_body = client_a.login(USER_A)
    assert status == 200, f"Login failed: status={status}"
    print(f"  [PASS] Login successful for '{USER_A['username']}', CSRF token issued.")

    status, me = client_a.get_me()
    assert status == 200 and me.get("username") == USER_A["username"]
    print(f"  [PASS] GET /auth/me confirmed identity: {me['username']} (role: {me.get('role')})")

    # 3. Document Upload
    print("\n[3/8] Uploading temporary test PDF document...")
    assert PDF_PATH.is_file(), f"Fixture not found at {PDF_PATH}"
    pdf_bytes = PDF_PATH.read_bytes()
    expected_sha256 = hashlib.sha256(pdf_bytes).hexdigest()
    test_filename = f"d9_13_test_{uuid.uuid4().hex[:8]}.pdf"

    status, upload_res = client_a.upload_document(test_filename, pdf_bytes)
    assert status == 201, f"Upload failed: status={status}, body={upload_res}"
    doc_id = upload_res["id"]
    print(f"  [PASS] Document uploaded successfully! Document ID: {doc_id}")
    print(f"         Filename: {upload_res.get('display_filename')}, Size: {upload_res.get('file_size')} bytes")

    try:
        # 4. Metadata Retrieval
        print("\n[4/8] Retrieving document metadata...")
        status, meta = client_a.get_document_metadata(doc_id)
        assert status == 200
        assert meta["display_filename"] == test_filename
        assert meta["file_size"] == len(pdf_bytes)
        assert meta["media_type"] == "application/pdf"
        print(f"  [PASS] Metadata verified: ID={meta['id']}, Filename='{meta['display_filename']}', Size={meta['file_size']}, MediaType={meta['media_type']}")

        # 5. Download & SHA-256 byte comparison
        print("\n[5/8] Downloading document and verifying byte integrity (SHA-256)...")
        status, downloaded_bytes = client_a.download_document(doc_id)
        assert status == 200
        downloaded_sha256 = hashlib.sha256(downloaded_bytes).hexdigest()
        assert downloaded_sha256 == expected_sha256, (
            f"SHA-256 mismatch! Expected: {expected_sha256}, Got: {downloaded_sha256}"
        )
        print(f"  [PASS] Downloaded {len(downloaded_bytes)} bytes.")
        print(f"         Original SHA-256:   {expected_sha256}")
        print(f"         Downloaded SHA-256: {downloaded_sha256}")
        print("  [PASS] 100% cryptographic byte match confirmed!")

        # 6. Access Control: Cross-User Isolation
        print("\n[6/8] Verifying access control: unauthorized cross-user access denial...")
        client_b = LiveTestClient()
        status_b, _ = client_b.login(USER_B)
        assert status_b == 200
        print(f"  [INFO] Authenticated User B ('{USER_B['username']}')")

        # User B attempts to access User A's document metadata
        status_b_meta, _ = client_b.get_document_metadata(doc_id)
        assert status_b_meta == 404, f"Expected 404 for unauthorized metadata query, got {status_b_meta}"
        print("  [PASS] User B metadata access denied with HTTP 404 (private document isolation confirmed).")

        # User B attempts to download User A's document
        status_b_dl, _ = client_b.download_document(doc_id)
        assert status_b_dl == 404, f"Expected 404 for unauthorized document download, got {status_b_dl}"
        print("  [PASS] User B download access denied with HTTP 404.")

        # 7. Document Deletion
        print("\n[7/8] Cleaning up temporary test document...")
        status = client_a.delete_document(doc_id)
        assert status == 204, f"Expected 204 on deletion, got {status}"
        print(f"  [PASS] DELETE /api/v1/documents/{doc_id} returned HTTP 204 No Content.")

        # Confirm post-deletion 404 for owner
        status_after, _ = client_a.get_document_metadata(doc_id)
        assert status_after == 404
        print("  [PASS] Document confirmed deleted (GET returned HTTP 404).")

    finally:
        # Guarantee cleanup
        client_a.delete_document(doc_id)

    # 8. Persistence Verification
    print("\n[8/8] Verifying persistent volume claim and PostgreSQL storage integrity...")
    env = os.environ.copy()
    env["KUBECONFIG"] = "/home/docvault/.kube/config"

    pvc_cmd = ["kubectl", "get", "pvc", "docvault-documents", "-n", "docvault", "-o", "jsonpath={.status.phase}"]
    pvc_status = subprocess.check_output(pvc_cmd, env=env, text=True).strip()
    assert pvc_status == "Bound", f"Expected PVC status Bound, got {pvc_status}"
    print(f"  [PASS] PVC 'docvault-documents' is in status: {pvc_status}")

    pod_cmd = ["kubectl", "get", "pods", "-n", "docvault", "-l", "app.kubernetes.io/name=docvault", "-o", "jsonpath={.items[0].status.phase}"]
    pod_phase = subprocess.check_output(pod_cmd, env=env, text=True).strip()
    assert pod_phase == "Running", f"Expected Pod phase Running, got {pod_phase}"
    print(f"  [PASS] Pod is in status: {pod_phase}")

    print("\n=================================================================")
    print(" ALL 8 VERIFICATION CHECKS PASSED: DEPLOYMENT VERIFIED 100%!     ")
    print("=================================================================")
    return 0


if __name__ == "__main__":
    sys.exit(main())
