#!/usr/bin/env python3
"""DocVault Phase D8.4 — Focused Jenkins-to-K3s Delivery Foundation Verifier.

Executes the focused pre-deployment verification suite proving:
1. Jenkins container can reach the K3s API endpoint (https://172.23.0.1:6443).
2. Strict TLS verification succeeds using the actual K3s CA certificate.
3. Authentication succeeds as system:serviceaccount:docvault:jenkins-deployer.
4. Read-only access to namespace 'docvault' succeeds (Pods, Deployments).
5. Cross-namespace access to 'kube-system' is strictly denied (HTTP 403).
6. Secret read access in 'docvault' is strictly denied (HTTP 403).
7. Cluster-scoped resource access (nodes) is strictly denied (HTTP 403).
8. GitHub CI verification correctly evaluates main commit and all 8 required checks.
9. Image digest retrieval returns the published immutable digest from verified CI metadata.

Execution constraint:
- Strictly read-only verification.
- Zero workloads created or deployed.
"""

from __future__ import annotations

import io
import json
import logging
import re
import subprocess
import sys
import urllib.error
import urllib.request
import zipfile

logger = logging.getLogger(__name__)

K3S_ENDPOINT = "https://172.23.0.1:6443"
CONTAINER_NAME = "docvault-jenkins"
DEFAULT_COMMIT = "14178f7dc0ff89fe16cd72bdbbe38cb90c838612"
GITHUB_REPO = "iyedben/DocVault"
REQUIRED_CHECKS = [
    "Gitleaks secret scan",
    "Automated Quality & Testing Gates",
    "Dependency vulnerability audit",
    "Semgrep SAST",
    "Build Container Image",
    "Vulnerability Scan & Policy Validation",
    "Playwright Browser End-to-End Tests",
    "OWASP ZAP Dynamic Security Scan",
]


def extract_cluster_ca() -> bytes:
    """Extract CA certificate from ~/.kube/config without printing sensitive data."""
    cmd = (
        "KUBECONFIG=/home/docvault/.kube/config kubectl config view --raw "
        "-o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 -d"
    )
    ca_bytes = subprocess.check_output(cmd, shell=True)
    if not ca_bytes.startswith(b"-----BEGIN CERTIFICATE-----"):
        raise ValueError("Failed to extract valid PEM certificate authority from kubeconfig.")
    return ca_bytes


def generate_deployer_token() -> str:
    """Request a short-lived bearer token for jenkins-deployer using TokenRequest API."""
    cmd = (
        "KUBECONFIG=/home/docvault/.kube/config kubectl create token jenkins-deployer "
        "-n docvault --duration=1h"
    )
    token = subprocess.check_output(cmd, shell=True).decode().strip()
    if not token or len(token) < 20:
        raise ValueError("Failed to generate short-lived ServiceAccount token.")
    return token


def run_container_curl(args: list[str]) -> tuple[int, str]:
    """Execute curl inside docvault-jenkins container and return (exit_code, output)."""
    full_cmd = ["docker", "exec", CONTAINER_NAME, "curl"] + args
    res = subprocess.run(full_cmd, capture_output=True, text=True, check=False)
    return res.returncode, (res.stdout + res.stderr).strip()


def verify_k3s_connectivity_and_tls(ca_bytes: bytes) -> bool:
    """Verify Jenkins container can reach K3s API with strict TLS certificate verification."""
    print("[1/9] Testing Jenkins container reachability to K3s endpoint...")
    p = subprocess.Popen(
        ["docker", "exec", "-i", CONTAINER_NAME, "tee", "/tmp/test-k3s-ca.crt"],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    p.communicate(input=ca_bytes)

    try:
        _ret, out = run_container_curl([
            "-s", "-o", "/dev/null", "-w", "%{http_code}",
            "--cacert", "/tmp/test-k3s-ca.crt",
            f"{K3S_ENDPOINT}/readyz",
        ])
        if out not in ("200", "401"):
            print(f"  [FAIL] TLS handshake or connectivity failed (code: {out})")
            return False
        print(f"  [PASS] Endpoint {K3S_ENDPOINT}/readyz reachable with valid TLS (HTTP {out}).")
        return True
    finally:
        subprocess.run(["docker", "exec", CONTAINER_NAME, "rm", "-f", "/tmp/test-k3s-ca.crt"], check=False)


def verify_k3s_rbac_boundaries(ca_bytes: bytes, token: str) -> dict[str, bool]:
    """Verify jenkins-deployer authentication and namespace-scoped authorization boundaries."""
    # Write CA and token to container temp files
    subprocess.Popen(
        ["docker", "exec", "-i", CONTAINER_NAME, "tee", "/tmp/test-k3s-ca.crt"],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ).communicate(input=ca_bytes)

    subprocess.Popen(
        ["docker", "exec", "-i", CONTAINER_NAME, "tee", "/tmp/test-k3s.token"],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ).communicate(input=token.encode())

    checks = [
        ("auth_deployer", f"{K3S_ENDPOINT}/api/v1/namespaces/docvault/pods", "200", "[3/9] Authentication as jenkins-deployer"),
        ("read_pods", f"{K3S_ENDPOINT}/api/v1/namespaces/docvault/pods", "200", "[4/9] Read-only access to docvault Pods"),
        ("read_deployments", f"{K3S_ENDPOINT}/apis/apps/v1/namespaces/docvault/deployments", "200", "[4b/9] Read-only access to docvault Deployments"),
        ("deny_kube_system", f"{K3S_ENDPOINT}/api/v1/namespaces/kube-system/pods", "403", "[5/9] Denial of access to kube-system namespace"),
        ("deny_secrets", f"{K3S_ENDPOINT}/api/v1/namespaces/docvault/secrets", "403", "[6/9] Denial of Secret read access in docvault"),
        ("deny_nodes", f"{K3S_ENDPOINT}/api/v1/nodes", "403", "[7/9] Denial of cluster-scoped node access"),
    ]

    results = {}
    try:
        for key, url, expected_code, desc in checks:
            curl_cmd = (
                f"curl -s -o /dev/null -w '%{{http_code}}' --cacert /tmp/test-k3s-ca.crt "
                f"-H \"Authorization: Bearer $(cat /tmp/test-k3s.token)\" '{url}'"
            )
            res = subprocess.run(["docker", "exec", CONTAINER_NAME, "bash", "-c", curl_cmd], capture_output=True, text=True, check=False)
            actual_code = res.stdout.strip()
            passed = (actual_code == expected_code)
            results[key] = passed
            status_str = "PASS" if passed else "FAIL"
            print(f"{desc}: actual={actual_code}, expected={expected_code} => [{status_str}]")
    finally:
        subprocess.run(["docker", "exec", CONTAINER_NAME, "rm", "-f", "/tmp/test-k3s-ca.crt", "/tmp/test-k3s.token"], check=False)

    return results


def verify_github_ci_commit_and_checks(commit_sha: str) -> bool:
    """Verify that commit_sha belongs to main and all 8 required checks are completed/success."""
    print(f"[8/9] Verifying GitHub Actions CI results for commit {commit_sha[:7]}...")

    # 1. Verify ancestry on main
    compare_url = f"https://api.github.com/repos/{GITHUB_REPO}/compare/main...{commit_sha}"
    req = urllib.request.Request(compare_url, headers={"User-Agent": "docvault-verifier"})
    try:
        opener = urllib.request.build_opener()
        with opener.open(req, timeout=10) as resp:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
            compare_data = json.loads(resp.read())
            status = compare_data.get("status")
            if status not in ("identical", "behind"):
                print(f"  [FAIL] Commit {commit_sha} does not belong to main branch (compare status: {status})")
                return False
            print(f"  [PASS] Commit {commit_sha[:7]} confirmed on main (compare status: {status}).")
    except (urllib.error.URLError, json.JSONDecodeError, OSError) as e:
        print(f"  [FAIL] GitHub API compare request failed: {e}")
        return False

    # 2. Verify all 8 required checks
    checks_url = f"https://api.github.com/repos/{GITHUB_REPO}/commits/{commit_sha}/check-runs"
    req = urllib.request.Request(checks_url, headers={"User-Agent": "docvault-verifier"})
    try:
        opener = urllib.request.build_opener()
        with opener.open(req, timeout=10) as resp:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
            checks_data = json.loads(resp.read())
            check_runs = checks_data.get("check_runs", [])
            check_map = {}
            for cr in check_runs:
                if cr.get("head_sha") == commit_sha:
                    check_map[cr["name"]] = (cr["status"], cr["conclusion"])

            missing_or_failed = []
            for req_check in REQUIRED_CHECKS:
                if req_check not in check_map:
                    missing_or_failed.append(f"{req_check}: MISSING")
                else:
                    st, conc = check_map[req_check]
                    if st != "completed" or conc != "success":
                        missing_or_failed.append(f"{req_check}: status={st}, conclusion={conc}")
                    else:
                        print(f"    - {req_check}: SUCCESS")

            if missing_or_failed:
                print(f"  [FAIL] CI gate check failure: {', '.join(missing_or_failed)}")
                return False

            print(f"  [PASS] All {len(REQUIRED_CHECKS)} mandatory GitHub Actions checks verified SUCCESS.")
            return True
    except (urllib.error.URLError, json.JSONDecodeError, OSError) as e:
        print(f"  [FAIL] GitHub API check-runs request failed: {e}")
        return False


def verify_image_digest_retrieval(commit_sha: str) -> tuple[bool, str]:
    """Retrieve already-published immutable image digest from verified CI artifact."""
    print("[9/9] Retrieving immutable Docker image digest from verified CI metadata...")

    # Query workflow runs for this commit
    runs_url = f"https://api.github.com/repos/{GITHUB_REPO}/actions/runs?head_sha={commit_sha}&event=push"
    try:
        token = subprocess.check_output("gh auth token", shell=True).decode().strip()
        headers = {"User-Agent": "docvault-verifier", "Authorization": f"Bearer {token}"}
    except (subprocess.SubprocessError, OSError):
        headers = {"User-Agent": "docvault-verifier"}

    try:
        req = urllib.request.Request(runs_url, headers=headers)
        opener = urllib.request.build_opener()
        with opener.open(req, timeout=10) as resp:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
            runs_data = json.loads(resp.read())
            runs = runs_data.get("workflow_runs", [])

        # Search workflow runs for the one containing scanned-image-metadata
        target_artifact_id = None
        target_run_id = None

        for r in runs:
            r_id = r.get("id")
            artifacts_url = f"https://api.github.com/repos/{GITHUB_REPO}/actions/runs/{r_id}/artifacts"
            req_art = urllib.request.Request(artifacts_url, headers=headers)
            try:
                with opener.open(req_art, timeout=10) as resp_art:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
                    artifacts_data = json.loads(resp_art.read())
                    for a in artifacts_data.get("artifacts", []):
                        if a.get("name") == "scanned-image-metadata":
                            target_artifact_id = a.get("id")
                            target_run_id = r_id
                            break
            except (urllib.error.URLError, json.JSONDecodeError, OSError) as exc:
                logger.debug("Skipping workflow run %s artifact check due to error: %s", r_id, exc)
                continue
            if target_artifact_id:
                break

        if not target_artifact_id:
            print(f"  [FAIL] Artifact 'scanned-image-metadata' not found across workflow runs for commit {commit_sha}.")
            return False, ""

        print(f"  Found artifact 'scanned-image-metadata' (ID: {target_artifact_id}) on workflow run {target_run_id}.")

        # Download zip via curl to avoid urllib Authorization redirect header retention
        zip_url = f"https://api.github.com/repos/{GITHUB_REPO}/actions/artifacts/{target_artifact_id}/zip"
        cmd = ["curl", "-sL", "-H", f"Authorization: Bearer {token}", "-H", "User-Agent: docvault-verifier", zip_url]
        zip_bytes = subprocess.check_output(cmd)

        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            digest = zf.read("scanned-image-id.txt").decode().strip()

        if not re.match(r"^sha256:[a-f0-9]{64}$", digest):
            print(f"  [FAIL] Malformed digest: {digest}")
            return False, ""

        image_ref = f"iyedbnaissa/docvault-api@{digest}"
        print(f"  [PASS] Retrieved verified immutable image reference: {image_ref}")
        return True, image_ref
    except (urllib.error.URLError, json.JSONDecodeError, subprocess.SubprocessError, zipfile.BadZipFile, OSError) as e:
        print(f"  [FAIL] Digest retrieval failed: {e}")
        return False, ""


def main() -> int:
    """Execute all focused D8.4 delivery foundation checks."""
    print("=================================================================")
    print(" DocVault D8.4 — Focused Delivery Foundation Verification Suite  ")
    print("=================================================================")
    print()

    # Step 1 & 2: TLS and Endpoint reachability
    try:
        ca_bytes = extract_cluster_ca()
    except (subprocess.SubprocessError, ValueError, OSError) as e:
        print(f"FATAL: {e}")
        return 1

    tls_ok = verify_k3s_connectivity_and_tls(ca_bytes)
    if not tls_ok:
        print("FAIL: K3s endpoint connectivity and TLS check failed.")
        return 1
    print()

    # Step 3 to 7: RBAC authentication and boundaries
    try:
        token = generate_deployer_token()
    except (subprocess.SubprocessError, ValueError, OSError) as e:
        print(f"FATAL: {e}")
        return 1

    rbac_results = verify_k3s_rbac_boundaries(ca_bytes, token)
    if not all(rbac_results.values()):
        print("FAIL: RBAC boundary verification failed.")
        return 1
    print()

    # Step 8: GitHub CI verification
    ci_ok = verify_github_ci_commit_and_checks(DEFAULT_COMMIT)
    if not ci_ok:
        print("FAIL: GitHub CI verification failed.")
        return 1
    print()

    # Step 9: Immutable image digest retrieval
    digest_ok, image_ref = verify_image_digest_retrieval(DEFAULT_COMMIT)
    if not digest_ok:
        print("FAIL: Immutable image digest retrieval failed.")
        return 1
    print()

    print("=================================================================")
    print(" VERIFICATION SUMMARY: ALL 9 FOCUSED CHECKS PASSED SUCCESSFULLY! ")
    print(f" Target Commit:    {DEFAULT_COMMIT}")
    print(f" Verified Image:   {image_ref}")
    print(" ServiceAccount:   system:serviceaccount:docvault:jenkins-deployer")
    print(f" K3s Endpoint:     {K3S_ENDPOINT} (TLS Verified)")
    print(" Scope:            Namespace 'docvault' strictly isolated")
    print(" Workloads:        ZERO application workloads deployed")
    print("=================================================================")
    return 0


if __name__ == "__main__":
    sys.exit(main())
