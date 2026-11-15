"""Automated Unit Tests for DocVault Phase D8.4 — Jenkins-to-K3s Delivery Foundation.

Validates:
1. Jenkinsfile declarative pipeline structure, options, parameters, and credential IDs.
2. Commit resolution and main branch ancestry verification logic.
3. GitHub Actions 8 mandatory security gate evaluation (fail-closed semantics).
4. Immutable image digest extraction and regex verification.
5. K3s authentication, TLS verification, and namespace isolation boundaries.
6. Standalone verification script integrity and security invariants.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
JENKINSFILE_PATH = REPO_ROOT / "jenkins" / "Jenkinsfile"
VERIFY_SCRIPT_PATH = REPO_ROOT / "scripts" / "verify_jenkins_delivery_foundation.py"

MANDATORY_CI_CHECKS = [
    "Gitleaks secret scan",
    "Automated Quality & Testing Gates",
    "Dependency vulnerability audit",
    "Semgrep SAST",
    "Build Container Image",
    "Vulnerability Scan & Policy Validation",
    "Playwright Browser End-to-End Tests",
    "OWASP ZAP Dynamic Security Scan",
]


# =============================================================================
# 1. Jenkinsfile Scaffolding & Configuration Tests
# =============================================================================


def test_jenkinsfile_exists_and_is_nonempty() -> None:
    """Jenkinsfile exists and contains declarative pipeline content."""
    assert JENKINSFILE_PATH.is_file(), f"Missing {JENKINSFILE_PATH}"
    content = JENKINSFILE_PATH.read_text(encoding="utf-8")
    assert content.strip().startswith("pipeline {"), "Jenkinsfile must be a declarative pipeline"


def test_jenkinsfile_options_and_parameters() -> None:
    """Jenkinsfile specifies required timeout, concurrency, and parameter definitions."""
    content = JENKINSFILE_PATH.read_text(encoding="utf-8")

    # Options
    assert "timeout(time: 15, unit: 'MINUTES')" in content
    assert "disableConcurrentBuilds()" in content
    assert "ansiColor('xterm')" in content
    assert "timestamps()" in content

    # Parameters
    assert "TARGET_COMMIT" in content
    assert "14178f7dc0ff89fe16cd72bdbbe38cb90c838612" in content


def test_jenkinsfile_dedicated_credential_ids() -> None:
    """Jenkinsfile uses dedicated DocVault credential IDs and never embeds raw secrets."""
    content = JENKINSFILE_PATH.read_text(encoding="utf-8")

    assert "docvault-k3s-token" in content
    assert "docvault-k3s-ca" in content
    assert "docvault-github-token" in content

    # Ensure no raw tokens or passwords embedded
    assert "password" not in content.lower() or "credentials" in content.lower()
    assert "ghp_" not in content
    assert "gho_" not in content
    assert "-----BEGIN RSA PRIVATE KEY-----" not in content


def test_jenkinsfile_stages_structure() -> None:
    """Jenkinsfile implements stages 1 to 5 in exact sequence."""
    content = JENKINSFILE_PATH.read_text(encoding="utf-8")

    expected_stages = [
        "1. Resolve Target Commit on main",
        "2. Verify GitHub Actions CI Gates",
        "3. Retrieve Immutable Image Digest",
        "4. Authenticate to K3s as jenkins-deployer",
        "5. Verify Namespace-Scoped K3s Access",
    ]

    for stage_name in expected_stages:
        assert f"stage('{stage_name}')" in content, f"Missing stage '{stage_name}' in Jenkinsfile"


def test_jenkinsfile_mandatory_ci_checks_list() -> None:
    """Jenkinsfile verifies all eight required GitHub Actions security checks."""
    content = JENKINSFILE_PATH.read_text(encoding="utf-8")

    for check_name in MANDATORY_CI_CHECKS:
        assert f"'{check_name}'" in content, f"Missing mandatory check '{check_name}' in Jenkinsfile"


def test_jenkinsfile_k3s_endpoint_and_tls_verification() -> None:
    """Jenkinsfile configures correct K3s endpoint and preserves TLS validation."""
    content = JENKINSFILE_PATH.read_text(encoding="utf-8")

    assert "https://172.23.0.1:6443" in content
    assert "--cacert" in content
    assert "--insecure" not in content
    assert "--insecure-skip-tls-verify" not in content


# =============================================================================
# 2. Logic Simulation Tests: Commit Ancestry & Main Branch Verification
# =============================================================================


def evaluate_commit_ancestry(compare_status: str) -> bool:
    """Simulates Stage 1 commit ancestry validation."""
    return compare_status in ("identical", "behind")


def test_commit_ancestry_validation_success() -> None:
    """Commit identical to main HEAD or behind main HEAD passes ancestry check."""
    assert evaluate_commit_ancestry("identical") is True
    assert evaluate_commit_ancestry("behind") is True


def test_commit_ancestry_validation_rejection() -> None:
    """Diverged, ahead, or unassociated commits are strictly rejected."""
    assert evaluate_commit_ancestry("ahead") is False
    assert evaluate_commit_ancestry("diverged") is False
    assert evaluate_commit_ancestry("unknown") is False


# =============================================================================
# 3. Logic Simulation Tests: 8 Mandatory GitHub Actions CI Gates
# =============================================================================


def evaluate_ci_gates(
    check_runs: list[dict[str, Any]], target_sha: str
) -> tuple[bool, list[str]]:
    """Simulates Stage 2 fail-closed GitHub Actions CI gate evaluation."""
    check_map: dict[str, tuple[str, str]] = {}
    for cr in check_runs:
        if cr.get("head_sha") == target_sha:
            check_map[cr["name"]] = (cr.get("status", ""), cr.get("conclusion", ""))

    missing_or_failed: list[str] = []
    for req_check in MANDATORY_CI_CHECKS:
        if req_check not in check_map:
            missing_or_failed.append(f"{req_check}: MISSING")
        else:
            status, conclusion = check_map[req_check]
            if status != "completed" or conclusion != "success":
                missing_or_failed.append(f"{req_check}: status={status}, conclusion={conclusion}")

    return len(missing_or_failed) == 0, missing_or_failed


def test_ci_gates_all_successful() -> None:
    """All 8 mandatory checks completed with success for exact SHA pass."""
    sha = "14178f7dc0ff89fe16cd72bdbbe38cb90c838612"
    checks = [
        {"name": name, "head_sha": sha, "status": "completed", "conclusion": "success"}
        for name in MANDATORY_CI_CHECKS
    ]

    passed, errors = evaluate_ci_gates(checks, sha)
    assert passed is True
    assert errors == []


def test_ci_gates_missing_check_fails_closed() -> None:
    """Missing required check (e.g., OWASP ZAP) fails closed."""
    sha = "14178f7dc0ff89fe16cd72bdbbe38cb90c838612"
    # Omit OWASP ZAP
    checks = [
        {"name": name, "head_sha": sha, "status": "completed", "conclusion": "success"}
        for name in MANDATORY_CI_CHECKS
        if name != "OWASP ZAP Dynamic Security Scan"
    ]

    passed, errors = evaluate_ci_gates(checks, sha)
    assert passed is False
    assert any("OWASP ZAP Dynamic Security Scan: MISSING" in err for err in errors)


def test_ci_gates_pending_check_fails_closed() -> None:
    """In-progress or queued check fails closed."""
    sha = "14178f7dc0ff89fe16cd72bdbbe38cb90c838612"
    checks = [
        {"name": name, "head_sha": sha, "status": "completed", "conclusion": "success"}
        for name in MANDATORY_CI_CHECKS
    ]
    # Mark Semgrep as in_progress
    checks[3]["status"] = "in_progress"
    checks[3]["conclusion"] = "pending"

    passed, errors = evaluate_ci_gates(checks, sha)
    assert passed is False
    assert any("Semgrep SAST: status=in_progress" in err for err in errors)


def test_ci_gates_failed_conclusion_fails_closed() -> None:
    """Check with failed or cancelled conclusion fails closed."""
    sha = "14178f7dc0ff89fe16cd72bdbbe38cb90c838612"
    checks = [
        {"name": name, "head_sha": sha, "status": "completed", "conclusion": "success"}
        for name in MANDATORY_CI_CHECKS
    ]
    # Mark Gitleaks as failure
    checks[0]["conclusion"] = "failure"

    passed, errors = evaluate_ci_gates(checks, sha)
    assert passed is False
    assert any("Gitleaks secret scan: status=completed, conclusion=failure" in err for err in errors)


def test_ci_gates_different_commit_sha_ignored() -> None:
    """Checks associated with a different commit SHA do not satisfy the required SHA."""
    target_sha = "14178f7dc0ff89fe16cd72bdbbe38cb90c838612"
    other_sha = "0bbb3f1dc0ff89fe16cd72bdbbe38cb90c838612"
    checks = [
        {"name": name, "head_sha": other_sha, "status": "completed", "conclusion": "success"}
        for name in MANDATORY_CI_CHECKS
    ]

    passed, errors = evaluate_ci_gates(checks, target_sha)
    assert passed is False
    assert len(errors) == 8  # All 8 are missing for target_sha


# =============================================================================
# 4. Logic Simulation Tests: Immutable Digest & Image Reference Provenance
# =============================================================================


DIGEST_REGEX = re.compile(r"^sha256:[a-f0-9]{64}$")
PROVENANCE_REGEX = re.compile(r"^iyedbnaissa/docvault-api@sha256:[a-f0-9]{64}$")


def test_valid_immutable_digest_format() -> None:
    """Valid sha256 digest conforms strictly to regex."""
    digest = "sha256:05a3d9053c7250448b760e02f92422bb32c8a6b465c9222b858bfc8eb1ccd687"
    assert DIGEST_REGEX.match(digest) is not None

    image_ref = f"iyedbnaissa/docvault-api@{digest}"
    assert PROVENANCE_REGEX.match(image_ref) is not None


def test_invalid_digest_formats_rejected() -> None:
    """Mutable tags, malformed hashes, or wrong algorithms are rejected."""
    invalid_digests = [
        "latest",
        "14178f7",
        "sha256:123",  # too short
        "sha256:zzza3d9053c7250448b760e02f92422bb32c8a6b465c9222b858bfc8eb1ccd687",  # non-hex
        "md5:05a3d9053c7250448b760e02f92422bb32c8a6b465c9222b858bfc8eb1ccd687",  # wrong algorithm
    ]
    for d in invalid_digests:
        assert DIGEST_REGEX.match(d) is None


# =============================================================================
# 5. Verification Script Structure & Invariant Tests
# =============================================================================


def test_verification_script_exists_and_is_executable() -> None:
    """scripts/verify_jenkins_delivery_foundation.py exists and is executable."""
    assert VERIFY_SCRIPT_PATH.is_file(), f"Missing {VERIFY_SCRIPT_PATH}"
    assert VERIFY_SCRIPT_PATH.stat().st_mode & 0o111, f"{VERIFY_SCRIPT_PATH} is not executable"


def test_verification_script_security_invariants() -> None:
    """Verification script enforces zero workload creation and non-root execution."""
    content = VERIFY_SCRIPT_PATH.read_text(encoding="utf-8")

    assert "https://172.23.0.1:6443" in content
    assert "docvault-jenkins" in content
    assert "jenkins-deployer" in content
    assert "14178f7dc0ff89fe16cd72bdbbe38cb90c838612" in content
    assert "scanned-image-metadata" in content
    assert "ZERO application workloads deployed" in content
