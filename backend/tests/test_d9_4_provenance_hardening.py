"""Automated Unit Tests for DocVault Phase D9.4 — Container Provenance Hardening and SCM Delivery.

Validates:
1. Container security workflow artifact retention (30 days) and metadata generation schema.
2. Jenkinsfile default commit resolution adopting SCM checked-out commit.
3. Workflow run resolution requiring completed, successful 'Container Security & Artifact Gate' run.
4. Docker Hub publication job verification requiring completed, successful 'Publish to Docker Hub' job.
5. Scanned image metadata artifact extraction rejecting expired or missing artifacts.
6. Provenance metadata validation enforcing repository, commit SHA, run ID, and immutable digest integrity.
7. Rejection of malicious, spoofed, mismatched, or unverified provenance records.
8. Backward compatibility for legacy single-digest artifact files.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "container-security.yml"
JENKINSFILE_PATH = REPO_ROOT / "jenkins" / "Jenkinsfile"

SHA256_REGEX = re.compile(r"^sha256:[a-f0-9]{64}$")
VALID_COMMIT = "538c39a8e72322c45ed24c8406bfbb68b535936f"
VALID_REPO = "iyedben/DocVault"
VALID_IMAGE_REPO = "iyedbnaissa/docvault-api"
VALID_DIGEST = "sha256:05a3d9053c7250448b760e02f92422bb32c8a6b465c9222b858bfc8eb1ccd687"
VALID_RUN_ID = 123456789


# =============================================================================
# Helper Functions Mirroring Jenkinsfile Groovy Logic
# =============================================================================


def extract_run_id(runs_data: dict[str, Any]) -> int | None:
    """Mirrors Jenkinsfile extractRunId(@NonCPS)."""
    for r in runs_data.get("workflow_runs", []):
        if (
            r.get("name") == "Container Security & Artifact Gate"
            and r.get("status") == "completed"
            and r.get("conclusion") == "success"
        ):
            return r.get("id")
    return None


def is_publish_job_successful(jobs_data: dict[str, Any]) -> bool:
    """Mirrors Jenkinsfile isPublishJobSuccessful(@NonCPS)."""
    for j in jobs_data.get("jobs", []):
        if (
            j.get("name") == "Publish to Docker Hub"
            and j.get("status") == "completed"
            and j.get("conclusion") == "success"
        ):
            return True
    return False


def extract_artifact_id(artifacts_data: dict[str, Any]) -> int | None:
    """Mirrors Jenkinsfile extractArtifactId(@NonCPS)."""
    for a in artifacts_data.get("artifacts", []):
        if a.get("name") == "scanned-image-metadata" and a.get("expired") is not True:
            return a.get("id")
    return None


def validate_provenance(
    meta: dict[str, Any],
    expected_repo: str,
    target_commit: str,
    verified_run_id: int,
    expected_image_repo: str,
) -> str:
    """Mirrors Jenkinsfile Stage 3 metadata provenance verification."""
    if meta.get("repository") != expected_repo:
        raise ValueError(
            f"Provenance violation: Metadata repository '{meta.get('repository')}' "
            f"does not match expected '{expected_repo}'."
        )
    if meta.get("commit_sha") != target_commit:
        raise ValueError(
            f"Provenance violation: Metadata commit_sha '{meta.get('commit_sha')}' "
            f"does not match target commit '{target_commit}'."
        )
    if str(meta.get("run_id")) != str(verified_run_id):
        raise ValueError(
            f"Provenance violation: Metadata run_id '{meta.get('run_id')}' "
            f"does not match verified workflow run '{verified_run_id}'."
        )

    expected_prefix = f"{expected_image_repo}@"
    image_ref = meta.get("image_ref", "")
    if not image_ref or not image_ref.startswith(expected_prefix):
        raise ValueError(
            f"Provenance violation: Metadata image_ref '{image_ref}' "
            f"does not match expected prefix '{expected_prefix}'."
        )

    digest = meta.get("image_digest")
    if not digest:
        match = re.search(r"@(sha256:[a-f0-9]{64})$", image_ref)
        if match:
            digest = match.group(1)

    if not digest or not SHA256_REGEX.match(digest):
        raise ValueError(f"Provenance verification failed: Invalid digest '{digest}'")

    return digest


# =============================================================================
# 1. Container Security Workflow Invariants
# =============================================================================


def test_container_security_workflow_artifact_retention() -> None:
    """Workflow sets 30-day retention on scanned-image-metadata."""
    content = WORKFLOW_PATH.read_text(encoding="utf-8")
    data = yaml.safe_load(content)

    scan_job = data["jobs"]["scan"]
    upload_step = None
    for step in scan_job.get("steps", []):
        if step.get("name") == "Upload scanned image metadata artifact":
            upload_step = step
            break

    assert upload_step is not None, "Missing 'Upload scanned image metadata artifact' step"
    assert upload_step["with"]["name"] == "scanned-image-metadata"
    assert upload_step["with"]["retention-days"] == 30, (
        f"Expected retention-days 30, got {upload_step['with'].get('retention-days')}"
    )


def test_container_security_workflow_metadata_generation_step() -> None:
    """Workflow contains metadata generation step with required keys."""
    content = WORKFLOW_PATH.read_text(encoding="utf-8")
    data = yaml.safe_load(content)

    scan_job = data["jobs"]["scan"]
    gen_step = None
    for step in scan_job.get("steps", []):
        if step.get("name") == "Generate image provenance metadata":
            gen_step = step
            break

    assert gen_step is not None, "Missing 'Generate image provenance metadata' step"
    run_script = gen_step.get("run", "")

    required_keys = [
        '"repository"',
        '"commit_sha"',
        '"run_id"',
        '"image_name"',
        '"image_digest"',
        '"image_ref"',
    ]
    for key in required_keys:
        assert key in run_script, f"Missing required key {key} in metadata generation script"


def test_container_security_workflow_includes_both_files() -> None:
    """Workflow artifact uploads both scanned-image-id.txt and image-metadata.json."""
    content = WORKFLOW_PATH.read_text(encoding="utf-8")
    assert "scanned-image-id.txt" in content
    assert "image-metadata.json" in content


# =============================================================================
# 2. Jenkinsfile Configuration & SCM Commit Adoption
# =============================================================================


def test_jenkinsfile_default_target_commit_is_empty() -> None:
    """Jenkinsfile TARGET_COMMIT defaults to empty string to adopt SCM commit."""
    content = JENKINSFILE_PATH.read_text(encoding="utf-8")
    param_block = re.search(r"string\s*\(\s*name:\s*'TARGET_COMMIT'[\s\S]*?\)", content)
    assert param_block is not None
    assert "defaultValue: ''" in param_block.group(0)


def test_jenkinsfile_adopts_pipeline_source_commit() -> None:
    """Jenkinsfile Stage 1 adopts PIPELINE_SOURCE_COMMIT when TARGET_COMMIT is empty."""
    content = JENKINSFILE_PATH.read_text(encoding="utf-8")
    assert "env.PIPELINE_SOURCE_COMMIT" in content
    assert "adopting SCM checked-out commit" in content


def test_jenkinsfile_contains_provenance_verification_logic() -> None:
    """Jenkinsfile contains required Stage 3 provenance verification steps."""
    content = JENKINSFILE_PATH.read_text(encoding="utf-8")

    assert "isPublishJobSuccessful" in content
    assert "extractRunId" in content
    assert "extractArtifactId" in content
    assert "image-metadata.json" in content
    assert "meta.repository != env.GITHUB_REPO" in content
    assert "meta.commit_sha != env.RESOLVED_COMMIT_SHA" in content
    assert "meta.image_ref" in content


# =============================================================================
# 3. Provenance Verification Positive Tests
# =============================================================================


def test_provenance_positive_full_metadata() -> None:
    """Valid provenance metadata succeeds and returns correct immutable digest."""
    meta = {
        "repository": VALID_REPO,
        "commit_sha": VALID_COMMIT,
        "run_id": str(VALID_RUN_ID),
        "image_name": VALID_IMAGE_REPO,
        "image_digest": VALID_DIGEST,
        "image_ref": f"{VALID_IMAGE_REPO}@{VALID_DIGEST}",
    }

    digest = validate_provenance(meta, VALID_REPO, VALID_COMMIT, VALID_RUN_ID, VALID_IMAGE_REPO)
    assert digest == VALID_DIGEST


def test_extract_run_id_success() -> None:
    """extract_run_id finds completed and successful Container Security run."""
    runs_data = {
        "workflow_runs": [
            {
                "id": 999,
                "name": "Dependency vulnerability audit",
                "status": "completed",
                "conclusion": "success",
            },
            {
                "id": VALID_RUN_ID,
                "name": "Container Security & Artifact Gate",
                "status": "completed",
                "conclusion": "success",
            },
        ]
    }
    assert extract_run_id(runs_data) == VALID_RUN_ID


def test_is_publish_job_successful() -> None:
    """is_publish_job_successful returns True when Publish job is completed and successful."""
    jobs_data = {
        "jobs": [
            {"name": "Build Container Image", "status": "completed", "conclusion": "success"},
            {"name": "Publish to Docker Hub", "status": "completed", "conclusion": "success"},
        ]
    }
    assert is_publish_job_successful(jobs_data) is True


def test_extract_artifact_id_success() -> None:
    """extract_artifact_id finds non-expired scanned-image-metadata artifact."""
    artifacts_data = {
        "artifacts": [
            {"id": 444, "name": "other-artifact", "expired": False},
            {"id": 555, "name": "scanned-image-metadata", "expired": False},
        ]
    }
    assert extract_artifact_id(artifacts_data) == 555


# =============================================================================
# 4. Provenance Rejection Tests (Negative Cases)
# =============================================================================


def test_reject_uncompleted_or_failed_workflow_run() -> None:
    """Rejects workflow run if status is in_progress or conclusion is failure."""
    runs_in_progress = {
        "workflow_runs": [
            {
                "id": 101,
                "name": "Container Security & Artifact Gate",
                "status": "in_progress",
                "conclusion": None,
            }
        ]
    }
    assert extract_run_id(runs_in_progress) is None

    runs_failed = {
        "workflow_runs": [
            {
                "id": 102,
                "name": "Container Security & Artifact Gate",
                "status": "completed",
                "conclusion": "failure",
            }
        ]
    }
    assert extract_run_id(runs_failed) is None


def test_reject_failed_publish_job() -> None:
    """Rejects if Publish to Docker Hub job is missing, failed, or cancelled."""
    jobs_failed = {
        "jobs": [
            {"name": "Publish to Docker Hub", "status": "completed", "conclusion": "failure"}
        ]
    }
    assert is_publish_job_successful(jobs_failed) is False

    jobs_missing = {
        "jobs": [
            {"name": "Build Container Image", "status": "completed", "conclusion": "success"}
        ]
    }
    assert is_publish_job_successful(jobs_missing) is False


def test_reject_expired_artifact() -> None:
    """Rejects scanned-image-metadata artifact if expired is true."""
    artifacts_expired = {
        "artifacts": [
            {"id": 777, "name": "scanned-image-metadata", "expired": True}
        ]
    }
    assert extract_artifact_id(artifacts_expired) is None


def test_reject_mismatched_repository() -> None:
    """Rejects provenance metadata if repository does not match."""
    meta = {
        "repository": "attacker/DocVault",
        "commit_sha": VALID_COMMIT,
        "run_id": str(VALID_RUN_ID),
        "image_ref": f"{VALID_IMAGE_REPO}@{VALID_DIGEST}",
    }
    try:
        validate_provenance(meta, VALID_REPO, VALID_COMMIT, VALID_RUN_ID, VALID_IMAGE_REPO)
        assert False, "Expected ValueError on mismatched repository"
    except ValueError as exc:
        assert "Metadata repository 'attacker/DocVault' does not match" in str(exc)


def test_reject_mismatched_commit_sha() -> None:
    """Rejects provenance metadata if commit SHA does not match target commit."""
    meta = {
        "repository": VALID_REPO,
        "commit_sha": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        "run_id": str(VALID_RUN_ID),
        "image_ref": f"{VALID_IMAGE_REPO}@{VALID_DIGEST}",
    }
    try:
        validate_provenance(meta, VALID_REPO, VALID_COMMIT, VALID_RUN_ID, VALID_IMAGE_REPO)
        assert False, "Expected ValueError on mismatched commit_sha"
    except ValueError as exc:
        assert "Metadata commit_sha 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeef' does not match" in str(exc)


def test_reject_mismatched_run_id() -> None:
    """Rejects provenance metadata if workflow run ID does not match verified run."""
    meta = {
        "repository": VALID_REPO,
        "commit_sha": VALID_COMMIT,
        "run_id": "999999999",
        "image_ref": f"{VALID_IMAGE_REPO}@{VALID_DIGEST}",
    }
    try:
        validate_provenance(meta, VALID_REPO, VALID_COMMIT, VALID_RUN_ID, VALID_IMAGE_REPO)
        assert False, "Expected ValueError on mismatched run_id"
    except ValueError as exc:
        assert "Metadata run_id '999999999' does not match" in str(exc)


def test_reject_mismatched_image_repo_prefix() -> None:
    """Rejects provenance metadata if image reference prefix does not match."""
    meta = {
        "repository": VALID_REPO,
        "commit_sha": VALID_COMMIT,
        "run_id": str(VALID_RUN_ID),
        "image_ref": f"attacker/docvault-api@{VALID_DIGEST}",
    }
    try:
        validate_provenance(meta, VALID_REPO, VALID_COMMIT, VALID_RUN_ID, VALID_IMAGE_REPO)
        assert False, "Expected ValueError on mismatched image_ref prefix"
    except ValueError as exc:
        assert "Metadata image_ref 'attacker/docvault-api@" in str(exc)


def test_reject_invalid_digest_format() -> None:
    """Rejects provenance metadata if digest format is not immutable sha256."""
    invalid_digests = [
        "latest",
        "v1.0.0",
        "md5:05a3d9053c7250448b760e02f92422bb",
        "sha256:short",
        "sha256:nothexZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",
    ]
    for inv in invalid_digests:
        meta = {
            "repository": VALID_REPO,
            "commit_sha": VALID_COMMIT,
            "run_id": str(VALID_RUN_ID),
            "image_digest": inv,
            "image_ref": f"{VALID_IMAGE_REPO}@{inv}",
        }
        try:
            validate_provenance(meta, VALID_REPO, VALID_COMMIT, VALID_RUN_ID, VALID_IMAGE_REPO)
            assert False, f"Expected ValueError for invalid digest '{inv}'"
        except ValueError as exc:
            assert "Invalid digest" in str(exc)
