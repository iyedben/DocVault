"""Automated tests for the Container Security GitHub Actions workflow.

Validates .github/workflows/container-security.yml structure, triggers, concurrency,
permissions, job dependencies, third-party action SHA pinning, secrets isolation,
image integrity verification, and fail-closed gates without requiring external YAML parsers.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "container-security.yml"
SHA40_PATTERN = re.compile(r"^[0-9a-f]{40}$")


def _read_workflow_text() -> str:
    assert WORKFLOW_PATH.is_file(), f"Workflow file not found: {WORKFLOW_PATH}"
    return WORKFLOW_PATH.read_text(encoding="utf-8")


def _extract_job_blocks(text: str) -> dict[str, str]:
    """Extract individual job sections from the workflow text."""
    assert "\njobs:\n" in text, "Workflow must contain 'jobs:' block"
    jobs_text = text.split("\njobs:\n", 1)[1]
    job_split = re.split(r"\n  (\w+):\n", "\n" + jobs_text)
    jobs: dict[str, str] = {}
    for i in range(1, len(job_split), 2):
        jobs[job_split[i]] = job_split[i + 1]
    return jobs


class TestContainerSecurityWorkflowTriggersAndPolicy:
    """Validate triggers, permissions, and concurrency controls."""

    def test_workflow_file_exists_and_named(self) -> None:
        text = _read_workflow_text()
        assert re.search(r"^name:\s*Container Security & Artifact Gate", text, re.MULTILINE)

    def test_triggers_and_branch_filters(self) -> None:
        text = _read_workflow_text()

        # Push branch triggers
        assert re.search(r"push:[\s\S]*?branches:[\s\S]*?-\s*main", text), "Push must trigger on main"
        assert re.search(r"push:[\s\S]*?branches:[\s\S]*?-\s*feature/container-security", text), (
            "Push must trigger on feature/container-security"
        )

        # Pull request triggers
        assert re.search(r"pull_request:[\s\S]*?branches:[\s\S]*?-\s*main", text), (
            "Pull request must trigger targeting main"
        )

        # Manual dispatch
        assert re.search(r"workflow_dispatch:\s*", text), "workflow_dispatch must be present"

    def test_least_privilege_permissions(self) -> None:
        text = _read_workflow_text()

        # Top-level permissions
        top_perms = re.search(r"^permissions:\s*\n\s*contents:\s*read", text, re.MULTILINE)
        assert top_perms is not None, "Workflow must declare contents: read at top level"

        # Each job must have permissions: contents: read
        jobs = _extract_job_blocks(text)
        assert len(jobs) == 3, f"Expected 3 jobs, found {len(jobs)}: {list(jobs.keys())}"
        for name, body in jobs.items():
            assert re.search(r"permissions:\s*\n\s*contents:\s*read", body), (
                f"Job '{name}' must declare least-privilege permissions: contents: read"
            )

    def test_concurrency_configuration(self) -> None:
        text = _read_workflow_text()
        assert "container-security" in text
        assert re.search(r"cancel-in-progress:\s*true", text)


class TestContainerSecurityWorkflowJobsAndIntegrity:
    """Validate job structure, dependencies, artifact retention, and handoff integrity."""

    def test_job_dependency_graph(self) -> None:
        jobs = _extract_job_blocks(_read_workflow_text())
        assert "build" in jobs
        assert "scan" in jobs
        assert "publish" in jobs

        # scan depends on build
        assert re.search(r"needs:\s*\[build\]", jobs["scan"])

        # publish depends on both build and scan
        assert re.search(r"needs:\s*\[build,\s*scan\]", jobs["publish"])

    def test_publish_job_isolation_and_conditions(self) -> None:
        jobs = _extract_job_blocks(_read_workflow_text())
        publish_body = jobs["publish"]

        # Must run only on push to main
        assert re.search(r"if:\s*github\.event_name == 'push'\s*&&\s*github\.ref == 'refs/heads/main'", publish_body)

    def test_docker_hub_secrets_isolation(self) -> None:
        jobs = _extract_job_blocks(_read_workflow_text())

        for name, body in jobs.items():
            if "secrets.DOCKERHUB_" in body:
                assert name == "publish", (
                    f"Docker Hub secrets must never be exposed outside the publish job. Found in '{name}'."
                )

    def test_third_party_actions_pinned_to_full_sha(self) -> None:
        text = _read_workflow_text()
        uses_matches = re.findall(r"uses:\s*([\w\-]+/[\w\-]+)@([0-9a-fA-F]+)", text)
        assert len(uses_matches) >= 5, f"Expected multiple action references, found {len(uses_matches)}"

        for action_name, action_sha in uses_matches:
            assert SHA40_PATTERN.match(action_sha), (
                f"Action '{action_name}' must be pinned to 40-character commit SHA (got '{action_sha}')"
            )

    def test_grype_scan_and_validator_integration(self) -> None:
        jobs = _extract_job_blocks(_read_workflow_text())
        scan_body = jobs["scan"]

        # Step scanning with Grype
        assert "anchore/scan-action@" in scan_body
        assert 'output-format: "json"' in scan_body
        assert "fail-build: false" in scan_body
        assert 'output-file: "grype-report.json"' in scan_body

        # Step validating scan report
        assert "scripts/validate_container_scan.py" in scan_body
        assert "--report grype-report.json" in scan_body
        assert "--exceptions .github/security/container-exceptions.json" in scan_body
        assert "--scanner-status" in scan_body
        assert "--summary" in scan_body

    def test_report_artifact_retention_and_fail_safe(self) -> None:
        jobs = _extract_job_blocks(_read_workflow_text())
        scan_body = jobs["scan"]

        # Upload container scan report
        assert "name: container-scan-report" in scan_body
        assert "path: grype-report.json" in scan_body
        assert "retention-days: 7" in scan_body

        # Must have if: always() for report upload
        report_upload_match = re.search(
            r"- name: Upload container scan report artifact[\s\S]*?if:\s*always\(\)",
            scan_body,
        )
        assert report_upload_match is not None, "Report artifact upload must have if: always() to preserve report on failure"

    def test_image_archive_checksum_and_id_verification(self) -> None:
        jobs = _extract_job_blocks(_read_workflow_text())

        # Build job saves archive and calculates sha256sum
        build_body = jobs["build"]
        assert "docker save docvault-api:local -o docvault-api.tar" in build_body
        assert "sha256sum docvault-api.tar > docvault-api.tar.sha256" in build_body
        assert "build-image-id.txt" in build_body

        # Scan job verifies sha256sum and compares image ID
        scan_body = jobs["scan"]
        assert "sha256sum -c docvault-api.tar.sha256" in scan_body
        assert "docker load -i docvault-api.tar" in scan_body
        assert "EXPECTED_BUILD_ID" in scan_body
        assert "scanned-image-id.txt" in scan_body

        # Publish job verifies checksum, build ID, and scanned ID
        publish_body = jobs["publish"]
        assert "sha256sum -c docvault-api.tar.sha256" in publish_body
        assert "docker load -i docvault-api.tar" in publish_body
        assert "build-image-id.txt" in publish_body
        assert "scanned-image-id.txt" in publish_body
        assert "RepoDigests" in publish_body
        assert "iyedbnaissa/docvault-api" in publish_body
