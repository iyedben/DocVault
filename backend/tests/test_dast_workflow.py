"""Automated tests for the DAST Dynamic Security Scan GitHub Actions workflow.

Validates .github/workflows/dast.yml structure, triggers, permissions, exact check name,
action commit SHA pinning, orchestrator invocation without duplicated scan logic,
safe artifact preservation on all outcomes, unique artifact naming, and absence
of secrets, write permissions, or deployment operations.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "dast.yml"
SHA40_PATTERN = re.compile(r"^[0-9a-f]{40}$")


def _read_workflow_text() -> str:
    assert WORKFLOW_PATH.is_file(), f"Workflow file not found: {WORKFLOW_PATH}"
    return WORKFLOW_PATH.read_text(encoding="utf-8")


class TestDASTWorkflowSyntaxAndTriggers:
    """Validate YAML syntax, triggers, branches, and expression validity."""

    def test_workflow_file_exists_and_yaml_syntax_valid(self) -> None:
        """Validate that the workflow exists and parses cleanly via Python YAML engine."""
        text = _read_workflow_text()
        assert len(text) > 0

        # Validate with python3 YAML parser via subprocess
        proc = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "import pathlib, sys\n"
                    "try:\n"
                    "    import yaml\n"
                    "    yaml.safe_load(open(sys.argv[1]))\n"
                    "    print('YAML_VALID')\n"
                    "except ImportError:\n"
                    "    print('YAML_SKIPPED')\n"
                ),
                str(WORKFLOW_PATH),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0
        assert "YAML_VALID" in proc.stdout or "YAML_SKIPPED" in proc.stdout

    def test_triggers_and_branch_filters(self) -> None:
        """Verify triggers for push, pull_request, and workflow_dispatch."""
        text = _read_workflow_text()

        # Push branch triggers
        assert re.search(r"push:[\s\S]*?branches:[\s\S]*?-\s*main", text), "Push must trigger on main"
        assert re.search(r"push:[\s\S]*?branches:[\s\S]*?-\s*feature/dast-integration", text), (
            "Push must trigger on feature/dast-integration"
        )

        # Pull request triggers (strictly targeting main)
        assert re.search(r"pull_request:[\s\S]*?branches:[\s\S]*?-\s*main", text), (
            "Pull request must trigger targeting main"
        )

        # Manual dispatch
        assert re.search(r"workflow_dispatch:\s*", text), "workflow_dispatch must be configured"

        # Safe contribution boundary: prohibit pull_request_target
        assert "pull_request_target" not in text, "Workflow must never use dangerous pull_request_target trigger"

    def test_concurrency_configuration(self) -> None:
        """Verify concurrency group and cancel-in-progress settings."""
        text = _read_workflow_text()
        assert re.search(r"concurrency:[\s\S]*?group:\s*dast-\${{\s*github\.workflow\s*}}-\${{\s*github\.ref\s*}}", text)
        assert re.search(r"cancel-in-progress:\s*true", text)

    def test_expression_syntax_validity(self) -> None:
        """Verify all GitHub Actions expressions have balanced braces and valid contexts."""
        text = _read_workflow_text()
        raw_expressions = re.findall(r"\${{\s*([^}]+)\s*}}", text)
        assert len(raw_expressions) >= 3, f"Expected at least 3 expressions, found {len(raw_expressions)}"

        valid_contexts = ("github.workflow", "github.ref", "github.run_id", "github.run_attempt")
        for expr in raw_expressions:
            cleaned = expr.strip()
            assert any(cleaned.startswith(ctx) for ctx in valid_contexts), (
                f"Unexpected or invalid GitHub Actions expression: {cleaned}"
            )


class TestDASTWorkflowPermissionsAndSafety:
    """Validate least-privilege security controls and absence of secrets."""

    def test_least_privilege_permissions(self) -> None:
        """Ensure minimal read-only permissions at workflow and job levels."""
        text = _read_workflow_text()

        # Top-level permissions
        top_perms = re.search(r"^permissions:\s*\n\s*contents:\s*read", text, re.MULTILINE)
        assert top_perms is not None, "Workflow must declare contents: read at top level"

        # Job-level permissions
        job_perms = re.search(r"jobs:[\s\S]*?permissions:\s*\n\s*contents:\s*read", text)
        assert job_perms is not None, "Job must declare permissions: contents: read"

        # Ensure zero write permissions
        assert ": write" not in text, "Workflow must never declare write permissions"

    def test_absence_of_secrets(self) -> None:
        """Verify workflow has zero access to repository or organization secrets."""
        text = _read_workflow_text()
        assert "secrets." not in text, "Workflow must not reference any secrets"
        assert "${{ secrets" not in text, "Workflow must not evaluate secrets context"

    def test_no_docker_hub_or_deployment_operations(self) -> None:
        """Verify workflow does not publish Docker images or perform deployment tasks."""
        text = _read_workflow_text()
        assert "docker login" not in text.lower()
        assert "docker push" not in text.lower()
        assert "docker/login-action" not in text
        assert "docker/build-push-action" not in text
        assert "deploy" not in text.lower()


class TestDASTWorkflowJobAndStepIntegrity:
    """Validate check name, pinned actions, orchestrator invocation, and artifact upload."""

    def test_exact_check_run_name(self) -> None:
        """Job must specify the exact required check name for ruleset integration."""
        text = _read_workflow_text()
        assert re.search(
            r"name:\s*OWASP ZAP Dynamic Security Scan",
            text,
        ), "Job must have exact name: 'OWASP ZAP Dynamic Security Scan'"

    def test_runner_and_bounded_timeout(self) -> None:
        """Verify GitHub-hosted Linux runner and bounded execution timeout."""
        text = _read_workflow_text()
        assert re.search(r"runs-on:\s*ubuntu-latest", text), "Job must run on ubuntu-latest"
        match = re.search(r"timeout-minutes:\s*(\d+)", text)
        assert match is not None, "Job must have timeout-minutes configured"
        timeout_val = int(match.group(1))
        assert 1 <= timeout_val <= 30, f"Job timeout must be bounded (got {timeout_val}m)"

    def test_third_party_actions_pinned_to_full_sha(self) -> None:
        """All third-party action invocations must be pinned to 40-character commit SHAs."""
        text = _read_workflow_text()
        uses_matches = re.findall(r"uses:\s*([\w\-]+/[\w\-]+)@([0-9a-fA-F]+)", text)
        assert len(uses_matches) >= 3, f"Expected at least 3 pinned action invocations, found {len(uses_matches)}"

        for action_name, action_sha in uses_matches:
            assert SHA40_PATTERN.match(action_sha), (
                f"Action '{action_name}' must be pinned to 40-char commit SHA (got '{action_sha}')"
            )

    def test_python_runtime_setup(self) -> None:
        """Verify setup-python configured for Python 3.13."""
        text = _read_workflow_text()
        assert "actions/setup-python" in text
        assert re.search(r"python-version:\s*['\"]?3\.13['\"]?", text), "Must specify Python 3.13"

    def test_invokes_existing_orchestrator_without_duplication(self) -> None:
        """Verify workflow invokes scripts/run_dast_scan.sh and avoids duplicating scan logic in YAML."""
        text = _read_workflow_text()
        assert re.search(r"run:\s*\./scripts/run_dast_scan\.sh", text) or re.search(
            r"run:\s*bash\s+scripts/run_dast_scan\.sh", text
        ), "Workflow must execute scripts/run_dast_scan.sh"

        # Verify scan logic is not duplicated in YAML
        assert "zap-baseline.py" not in text, "Workflow YAML must not duplicate zap-baseline.py invocation"
        assert "compose.e2e.yaml" not in text, "Workflow YAML must not duplicate compose invocations"
        assert "validate_dast_scan.py" not in text, "Workflow YAML must not duplicate validator invocation"

    def test_artifact_upload_preservation_and_retention(self) -> None:
        """Verify reports are uploaded on both success and failure with unique naming and bounded retention."""
        text = _read_workflow_text()
        upload_match = re.search(
            r"- name:\s*Upload DAST scan reports[\s\S]*?uses:\s*actions/upload-artifact@([0-9a-fA-F]+)[\s\S]*?with:([\s\S]*?)(?=\n\s*-|\Z)",
            text,
        )
        assert upload_match is not None, "Upload DAST scan reports step must be defined"
        step_body = upload_match.group(0)

        # Upload runs on both success and failure
        assert re.search(r"if:\s*always\(\)", step_body), "Artifact upload must run with 'if: always()'"

        # Unique naming with run_id and run_attempt
        assert re.search(r"name:.*github\.run_id.*github\.run_attempt", step_body), (
            "Artifact name must incorporate both github.run_id and github.run_attempt"
        )

        # File paths
        assert "zap-report.html" in step_body, "Artifact path must include zap-report.html"
        assert "zap-report.json" in step_body, "Artifact path must include zap-report.json"

        # Bounded retention
        retention_match = re.search(r"retention-days:\s*(\d+)", step_body)
        assert retention_match is not None, "Must configure retention-days"
        assert int(retention_match.group(1)) <= 7, "Retention days must be bounded to at most 7 days"

        # Do not silently ignore missing reports
        assert "if-no-files-found: ignore" not in step_body, "Must not silently ignore missing reports"
        assert re.search(r"if-no-files-found:\s*error", step_body), "Must set if-no-files-found: error"
