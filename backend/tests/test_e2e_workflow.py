"""Automated tests for the Browser E2E Testing GitHub Actions workflow.

Validates .github/workflows/e2e.yml structure, triggers, concurrency,
permissions, action SHA pinning, Playwright browser setup, container build,
and test artifact retention.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "e2e.yml"
SHA40_PATTERN = re.compile(r"^[0-9a-f]{40}$")


def _read_workflow_text() -> str:
    assert WORKFLOW_PATH.is_file(), f"Workflow file not found: {WORKFLOW_PATH}"
    return WORKFLOW_PATH.read_text(encoding="utf-8")


class TestE2EWorkflowTriggersAndPolicy:
    """Validate triggers, permissions, and concurrency controls."""

    def test_workflow_file_exists_and_named(self) -> None:
        text = _read_workflow_text()
        assert re.search(r"^name:\s*Browser E2E Testing", text, re.MULTILINE)

    def test_triggers_and_branch_filters(self) -> None:
        text = _read_workflow_text()

        # Push branch triggers
        assert re.search(r"push:[\s\S]*?branches:[\s\S]*?-\s*main", text), "Push must trigger on main"
        assert re.search(r"push:[\s\S]*?branches:[\s\S]*?-\s*'?feature/\*\*'?", text), (
            "Push must trigger on feature/**"
        )

        # Pull request triggers
        assert re.search(r"pull_request:[\s\S]*?branches:[\s\S]*?-\s*main", text), (
            "Pull request must trigger targeting main"
        )
        assert re.search(r"pull_request:[\s\S]*?branches:[\s\S]*?-\s*'?feature/\*\*'?", text), (
            "Pull request must trigger targeting feature/**"
        )

        # Manual dispatch
        assert re.search(r"workflow_dispatch:\s*", text), "workflow_dispatch must be present"

    def test_least_privilege_permissions(self) -> None:
        text = _read_workflow_text()

        # Top-level permissions
        top_perms = re.search(r"^permissions:\s*\n\s*contents:\s*read", text, re.MULTILINE)
        assert top_perms is not None, "Workflow must declare contents: read at top level"

        # Job-level permissions
        job_perms = re.search(r"jobs:[\s\S]*?permissions:\s*\n\s*contents:\s*read", text)
        assert job_perms is not None, "Job must declare permissions: contents: read"

    def test_concurrency_configuration(self) -> None:
        text = _read_workflow_text()
        assert "e2e" in text
        assert re.search(r"cancel-in-progress:\s*true", text)


class TestE2EWorkflowExecutionAndIntegrity:
    """Validate action pins, dependencies, browser setup, and artifact preservation."""

    def test_third_party_actions_pinned_to_full_sha(self) -> None:
        text = _read_workflow_text()
        uses_matches = re.findall(r"uses:\s*([\w\-]+/[\w\-]+)@([0-9a-fA-F]+)", text)
        assert len(uses_matches) >= 3, f"Expected at least 3 action references, found {len(uses_matches)}"

        for action_name, action_sha in uses_matches:
            assert SHA40_PATTERN.match(action_sha), (
                f"Action '{action_name}' must be pinned to 40-character commit SHA (got '{action_sha}')"
            )

    def test_e2e_dependencies_installation_step(self) -> None:
        text = _read_workflow_text()
        assert "-r requirements-e2e.txt" in text, (
            "Workflow must install E2E dependencies from requirements-e2e.txt"
        )
        assert "requirements-e2e.txt" in text

    def test_playwright_browser_installation_step(self) -> None:
        text = _read_workflow_text()
        assert "python -m playwright install --with-deps chromium" in text, (
            "Workflow must install Playwright chromium browser and OS system dependencies"
        )

    def test_container_image_build_step(self) -> None:
        text = _read_workflow_text()
        assert "docker build -t docvault-api:local -f backend/Dockerfile ." in text, (
            "Workflow must build docvault-api:local image before running tests"
        )

    def test_e2e_runner_script_execution(self) -> None:
        text = _read_workflow_text()
        assert "./scripts/run_e2e_tests.sh backend/tests/e2e" in text, (
            "Workflow must execute run_e2e_tests.sh targeting backend/tests/e2e"
        )
        assert "--tracing=retain-on-failure" in text
        assert "--screenshot=only-on-failure" in text

    def test_artifact_retention_and_fail_safe(self) -> None:
        text = _read_workflow_text()
        assert "name: playwright-e2e-artifacts" in text
        assert "path: test-results/" in text
        assert "retention-days: 7" in text
        assert re.search(r"- name: Upload Playwright test artifacts[\s\S]*?if:\s*always\(\)", text), (
            "Artifact upload must specify if: always() to preserve failure diagnostics"
        )
