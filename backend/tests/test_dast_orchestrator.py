"""Automated unit and regression tests for the DAST scan orchestrator.

Validates scripts/run_dast_scan.sh orchestration lifecycle, dependency checks,
ephemeral resource provisioning, bounded readiness verification, passive-only
ZAP execution safeguards, policy enforcement (High, Medium, Low/Info), report
preservation on failure, idempotent cleanup, and deterministic exit-code contracts.
"""

from __future__ import annotations

import contextlib
import http.server
import json
import os
import signal
import socketserver
import subprocess
import threading
import time
from collections.abc import Generator
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
ORCHESTRATOR_SCRIPT = REPO_ROOT / "scripts" / "run_dast_scan.sh"


class MockReadyHandler(http.server.BaseHTTPRequestHandler):
    """Minimal HTTP request handler responding 200 OK to /ready."""

    def do_GET(self) -> None:
        if self.path == "/ready":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status": "ready"}')
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format: str, *args: Any) -> None:
        # Suppress logging to keep pytest output clean
        pass


@contextlib.contextmanager
def ephemeral_ready_server() -> Generator[int, None, None]:
    """Start an ephemeral HTTP server on 127.0.0.1 serving /ready."""
    server = socketserver.TCPServer(("127.0.0.1", 0), MockReadyHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        server.shutdown()
        server.server_close()


def create_mock_docker(
    tmp_path: Path,
    build_exit: int = 0,
    compose_up_exit: int = 0,
    compose_down_exit: int = 0,
    record_file: Path | None = None,
) -> Path:
    """Create an executable mock docker script that tracks invocations and returns simulated codes."""
    mock_script = tmp_path / "mock_docker.sh"
    record_path = str(record_file) if record_file else ""
    content = f"""#!/usr/bin/env bash
if [[ -n "{record_path}" ]]; then
    echo "docker $*" >> "{record_path}"
fi

if [[ "$1" == "build" ]]; then
    exit {build_exit}
elif [[ "$1" == "compose" ]]; then
    for arg in "$@"; do
        if [[ "$arg" == "up" ]]; then
            exit {compose_up_exit}
        elif [[ "$arg" == "down" ]]; then
            exit {compose_down_exit}
        fi
    done
    exit 0
else
    exit 0
fi
"""
    mock_script.write_text(content, encoding="utf-8")
    mock_script.chmod(0o755)
    return mock_script


def build_mock_zap_cmd(
    report_json_path: Path,
    report_html_path: Path,
    report_data: dict[str, Any],
    scanner_exit: int = 0,
) -> str:
    """Build a bash command that writes mock ZAP report files and exits with scanner_exit."""
    report_json_str = json.dumps(report_data).replace('"', '\\"')
    return (
        f'mkdir -p "{report_json_path.parent}" && '
        f'echo "{report_json_str}" > "{report_json_path}" && '
        f'echo "<html><body>Mock ZAP Report</body></html>" > "{report_html_path}" && '
        f"exit {scanner_exit}"
    )


# ==============================================================================
# Dependency Verification and Startup Tests
# ==============================================================================


def test_missing_docker_dependency_fails_cleanly(tmp_path: Path) -> None:
    env = os.environ.copy()
    env["DOCKER_BIN"] = str(tmp_path / "non_existent_docker")
    proc = subprocess.run(
        [str(ORCHESTRATOR_SCRIPT), "--no-build"],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert proc.returncode == 2
    assert "Docker binary" in proc.stderr
    assert "is not available on PATH" in proc.stderr


def test_missing_compose_file_fails_cleanly(tmp_path: Path) -> None:
    mock_docker = create_mock_docker(tmp_path)
    env = os.environ.copy()
    env["DOCKER_BIN"] = str(mock_docker)
    env["COMPOSE_FILE"] = str(tmp_path / "non_existent_compose.yaml")
    proc = subprocess.run(
        [str(ORCHESTRATOR_SCRIPT), "--no-build"],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert proc.returncode == 2
    assert "Docker Compose file not found" in proc.stderr


def test_missing_exceptions_file_fails_cleanly(tmp_path: Path) -> None:
    mock_docker = create_mock_docker(tmp_path)
    env = os.environ.copy()
    env["DOCKER_BIN"] = str(mock_docker)
    env["DAST_EXCEPTIONS"] = str(tmp_path / "non_existent_exceptions.json")
    proc = subprocess.run(
        [str(ORCHESTRATOR_SCRIPT), "--no-build"],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert proc.returncode == 2
    assert "Exception register not found" in proc.stderr


# ==============================================================================
# Lifecycle Failures and Cleanup Tests
# ==============================================================================


def test_image_build_failure_exits_code_2(tmp_path: Path) -> None:
    mock_docker = create_mock_docker(tmp_path, build_exit=1)
    env = os.environ.copy()
    env["DOCKER_BIN"] = str(mock_docker)
    proc = subprocess.run(
        [str(ORCHESTRATOR_SCRIPT)],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert proc.returncode == 2
    assert "Docker build failed" in proc.stderr


def test_compose_startup_failure_cleans_up_and_exits_code_2(tmp_path: Path) -> None:
    docker_log = tmp_path / "docker_invocations.txt"
    mock_docker = create_mock_docker(tmp_path, compose_up_exit=1, record_file=docker_log)
    env = os.environ.copy()
    env["DOCKER_BIN"] = str(mock_docker)
    proc = subprocess.run(
        [str(ORCHESTRATOR_SCRIPT), "--no-build"],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert proc.returncode == 2
    assert "Docker Compose stack failed to start" in proc.stderr
    assert "Cleaning up isolated DAST containers" in proc.stdout

    # Verify compose down was executed in cleanup
    assert docker_log.is_file()
    docker_calls = docker_log.read_text(encoding="utf-8")
    assert "compose" in docker_calls
    assert "down" in docker_calls


def test_readiness_timeout_fails_cleanly(tmp_path: Path) -> None:
    docker_log = tmp_path / "docker_invocations.txt"
    mock_docker = create_mock_docker(tmp_path, record_file=docker_log)
    env = os.environ.copy()
    env["DOCKER_BIN"] = str(mock_docker)
    env["DAST_READINESS_RETRIES"] = "2"
    # Point to an unallocated port where no server is listening
    env["DAST_PORT"] = "49999"

    proc = subprocess.run(
        [str(ORCHESTRATOR_SCRIPT), "--no-build"],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert proc.returncode == 2
    assert "readiness check failed" in proc.stderr
    assert "Cleaning up isolated DAST containers" in proc.stdout


# ==============================================================================
# ZAP Scanner Failures and Report Preservation
# ==============================================================================


def test_zap_scanner_execution_failure_exits_code_2(tmp_path: Path) -> None:
    mock_docker = create_mock_docker(tmp_path)
    report_json = tmp_path / "zap-report.json"
    report_html = tmp_path / "zap-report.html"

    # Scanner fails with exit code 2 (e.g. fatal scan error)
    clean_report = {"@version": "2.14.0", "site": []}
    zap_cmd = build_mock_zap_cmd(report_json, report_html, clean_report, scanner_exit=2)

    with ephemeral_ready_server() as port:
        env = os.environ.copy()
        env["DOCKER_BIN"] = str(mock_docker)
        env["DAST_PORT"] = str(port)
        env["DAST_REPORT_DIR"] = str(tmp_path)
        env["ZAP_CMD"] = zap_cmd

        proc = subprocess.run(
            [str(ORCHESTRATOR_SCRIPT), "--no-build"],
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )
        assert proc.returncode == 2
        assert "ZAP scanner exited with non-zero status code: 2" in proc.stderr
        assert "DAST operational or configuration failure (exit code 2)" in proc.stderr

        # Verify reports are preserved even when scanner failed
        assert report_json.is_file()
        assert report_html.is_file()


def test_validator_operational_failure_on_malformed_report(tmp_path: Path) -> None:
    mock_docker = create_mock_docker(tmp_path)
    report_json = tmp_path / "zap-report.json"
    report_html = tmp_path / "zap-report.html"

    # Malformed report content
    zap_cmd = (
        f'echo "{{\\"broken\\": json" > "{report_json}" && '
        f'echo "<html>broken</html>" > "{report_html}"'
    )

    with ephemeral_ready_server() as port:
        env = os.environ.copy()
        env["DOCKER_BIN"] = str(mock_docker)
        env["DAST_PORT"] = str(port)
        env["DAST_REPORT_DIR"] = str(tmp_path)
        env["ZAP_CMD"] = zap_cmd

        proc = subprocess.run(
            [str(ORCHESTRATOR_SCRIPT), "--no-build"],
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )
        assert proc.returncode == 2
        assert "DAST operational or configuration failure (exit code 2)" in proc.stderr
        # Verify reports preserved
        assert report_json.is_file()
        assert report_html.is_file()


# ==============================================================================
# Security Policy Enforcement Tests
# ==============================================================================


def test_unapproved_high_severity_finding_fails_policy(tmp_path: Path) -> None:
    """Policy Behavior 1: Unapproved High finding must fail the policy gate (exit code 1)."""
    mock_docker = create_mock_docker(tmp_path)
    report_json = tmp_path / "zap-report.json"
    report_html = tmp_path / "zap-report.html"

    high_finding_report = {
        "@version": "2.14.0",
        "site": [
            {
                "@name": "http://127.0.0.1:8002",
                "alerts": [
                    {
                        "pluginid": "40018",
                        "alert": "SQL Injection",
                        "riskdesc": "High (High)",
                        "instances": [
                            {"uri": "http://127.0.0.1:8002/api/v1/users/lookup", "method": "GET"}
                        ],
                    }
                ],
            }
        ],
    }
    zap_cmd = build_mock_zap_cmd(report_json, report_html, high_finding_report)

    with ephemeral_ready_server() as port:
        env = os.environ.copy()
        env["DOCKER_BIN"] = str(mock_docker)
        env["DAST_PORT"] = str(port)
        env["DAST_REPORT_DIR"] = str(tmp_path)
        env["ZAP_CMD"] = zap_cmd

        proc = subprocess.run(
            [str(ORCHESTRATOR_SCRIPT), "--no-build"],
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )
        assert proc.returncode == 1
        assert "DAST policy violation detected (exit code 1)" in proc.stderr
        assert "1 unapproved High/Medium finding(s)" in proc.stdout
        assert "SQL Injection" in proc.stdout

        # Verify reports are preserved on policy violation
        assert report_json.is_file()
        assert report_html.is_file()


def test_unapproved_medium_severity_finding_fails_policy(tmp_path: Path) -> None:
    """Policy Behavior 2A: Unapproved Medium finding must fail the policy gate (exit code 1)."""
    mock_docker = create_mock_docker(tmp_path)
    report_json = tmp_path / "zap-report.json"
    report_html = tmp_path / "zap-report.html"

    medium_finding_report = {
        "@version": "2.14.0",
        "site": [
            {
                "@name": "http://127.0.0.1:8002",
                "alerts": [
                    {
                        "pluginid": "10038",
                        "alert": "Content Security Policy (CSP) Header Not Set",
                        "riskdesc": "Medium (High)",
                        "instances": [
                            {"uri": "http://127.0.0.1:8002/docs", "method": "GET"}
                        ],
                    }
                ],
            }
        ],
    }
    zap_cmd = build_mock_zap_cmd(report_json, report_html, medium_finding_report)

    with ephemeral_ready_server() as port:
        env = os.environ.copy()
        env["DOCKER_BIN"] = str(mock_docker)
        env["DAST_PORT"] = str(port)
        env["DAST_REPORT_DIR"] = str(tmp_path)
        env["ZAP_CMD"] = zap_cmd

        proc = subprocess.run(
            [str(ORCHESTRATOR_SCRIPT), "--no-build"],
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )
        assert proc.returncode == 1
        assert "DAST policy violation detected (exit code 1)" in proc.stderr
        assert "1 unapproved High/Medium finding(s)" in proc.stdout


def test_approved_medium_exception_passes_policy(tmp_path: Path) -> None:
    """Policy Behavior 2B: Approved, active, narrowly scoped exception suppresses Medium finding (exit code 0)."""
    mock_docker = create_mock_docker(tmp_path)
    report_json = tmp_path / "zap-report.json"
    report_html = tmp_path / "zap-report.html"
    exceptions_json = tmp_path / "dast-exceptions.json"

    # Medium finding on /docs
    medium_finding_report = {
        "@version": "2.14.0",
        "site": [
            {
                "@name": "http://127.0.0.1:8002",
                "alerts": [
                    {
                        "pluginid": "10038",
                        "alert": "Content Security Policy (CSP) Header Not Set",
                        "riskdesc": "Medium (High)",
                        "instances": [
                            {"uri": "http://127.0.0.1:8002/docs", "method": "GET"}
                        ],
                    }
                ],
            }
        ],
    }
    # Targeted exception approving Rule 10038 on /docs
    exceptions_data = {
        "version": "1.0",
        "exceptions": [
            {
                "zap_rule_id": "10038",
                "alert_name": "Content Security Policy (CSP) Header Not Set",
                "target_url_pattern": r"^http://127\.0\.0\.1:[0-9]+/docs.*",
                "severity": "MEDIUM",
                "reason": "Swagger UI documentation intentionally permits inline assets.",
                "expires_at": "2027-02-09",
            }
        ],
    }
    exceptions_json.write_text(json.dumps(exceptions_data), encoding="utf-8")
    zap_cmd = build_mock_zap_cmd(report_json, report_html, medium_finding_report)

    with ephemeral_ready_server() as port:
        env = os.environ.copy()
        env["DOCKER_BIN"] = str(mock_docker)
        env["DAST_PORT"] = str(port)
        env["DAST_REPORT_DIR"] = str(tmp_path)
        env["DAST_EXCEPTIONS"] = str(exceptions_json)
        env["ZAP_CMD"] = zap_cmd

        proc = subprocess.run(
            [str(ORCHESTRATOR_SCRIPT), "--no-build"],
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )
        assert proc.returncode == 0
        assert "DAST scan passed policy validation" in proc.stdout
        assert "Approved active exceptions:          1" in proc.stdout
        assert "Unapproved High / Medium findings:    0" in proc.stdout


def test_low_and_informational_findings_monitored_non_blocking(tmp_path: Path) -> None:
    """Policy Behavior 2C: Low and Informational findings are monitored and non-blocking (exit code 0)."""
    mock_docker = create_mock_docker(tmp_path)
    report_json = tmp_path / "zap-report.json"
    report_html = tmp_path / "zap-report.html"

    low_info_report = {
        "@version": "2.14.0",
        "site": [
            {
                "@name": "http://127.0.0.1:8002",
                "alerts": [
                    {
                        "pluginid": "10015",
                        "alert": "Incomplete or No Cache-control Header",
                        "riskdesc": "Low (Low)",
                        "instances": [{"uri": "http://127.0.0.1:8002/favicon.ico", "method": "GET"}],
                    },
                    {
                        "pluginid": "10104",
                        "alert": "User Controllable HTML Element Attribute",
                        "riskdesc": "Informational (Informational)",
                        "instances": [{"uri": "http://127.0.0.1:8002/", "method": "GET"}],
                    },
                ],
            }
        ],
    }
    zap_cmd = build_mock_zap_cmd(report_json, report_html, low_info_report)

    with ephemeral_ready_server() as port:
        env = os.environ.copy()
        env["DOCKER_BIN"] = str(mock_docker)
        env["DAST_PORT"] = str(port)
        env["DAST_REPORT_DIR"] = str(tmp_path)
        env["ZAP_CMD"] = zap_cmd

        proc = subprocess.run(
            [str(ORCHESTRATOR_SCRIPT), "--no-build"],
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )
        assert proc.returncode == 0
        assert "DAST scan passed policy validation" in proc.stdout
        assert "Monitored (Low / Informational):     2" in proc.stdout
        assert "Unapproved High / Medium findings:    0" in proc.stdout


# ==============================================================================
# End-to-End Successful Orchestration & Signal Cleanup Tests
# ==============================================================================


def test_successful_orchestration_flow(tmp_path: Path) -> None:
    docker_log = tmp_path / "docker_invocations.txt"
    mock_docker = create_mock_docker(tmp_path, record_file=docker_log)
    report_json = tmp_path / "zap-report.json"
    report_html = tmp_path / "zap-report.html"
    summary_file = tmp_path / "step_summary.md"

    clean_report = {"@version": "2.14.0", "site": []}
    zap_cmd = build_mock_zap_cmd(report_json, report_html, clean_report)

    with ephemeral_ready_server() as port:
        env = os.environ.copy()
        env["DOCKER_BIN"] = str(mock_docker)
        env["DAST_PORT"] = str(port)
        env["DAST_REPORT_DIR"] = str(tmp_path)
        env["GITHUB_STEP_SUMMARY"] = str(summary_file)
        env["ZAP_CMD"] = zap_cmd

        proc = subprocess.run(
            [str(ORCHESTRATOR_SCRIPT), "--no-build"],
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )
        assert proc.returncode == 0
        assert "DAST scan passed policy validation" in proc.stdout

        # Verify artifacts
        assert report_json.is_file()
        assert report_html.is_file()
        assert summary_file.is_file()
        summary_text = summary_file.read_text(encoding="utf-8")
        assert "OWASP ZAP DAST Vulnerability Gate Report" in summary_text

        # Verify docker compose down was called in cleanup
        docker_calls = docker_log.read_text(encoding="utf-8")
        assert "compose" in docker_calls
        assert "down" in docker_calls


def test_orchestrator_signal_handling_cleanup(tmp_path: Path) -> None:
    """Verify that SIGTERM triggers idempotent cleanup and returns non-zero termination code."""
    docker_log = tmp_path / "docker_invocations.txt"
    mock_docker = create_mock_docker(tmp_path, record_file=docker_log)

    # ZAP command sleeps so we can deliver a signal while running
    zap_cmd = "sleep 10"

    with ephemeral_ready_server() as port:
        env = os.environ.copy()
        env["DOCKER_BIN"] = str(mock_docker)
        env["DAST_PORT"] = str(port)
        env["DAST_REPORT_DIR"] = str(tmp_path)
        env["ZAP_CMD"] = zap_cmd

        proc = subprocess.Popen(
            [str(ORCHESTRATOR_SCRIPT), "--no-build"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )

        # Give it a moment to boot and enter the ZAP scan block
        time.sleep(1.5)
        # Send SIGTERM
        proc.send_signal(signal.SIGTERM)
        stdout, _stderr = proc.communicate(timeout=5)

        # On SIGTERM, trap 'exit 143' TERM executes
        assert proc.returncode == 143
        assert "Cleaning up isolated DAST containers" in stdout

        # Verify cleanup ran compose down
        docker_calls = docker_log.read_text(encoding="utf-8")
        assert "compose" in docker_calls
        assert "down" in docker_calls


def test_orchestrator_sigint_handling_cleanup(tmp_path: Path) -> None:
    """Verify that SIGINT (interruption) triggers idempotent cleanup and returns non-zero code 130."""
    docker_log = tmp_path / "docker_invocations.txt"
    mock_docker = create_mock_docker(tmp_path, record_file=docker_log)

    zap_cmd = "sleep 10"

    with ephemeral_ready_server() as port:
        env = os.environ.copy()
        env["DOCKER_BIN"] = str(mock_docker)
        env["DAST_PORT"] = str(port)
        env["DAST_REPORT_DIR"] = str(tmp_path)
        env["ZAP_CMD"] = zap_cmd

        proc = subprocess.Popen(
            [str(ORCHESTRATOR_SCRIPT), "--no-build"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )

        time.sleep(1.5)
        # Send SIGINT
        proc.send_signal(signal.SIGINT)
        stdout, _stderr = proc.communicate(timeout=5)

        # On SIGINT, trap 'exit 130' INT executes
        assert proc.returncode == 130
        assert "Cleaning up isolated DAST containers" in stdout

        # Verify cleanup ran compose down
        docker_calls = docker_log.read_text(encoding="utf-8")
        assert "compose" in docker_calls
        assert "down" in docker_calls
