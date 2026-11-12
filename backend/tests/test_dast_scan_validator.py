"""Unit and integration tests for the OWASP ZAP DAST scan validator.

Validates ZAP JSON report parsing, severity policy enforcement, DAST exception
register semantics, targeted endpoint pattern matching, rejection of blanket
suppressions, rejection of expired and duplicate exceptions, GitHub Step Summary
generation, and deterministic exit-code contracts.
"""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# Import validator module directly from scripts/
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import validate_dast_scan as vds


def build_zap_instance(
    uri: str = "http://127.0.0.1:8002/",
    method: str = "GET",
    param: str = "",
) -> dict[str, Any]:
    """Helper to create a realistic ZAP alert instance."""
    return {
        "uri": uri,
        "method": method,
        "param": param,
        "attack": "",
        "evidence": "",
    }


def build_zap_alert(
    rule_id: str = "10038",
    name: str = "Content Security Policy (CSP) Header Not Set",
    severity: str = "Medium",
    instances: list[dict[str, Any]] | None = None,
    uri: str | None = None,
    solution: str = "Ensure CSP header is properly set",
    cweid: str = "693",
) -> dict[str, Any]:
    """Helper to create a realistic ZAP alert object."""
    alert_obj: dict[str, Any] = {
        "pluginid": str(rule_id),
        "alertRef": str(rule_id),
        "alert": name,
        "name": name,
        "riskdesc": f"{severity} (High)",
        "desc": f"Description for {name}",
        "solution": solution,
        "cweid": cweid,
        "wascid": "15",
    }
    if instances is not None:
        alert_obj["instances"] = instances
    elif uri is not None:
        alert_obj["uri"] = uri
        alert_obj["method"] = "GET"
    else:
        alert_obj["instances"] = [build_zap_instance()]
    return alert_obj


def build_zap_report(
    site_url: str = "http://127.0.0.1:8002",
    alerts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Helper to create a standard ZAP report JSON root object."""
    return {
        "@version": "2.14.0",
        "@generated": "Thu, 12 Nov 2026 12:00:00",
        "site": [
            {
                "@name": site_url,
                "@host": "127.0.0.1",
                "@port": "8002",
                "@ssl": "false",
                "alerts": alerts or [],
            }
        ],
    }


def build_exception_entry(
    rule_id: str = "10038",
    name: str = "Content Security Policy (CSP) Header Not Set",
    pattern: str = r"^http://127\.0\.0\.1:8002/docs.*",
    severity: str = "MEDIUM",
    reason: str = "Swagger UI documentation allows inline scripts under CSP_DOCS.",
    expires_at: str = "2027-02-09",
) -> dict[str, Any]:
    """Helper to create a valid DAST exception entry."""
    return {
        "zap_rule_id": str(rule_id),
        "alert_name": name,
        "target_url_pattern": pattern,
        "severity": severity,
        "reason": reason,
        "expires_at": expires_at,
    }


def build_exception_register(
    exceptions: list[dict[str, Any]] | None = None,
    version: str = "1.0",
) -> dict[str, Any]:
    """Helper to create a full exception register object."""
    return {
        "version": version,
        "exceptions": exceptions or [],
    }


def run_validator_cli(
    report_path: Path,
    exceptions_path: Path,
    summary_path: Path | None = None,
    scanner_status: int = 0,
) -> tuple[int, str, str]:
    """Run validate_dast_scan.py CLI via subprocess and return (exit_code, stdout, stderr)."""
    validator_path = Path(__file__).resolve().parents[2] / "scripts" / "validate_dast_scan.py"
    cmd = [
        sys.executable,
        str(validator_path),
        "--report",
        str(report_path),
        "--exceptions",
        str(exceptions_path),
        "--scanner-status",
        str(scanner_status),
    ]
    if summary_path is not None:
        cmd.extend(["--summary", str(summary_path)])

    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    return proc.returncode, proc.stdout, proc.stderr


# ==============================================================================
# Helper Parsing and Date Semantics Unit Tests
# ==============================================================================


def test_parse_canonical_date_valid() -> None:
    dt = vds.parse_canonical_date("2027-02-09")
    assert dt is not None
    assert dt.year == 2027
    assert dt.month == 2
    assert dt.day == 9
    assert dt.tzinfo == UTC


def test_parse_canonical_date_invalid() -> None:
    assert vds.parse_canonical_date("2027/02/09") is None
    assert vds.parse_canonical_date("09-02-2027") is None
    assert vds.parse_canonical_date("2027-02-31") is None
    assert vds.parse_canonical_date("invalid") is None
    assert vds.parse_canonical_date(12345) is None  # type: ignore[arg-type]


def test_is_exception_active_semantics() -> None:
    now_utc = datetime(2026, 11, 12, 12, 0, 0, tzinfo=UTC)

    # Active future date
    is_active, msg = vds.is_exception_active("2027-02-09", now_utc)
    assert is_active is True
    assert msg == "Active"

    # Expired past date
    is_active, msg = vds.is_exception_active("2026-11-11", now_utc)
    assert is_active is False
    assert "expired on 2026-11-11" in msg

    # Same calendar day (active through 23:59:59 UTC)
    same_day_now = datetime(2026, 11, 12, 10, 0, 0, tzinfo=UTC)
    is_active, msg = vds.is_exception_active("2026-11-12", same_day_now)
    assert is_active is True

    # Same calendar day just after midnight (expired)
    next_day_now = datetime(2026, 11, 13, 0, 0, 1, tzinfo=UTC)
    is_active, msg = vds.is_exception_active("2026-11-12", next_day_now)
    assert is_active is False


def test_is_blanket_suppression_detection() -> None:
    # Explicit blanket patterns must return True
    assert vds.is_blanket_suppression(".*") is True
    assert vds.is_blanket_suppression("^.*$") is True
    assert vds.is_blanket_suppression(".+") is True
    assert vds.is_blanket_suppression("*") is True
    assert vds.is_blanket_suppression("") is True
    assert vds.is_blanket_suppression("^http://127.0.0.1:8002/.*$") is True
    assert vds.is_blanket_suppression("http://127.0.0.1:8002/.*") is True
    assert vds.is_blanket_suppression("https://example.com/.*") is True

    # Targeted patterns must return False
    assert vds.is_blanket_suppression(r"^http://127\.0\.0\.1:8002/docs.*") is False
    assert vds.is_blanket_suppression("/api/v1/auth/login") is False
    assert vds.is_blanket_suppression(r"^/ready$") is False
    assert vds.is_blanket_suppression(r"/static/vendor/.*") is False


def test_normalize_severity_mapping() -> None:
    # Primary strings
    assert vds.normalize_severity("High (Medium)") == "HIGH"
    assert vds.normalize_severity("Medium (Low)") == "MEDIUM"
    assert vds.normalize_severity("Low") == "LOW"
    assert vds.normalize_severity("Informational (High)") == "INFORMATIONAL"
    assert vds.normalize_severity("Info") == "INFORMATIONAL"
    assert vds.normalize_severity("Critical") == "CRITICAL"

    # Numeric codes
    assert vds.normalize_severity(3) == "HIGH"
    assert vds.normalize_severity("3") == "HIGH"
    assert vds.normalize_severity(2) == "MEDIUM"
    assert vds.normalize_severity(1) == "LOW"
    assert vds.normalize_severity(0) == "INFORMATIONAL"

    # Invalid / unknown
    import pytest

    with pytest.raises(ValueError, match="Unknown or invalid severity"):
        vds.normalize_severity("EXTREME")

    with pytest.raises(ValueError, match="Unknown or invalid severity"):
        vds.normalize_severity("UNKNOWN")

    with pytest.raises(ValueError, match="Severity is missing"):
        vds.normalize_severity(None)


# ==============================================================================
# End-to-End Validation CLI & Policy Tests
# ==============================================================================


def test_clean_report_passes(tmp_path: Path) -> None:
    report_file = tmp_path / "zap-clean.json"
    exceptions_file = tmp_path / "dast-exceptions.json"

    report_file.write_text(json.dumps(build_zap_report(alerts=[])), encoding="utf-8")
    exceptions_file.write_text(json.dumps(build_exception_register([])), encoding="utf-8")

    code, stdout, _ = run_validator_cli(report_file, exceptions_file)
    assert code == vds.EXIT_SUCCESS
    assert "Policy compliant" in stdout
    assert "Total findings analyzed:              0" in stdout


def test_unapproved_high_finding_fails(tmp_path: Path) -> None:
    report_file = tmp_path / "zap-high.json"
    exceptions_file = tmp_path / "dast-exceptions.json"

    alert = build_zap_alert(
        rule_id="40018",
        name="SQL Injection",
        severity="High",
        instances=[build_zap_instance(uri="http://127.0.0.1:8002/api/v1/users/lookup")],
    )
    report_file.write_text(json.dumps(build_zap_report(alerts=[alert])), encoding="utf-8")
    exceptions_file.write_text(json.dumps(build_exception_register([])), encoding="utf-8")

    code, stdout, _ = run_validator_cli(report_file, exceptions_file)
    assert code == vds.EXIT_POLICY_VIOLATION
    assert "Policy violation: 1 unapproved High/Medium finding(s)" in stdout
    assert "[HIGH] Rule 40018: SQL Injection" in stdout


def test_unapproved_medium_finding_fails(tmp_path: Path) -> None:
    report_file = tmp_path / "zap-medium.json"
    exceptions_file = tmp_path / "dast-exceptions.json"

    alert = build_zap_alert(
        rule_id="10038",
        name="Content Security Policy (CSP) Header Not Set",
        severity="Medium",
        instances=[build_zap_instance(uri="http://127.0.0.1:8002/docs")],
    )
    report_file.write_text(json.dumps(build_zap_report(alerts=[alert])), encoding="utf-8")
    exceptions_file.write_text(json.dumps(build_exception_register([])), encoding="utf-8")

    code, stdout, _ = run_validator_cli(report_file, exceptions_file)
    assert code == vds.EXIT_POLICY_VIOLATION
    assert "Policy violation: 1 unapproved High/Medium finding(s)" in stdout
    assert "[MEDIUM] Rule 10038" in stdout


def test_low_and_informational_findings_monitored_only(tmp_path: Path) -> None:
    report_file = tmp_path / "zap-low-info.json"
    exceptions_file = tmp_path / "dast-exceptions.json"

    alert_low = build_zap_alert(
        rule_id="10015",
        name="Incomplete or No Cache-control Header",
        severity="Low",
        instances=[build_zap_instance(uri="http://127.0.0.1:8002/static/favicon.svg")],
    )
    alert_info = build_zap_alert(
        rule_id="10104",
        name="User Controllable HTML Element Attribute",
        severity="Informational",
        instances=[build_zap_instance(uri="http://127.0.0.1:8002/")],
    )
    report_file.write_text(json.dumps(build_zap_report(alerts=[alert_low, alert_info])), encoding="utf-8")
    exceptions_file.write_text(json.dumps(build_exception_register([])), encoding="utf-8")

    code, stdout, _ = run_validator_cli(report_file, exceptions_file)
    assert code == vds.EXIT_SUCCESS
    assert "Policy compliant" in stdout
    assert "Monitored (Low / Informational):     2" in stdout
    assert "Unapproved High / Medium findings:    0" in stdout


def test_valid_exception_match_passes(tmp_path: Path) -> None:
    report_file = tmp_path / "zap-excepted.json"
    exceptions_file = tmp_path / "dast-exceptions.json"

    alert = build_zap_alert(
        rule_id="10038",
        name="Content Security Policy (CSP) Header Not Set",
        severity="Medium",
        instances=[build_zap_instance(uri="http://127.0.0.1:8002/docs")],
    )
    exc = build_exception_entry(
        rule_id="10038",
        name="Content Security Policy (CSP) Header Not Set",
        pattern=r"^http://127\.0\.0\.1:8002/docs.*",
        severity="MEDIUM",
        expires_at="2027-02-09",
    )
    report_file.write_text(json.dumps(build_zap_report(alerts=[alert])), encoding="utf-8")
    exceptions_file.write_text(json.dumps(build_exception_register([exc])), encoding="utf-8")

    code, stdout, _ = run_validator_cli(report_file, exceptions_file)
    assert code == vds.EXIT_SUCCESS
    assert "Policy compliant" in stdout
    assert "Approved active exceptions:          1" in stdout
    assert "Unapproved High / Medium findings:    0" in stdout


def test_wrong_rule_id_does_not_suppress(tmp_path: Path) -> None:
    report_file = tmp_path / "zap-mismatch-rule.json"
    exceptions_file = tmp_path / "dast-exceptions.json"

    alert = build_zap_alert(
        rule_id="10038",
        name="Content Security Policy (CSP) Header Not Set",
        severity="Medium",
        instances=[build_zap_instance(uri="http://127.0.0.1:8002/docs")],
    )
    # Exception targets rule 10035 instead of 10038
    exc = build_exception_entry(
        rule_id="10035",
        name="Strict-Transport-Security Header Not Set",
        pattern=r"^http://127\.0\.0\.1:8002/docs.*",
        severity="MEDIUM",
    )
    report_file.write_text(json.dumps(build_zap_report(alerts=[alert])), encoding="utf-8")
    exceptions_file.write_text(json.dumps(build_exception_register([exc])), encoding="utf-8")

    code, stdout, _ = run_validator_cli(report_file, exceptions_file)
    assert code == vds.EXIT_POLICY_VIOLATION
    assert "Policy violation: 1 unapproved High/Medium finding(s)" in stdout
    assert "The following exception(s) were unused" in stdout


def test_wrong_endpoint_pattern_does_not_suppress(tmp_path: Path) -> None:
    report_file = tmp_path / "zap-mismatch-endpoint.json"
    exceptions_file = tmp_path / "dast-exceptions.json"

    # Alert is on /api/v1/auth/login
    alert = build_zap_alert(
        rule_id="10038",
        name="Content Security Policy (CSP) Header Not Set",
        severity="Medium",
        instances=[build_zap_instance(uri="http://127.0.0.1:8002/api/v1/auth/login")],
    )
    # Exception only targets /docs
    exc = build_exception_entry(
        rule_id="10038",
        pattern=r"^http://127\.0\.0\.1:8002/docs.*",
        severity="MEDIUM",
    )
    report_file.write_text(json.dumps(build_zap_report(alerts=[alert])), encoding="utf-8")
    exceptions_file.write_text(json.dumps(build_exception_register([exc])), encoding="utf-8")

    code, stdout, _ = run_validator_cli(report_file, exceptions_file)
    assert code == vds.EXIT_POLICY_VIOLATION
    assert "Policy violation: 1 unapproved High/Medium finding(s)" in stdout


def test_expired_exception_triggers_policy_violation(tmp_path: Path) -> None:
    report_file = tmp_path / "zap-clean.json"
    exceptions_file = tmp_path / "dast-exceptions.json"

    # Expired in past
    exc = build_exception_entry(
        rule_id="10038",
        pattern=r"^http://127\.0\.0\.1:8002/docs.*",
        expires_at="2020-01-01",
    )
    report_file.write_text(json.dumps(build_zap_report(alerts=[])), encoding="utf-8")
    exceptions_file.write_text(json.dumps(build_exception_register([exc])), encoding="utf-8")

    code, stdout, _ = run_validator_cli(report_file, exceptions_file)
    assert code == vds.EXIT_POLICY_VIOLATION
    assert "Policy violation: 1 expired exception(s)" in stdout
    assert "Expired exception(s) detected in register:" in stdout


def test_duplicate_exception_rejected(tmp_path: Path) -> None:
    report_file = tmp_path / "zap-clean.json"
    exceptions_file = tmp_path / "dast-exceptions.json"

    exc1 = build_exception_entry(rule_id="10038", pattern=r"^http://127\.0\.0\.1:8002/docs.*")
    exc2 = build_exception_entry(rule_id="10038", pattern=r"^http://127\.0\.0\.1:8002/docs.*")

    report_file.write_text(json.dumps(build_zap_report(alerts=[])), encoding="utf-8")
    exceptions_file.write_text(json.dumps(build_exception_register([exc1, exc2])), encoding="utf-8")

    code, _, stderr = run_validator_cli(report_file, exceptions_file)
    assert code == vds.EXIT_OPERATIONAL_ERROR
    assert "Duplicate exception entry for rule '10038'" in stderr


def test_blanket_suppression_rejected_in_register(tmp_path: Path) -> None:
    report_file = tmp_path / "zap-clean.json"
    exceptions_file = tmp_path / "dast-exceptions.json"

    # Blanket pattern ".*" must be rejected
    exc = build_exception_entry(rule_id="10038", pattern=".*")

    report_file.write_text(json.dumps(build_zap_report(alerts=[])), encoding="utf-8")
    exceptions_file.write_text(json.dumps(build_exception_register([exc])), encoding="utf-8")

    code, _, stderr = run_validator_cli(report_file, exceptions_file)
    assert code == vds.EXIT_OPERATIONAL_ERROR
    assert "Blanket suppression pattern '.*' is not permitted" in stderr


def test_invalid_json_report(tmp_path: Path) -> None:
    report_file = tmp_path / "zap-broken.json"
    exceptions_file = tmp_path / "dast-exceptions.json"

    report_file.write_text('{"site": [broken json', encoding="utf-8")
    exceptions_file.write_text(json.dumps(build_exception_register([])), encoding="utf-8")

    code, _, stderr = run_validator_cli(report_file, exceptions_file)
    assert code == vds.EXIT_OPERATIONAL_ERROR
    assert "Failed to parse ZAP report JSON" in stderr


def test_invalid_json_register(tmp_path: Path) -> None:
    report_file = tmp_path / "zap-clean.json"
    exceptions_file = tmp_path / "dast-broken.json"

    report_file.write_text(json.dumps(build_zap_report(alerts=[])), encoding="utf-8")
    exceptions_file.write_text('{"version": "1.0", broken', encoding="utf-8")

    code, _, stderr = run_validator_cli(report_file, exceptions_file)
    assert code == vds.EXIT_OPERATIONAL_ERROR
    assert "Failed to parse exception register JSON" in stderr


def test_missing_report_file(tmp_path: Path) -> None:
    report_file = tmp_path / "non-existent-report.json"
    exceptions_file = tmp_path / "dast-exceptions.json"

    exceptions_file.write_text(json.dumps(build_exception_register([])), encoding="utf-8")

    code, _, stderr = run_validator_cli(report_file, exceptions_file)
    assert code == vds.EXIT_OPERATIONAL_ERROR
    assert "ZAP report file not found" in stderr


def test_missing_register_file(tmp_path: Path) -> None:
    report_file = tmp_path / "zap-clean.json"
    exceptions_file = tmp_path / "non-existent-register.json"

    report_file.write_text(json.dumps(build_zap_report(alerts=[])), encoding="utf-8")

    code, _, stderr = run_validator_cli(report_file, exceptions_file)
    assert code == vds.EXIT_OPERATIONAL_ERROR
    assert "Exception register file not found" in stderr


def test_malformed_alert_structure_missing_instances(tmp_path: Path) -> None:
    report_file = tmp_path / "zap-malformed.json"
    exceptions_file = tmp_path / "dast-exceptions.json"

    alert = {
        "pluginid": "10038",
        "alert": "CSP Missing",
        "riskdesc": "Medium",
        # Missing instances, uri, and url
    }
    report_file.write_text(json.dumps(build_zap_report(alerts=[alert])), encoding="utf-8")
    exceptions_file.write_text(json.dumps(build_exception_register([])), encoding="utf-8")

    code, _, stderr = run_validator_cli(report_file, exceptions_file)
    assert code == vds.EXIT_OPERATIONAL_ERROR
    assert "no valid instances or URI found" in stderr


def test_unknown_severity_rejected(tmp_path: Path) -> None:
    report_file = tmp_path / "zap-unknown-sev.json"
    exceptions_file = tmp_path / "dast-exceptions.json"

    alert = build_zap_alert(
        rule_id="10038",
        name="Unknown Severity Finding",
        severity="DISASTROUS",
        instances=[build_zap_instance()],
    )
    # Force raw riskdesc to unknown
    alert["riskdesc"] = "DISASTROUS (High)"
    report_file.write_text(json.dumps(build_zap_report(alerts=[alert])), encoding="utf-8")
    exceptions_file.write_text(json.dumps(build_exception_register([])), encoding="utf-8")

    code, _, stderr = run_validator_cli(report_file, exceptions_file)
    assert code == vds.EXIT_OPERATIONAL_ERROR
    assert "Unknown or invalid severity value: 'DISASTROUS (High)'" in stderr


def test_github_step_summary_output(tmp_path: Path) -> None:
    report_file = tmp_path / "zap-summary.json"
    exceptions_file = tmp_path / "dast-exceptions.json"
    summary_file = tmp_path / "step_summary.md"

    alert = build_zap_alert(
        rule_id="10038",
        name="Content Security Policy (CSP) Header Not Set",
        severity="Medium",
        instances=[build_zap_instance(uri="http://127.0.0.1:8002/docs")],
    )
    exc = build_exception_entry(
        rule_id="10038",
        pattern=r"^http://127\.0\.0\.1:8002/docs.*",
        severity="MEDIUM",
    )
    report_file.write_text(json.dumps(build_zap_report(alerts=[alert])), encoding="utf-8")
    exceptions_file.write_text(json.dumps(build_exception_register([exc])), encoding="utf-8")

    code, _, _ = run_validator_cli(report_file, exceptions_file, summary_path=summary_file)
    assert code == vds.EXIT_SUCCESS
    assert summary_file.is_file()

    summary_content = summary_file.read_text(encoding="utf-8")
    assert "### OWASP ZAP DAST Vulnerability Gate Report" in summary_content
    assert "Approved Active Exceptions" in summary_content
    assert "`10038`" in summary_content


def test_non_zero_scanner_status_fails(tmp_path: Path) -> None:
    report_file = tmp_path / "zap-clean.json"
    exceptions_file = tmp_path / "dast-exceptions.json"

    report_file.write_text(json.dumps(build_zap_report(alerts=[])), encoding="utf-8")
    exceptions_file.write_text(json.dumps(build_exception_register([])), encoding="utf-8")

    code, _, stderr = run_validator_cli(report_file, exceptions_file, scanner_status=2)
    assert code == vds.EXIT_OPERATIONAL_ERROR
    assert "ZAP scanner exited with non-zero status code: 2" in stderr


def test_multi_instance_partial_match_isolates_unapproved(tmp_path: Path) -> None:
    report_file = tmp_path / "zap-multi.json"
    exceptions_file = tmp_path / "dast-exceptions.json"

    # Alert has 2 instances: /docs and /api/v1/auth/login
    alert = build_zap_alert(
        rule_id="10038",
        name="CSP Header Not Set",
        severity="Medium",
        instances=[
            build_zap_instance(uri="http://127.0.0.1:8002/docs"),
            build_zap_instance(uri="http://127.0.0.1:8002/api/v1/auth/login"),
        ],
    )
    # Exception ONLY targets /docs
    exc = build_exception_entry(
        rule_id="10038",
        pattern=r"^http://127\.0\.0\.1:8002/docs.*",
        severity="MEDIUM",
    )
    report_file.write_text(json.dumps(build_zap_report(alerts=[alert])), encoding="utf-8")
    exceptions_file.write_text(json.dumps(build_exception_register([exc])), encoding="utf-8")

    code, stdout, _ = run_validator_cli(report_file, exceptions_file)
    # Must fail because /api/v1/auth/login is unapproved!
    assert code == vds.EXIT_POLICY_VIOLATION
    assert "1 unapproved High/Medium finding(s)" in stdout
    assert "Approved active exceptions:          1" in stdout
    assert "/api/v1/auth/login" in stdout
