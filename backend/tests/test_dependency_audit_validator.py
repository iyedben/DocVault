"""Automated unit and integration test suite for dependency vulnerability audit validator."""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

# Ensure scripts directory is importable
repo_root = Path(__file__).resolve().parent.parent.parent
if str(repo_root / "scripts") not in sys.path:
    sys.path.insert(0, str(repo_root / "scripts"))

import validate_dependency_audit as validator


class TestValidatorHelpers:
    """Tests for regex patterns and helper functions."""

    def test_valid_advisory_identifiers(self) -> None:
        valid_ids = [
            "CVE-2024-12345",
            "cve-2021-43818",
            "GHSA-72p3-jq4q-78hx",
            "GHSA-gggg-2345-6789",
            "ghsa-2345-6789-cfgh",
            "PYSEC-2024-123",
            "pysec-2021-9999",
        ]
        for v_id in valid_ids:
            assert validator.is_valid_advisory_id(v_id), f"Expected {v_id} to be valid"

    def test_invalid_advisory_identifiers(self) -> None:
        invalid_ids = [
            "GHSA-234k-2345-6789",  # 'k' is excluded
            "GHSA-234l-2345-6789",  # 'l' is excluded
            "GHSA-234s-2345-6789",  # 's' is excluded
            "GHSA-234t-2345-6789",  # 't' is excluded
            "GHSA-234y-2345-6789",  # 'y' is excluded
            "GHSA-234z-2345-6789",  # 'z' is excluded
            "GHSA-2340-2345-6789",  # '0' is excluded
            "GHSA-2341-2345-6789",  # '1' is excluded
            "GHSA-234a-2345-6789",  # 'a' is excluded
            "GHSA-123",             # incorrect segment length
            "CVE-2024",             # missing sequence
            "CVE-ABCD-1234",        # non-digit year
            "PYSEC-2024",           # missing sequence
            "OSV-2024-123",         # OSV generic prefix not in PyPA supported list
            "foo-bar",              # arbitrary string
            "",                     # empty string
        ]
        for v_id in invalid_ids:
            assert not validator.is_valid_advisory_id(v_id), f"Expected {v_id} to be invalid"

    def test_valid_package_names_pep508(self) -> None:
        valid_names = [
            "fastapi",
            "FastAPI",
            "pip-audit",
            "pydantic_core",
            "argon2.cffi",
            "a",
            "0",
            "lib-rt-1.0",
        ]
        for name in valid_names:
            assert validator.is_valid_package_name(name), f"Expected {name} to be valid"

    def test_invalid_package_names_pep508(self) -> None:
        invalid_names = [
            "",
            "-bad",
            "bad-",
            "_bad",
            "bad_",
            ".bad",
            "bad.",
            "bad name",
            "bad/name",
        ]
        for name in invalid_names:
            assert not validator.is_valid_package_name(name), f"Expected {name} to be invalid"

    def test_normalize_package_name_pep503(self) -> None:
        assert validator.normalize_package_name("FastAPI") == "fastapi"
        assert validator.normalize_package_name("pip_audit") == "pip-audit"
        assert validator.normalize_package_name("argon2.cffi") == "argon2-cffi"
        assert validator.normalize_package_name("A...B---C___D") == "a-b-c-d"

    def test_normalize_advisory_id(self) -> None:
        assert validator.normalize_advisory_id(" ghsa-72p3-jq4q-78hx ") == "GHSA-72P3-JQ4Q-78HX"
        assert validator.normalize_advisory_id("cve-2024-12345") == "CVE-2024-12345"


class TestExceptionRegisterValidation:
    """Tests for exception register schema and constraints."""

    def test_valid_empty_register(self, tmp_path: Path) -> None:
        reg_file = tmp_path / "exceptions.json"
        reg_file.write_text('{"version": "1.0", "exceptions": []}')
        exceptions, errors = validator.load_exception_register(reg_file)
        assert not errors
        assert exceptions == []

    def test_valid_populated_register(self, tmp_path: Path) -> None:
        future_date = (datetime.now(UTC).date() + timedelta(days=30)).strftime("%Y-%m-%d")
        payload = {
            "version": "1.0",
            "exceptions": [
                {
                    "vulnerability_id": "GHSA-72p3-jq4q-78hx",
                    "package_name": "pypdf",
                    "affected_version": "6.21.4",
                    "severity": "HIGH",
                    "technical_justification": "DocVault strictly validates PDF trailers and runs in read-only container.",
                    "compensating_controls": "Read-only root filesystem and non-root execution.",
                    "reviewer_approval": "Security Officer",
                    "tracking_issue": "https://github.com/iyedben/DocVault/issues/100",
                    "expiration_date": future_date,
                }
            ],
        }
        reg_file = tmp_path / "exceptions.json"
        reg_file.write_text(json.dumps(payload))
        exceptions, errors = validator.load_exception_register(reg_file)
        assert not errors
        assert len(exceptions) == 1
        assert exceptions[0]["package_name"] == "pypdf"

    def test_root_structure_validation(self, tmp_path: Path) -> None:
        reg_file = tmp_path / "exceptions.json"

        # Non-dict root
        reg_file.write_text('["version", "1.0"]')
        _, errors = validator.load_exception_register(reg_file)
        assert any("root must be a JSON object" in e for e in errors)

        # Unknown root keys
        reg_file.write_text('{"version": "1.0", "exceptions": [], "author": "admin"}')
        _, errors = validator.load_exception_register(reg_file)
        assert any("forbidden unknown keys" in e for e in errors)

        # Missing root keys
        reg_file.write_text('{"version": "1.0"}')
        _, errors = validator.load_exception_register(reg_file)
        assert any("missing required keys" in e for e in errors)

        # Invalid version
        reg_file.write_text('{"version": "2.0", "exceptions": []}')
        _, errors = validator.load_exception_register(reg_file)
        assert any("'version' must be literal '1.0'" in e for e in errors)

    def test_entry_required_and_unknown_fields(self, tmp_path: Path) -> None:
        future_date = (datetime.now(UTC).date() + timedelta(days=30)).strftime("%Y-%m-%d")
        valid_entry = {
            "vulnerability_id": "CVE-2024-12345",
            "package_name": "fastapi",
            "affected_version": "0.162.0",
            "technical_justification": "Test justification of sufficient character length.",
            "compensating_controls": "Non-root container execution.",
            "reviewer_approval": "Reviewer",
            "tracking_issue": "https://issue/1",
            "expiration_date": future_date,
        }
        reg_file = tmp_path / "exceptions.json"

        # Unknown entry field
        bad_entry_1 = dict(valid_entry, unknown_field="invalid")
        reg_file.write_text(json.dumps({"version": "1.0", "exceptions": [bad_entry_1]}))
        _, errors = validator.load_exception_register(reg_file)
        assert any("forbidden unknown fields" in e for e in errors)

        # Missing required field
        bad_entry_2 = dict(valid_entry)
        del bad_entry_2["reviewer_approval"]
        reg_file.write_text(json.dumps({"version": "1.0", "exceptions": [bad_entry_2]}))
        _, errors = validator.load_exception_register(reg_file)
        assert any("missing required fields" in e for e in errors)

    def test_strict_string_type_enforcement(self, tmp_path: Path) -> None:
        future_date = (datetime.now(UTC).date() + timedelta(days=30)).strftime("%Y-%m-%d")
        reg_file = tmp_path / "exceptions.json"

        # Non-string version (numeric float)
        bad_entry_float = {
            "vulnerability_id": "CVE-2024-12345",
            "package_name": "fastapi",
            "affected_version": 1.0,  # float instead of str
            "technical_justification": "Test justification of sufficient character length.",
            "compensating_controls": "Non-root container execution.",
            "reviewer_approval": "Reviewer",
            "tracking_issue": "https://issue/1",
            "expiration_date": future_date,
        }
        reg_file.write_text(json.dumps({"version": "1.0", "exceptions": [bad_entry_float]}))
        _, errors = validator.load_exception_register(reg_file)
        assert any("must be a non-empty string" in e for e in errors)

        # Boolean value
        bad_entry_bool = dict(bad_entry_float, affected_version="1.0", reviewer_approval=True)
        reg_file.write_text(json.dumps({"version": "1.0", "exceptions": [bad_entry_bool]}))
        _, errors = validator.load_exception_register(reg_file)
        assert any("must be a non-empty string" in e for e in errors)

        # Whitespace-only string
        bad_entry_ws = dict(bad_entry_float, affected_version="1.0", reviewer_approval="   ")
        reg_file.write_text(json.dumps({"version": "1.0", "exceptions": [bad_entry_ws]}))
        _, errors = validator.load_exception_register(reg_file)
        assert any("must be a non-empty string" in e for e in errors)

    def test_severity_validation(self, tmp_path: Path) -> None:
        future_date = (datetime.now(UTC).date() + timedelta(days=30)).strftime("%Y-%m-%d")
        base_entry = {
            "vulnerability_id": "CVE-2024-12345",
            "package_name": "fastapi",
            "affected_version": "0.162.0",
            "technical_justification": "Test justification of sufficient character length.",
            "compensating_controls": "Non-root container execution.",
            "reviewer_approval": "Reviewer",
            "tracking_issue": "https://issue/1",
            "expiration_date": future_date,
        }
        reg_file = tmp_path / "exceptions.json"

        # Valid severities
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
            reg_file.write_text(json.dumps({"version": "1.0", "exceptions": [dict(base_entry, severity=sev)]}))
            _, errors = validator.load_exception_register(reg_file)
            assert not errors, f"Failed for valid severity {sev}"

        # Invalid casing
        reg_file.write_text(json.dumps({"version": "1.0", "exceptions": [dict(base_entry, severity="critical")]}))
        _, errors = validator.load_exception_register(reg_file)
        assert any("optional field 'severity' must be exactly one of" in e for e in errors)

        # Whitespace padding
        reg_file.write_text(json.dumps({"version": "1.0", "exceptions": [dict(base_entry, severity=" CRITICAL ")]}))
        _, errors = validator.load_exception_register(reg_file)
        assert any("optional field 'severity' must be exactly one of" in e for e in errors)

    def test_duplicate_exception_rejection(self, tmp_path: Path) -> None:
        future_date = (datetime.now(UTC).date() + timedelta(days=30)).strftime("%Y-%m-%d")
        entry_1 = {
            "vulnerability_id": "CVE-2024-12345",
            "package_name": "fastapi",
            "affected_version": "0.162.0",
            "technical_justification": "Test justification of sufficient character length.",
            "compensating_controls": "Non-root container execution.",
            "reviewer_approval": "Reviewer 1",
            "tracking_issue": "https://issue/1",
            "expiration_date": future_date,
        }
        entry_2 = dict(entry_1, package_name="FastAPI", reviewer_approval="Reviewer 2")
        reg_file = tmp_path / "exceptions.json"
        reg_file.write_text(json.dumps({"version": "1.0", "exceptions": [entry_1, entry_2]}))
        _, errors = validator.load_exception_register(reg_file)
        assert any("Duplicate exception entry" in e for e in errors)

    def test_expiration_date_semantics(self, tmp_path: Path) -> None:
        today_utc = datetime.now(UTC).date()
        yesterday_str = (today_utc - timedelta(days=1)).strftime("%Y-%m-%d")
        today_str = today_utc.strftime("%Y-%m-%d")
        future_str = (today_utc + timedelta(days=5)).strftime("%Y-%m-%d")

        base_entry = {
            "vulnerability_id": "CVE-2024-12345",
            "package_name": "fastapi",
            "affected_version": "0.162.0",
            "technical_justification": "Test justification of sufficient character length.",
            "compensating_controls": "Non-root container execution.",
            "reviewer_approval": "Reviewer",
            "tracking_issue": "https://issue/1",
        }
        reg_file = tmp_path / "exceptions.json"

        # Expired yesterday -> error
        reg_file.write_text(json.dumps({"version": "1.0", "exceptions": [dict(base_entry, expiration_date=yesterday_str)]}))
        _, errors = validator.load_exception_register(reg_file)
        assert any("EXPIRED EXCEPTION" in e for e in errors)

        # Stated date is today -> active through 23:59:59 UTC
        reg_file.write_text(json.dumps({"version": "1.0", "exceptions": [dict(base_entry, expiration_date=today_str)]}))
        exceptions, errors = validator.load_exception_register(reg_file)
        assert not errors
        assert len(exceptions) == 1

        # Future date -> active
        reg_file.write_text(json.dumps({"version": "1.0", "exceptions": [dict(base_entry, expiration_date=future_str)]}))
        exceptions, errors = validator.load_exception_register(reg_file)
        assert not errors
        assert len(exceptions) == 1


class TestReportValidation:
    """Tests for pip-audit JSON report structural validation."""

    def test_valid_clean_report(self, tmp_path: Path) -> None:
        report_file = tmp_path / "report.json"
        report_file.write_text('[{"name": "fastapi", "version": "0.162.0", "vulns": []}]')
        packages, errors = validator.load_scan_report(report_file)
        assert not errors
        assert len(packages) == 1
        assert packages[0]["name"] == "fastapi"

    def test_valid_vulnerable_report(self, tmp_path: Path) -> None:
        report_file = tmp_path / "report.json"
        report_file.write_text(
            json.dumps(
                [
                    {
                        "name": "pypdf",
                        "version": "6.21.4",
                        "vulns": [
                            {
                                "id": "GHSA-72p3-jq4q-78hx",
                                "fix_versions": ["6.21.5"],
                                "aliases": ["CVE-2024-99999"],
                                "description": "Example vulnerability description.",
                            }
                        ],
                    }
                ]
            )
        )
        packages, errors = validator.load_scan_report(report_file)
        assert not errors
        assert len(packages) == 1
        assert len(packages[0]["vulns"]) == 1

    def test_report_root_not_array(self, tmp_path: Path) -> None:
        report_file = tmp_path / "report.json"
        report_file.write_text('{"dependencies": []}')
        _, errors = validator.load_scan_report(report_file)
        assert any("root must be a top-level JSON array" in e for e in errors)

    def test_explicit_null_rejection_in_report(self, tmp_path: Path) -> None:
        report_file = tmp_path / "report.json"

        # Explicit null aliases
        report_file.write_text(
            json.dumps(
                [
                    {
                        "name": "pypdf",
                        "version": "6.21.4",
                        "vulns": [{"id": "CVE-2024-12345", "aliases": None}],
                    }
                ]
            )
        )
        _, errors = validator.load_scan_report(report_file)
        assert any("contains invalid or unsupported alias identifier" in e for e in errors)

        # Explicit null fix_versions
        report_file.write_text(
            json.dumps(
                [
                    {
                        "name": "pypdf",
                        "version": "6.21.4",
                        "vulns": [{"id": "CVE-2024-12345", "fix_versions": None}],
                    }
                ]
            )
        )
        _, errors = validator.load_scan_report(report_file)
        assert any("must be a list of non-empty strings" in e for e in errors)

        # Explicit null description
        report_file.write_text(
            json.dumps(
                [
                    {
                        "name": "pypdf",
                        "version": "6.21.4",
                        "vulns": [{"id": "CVE-2024-12345", "description": None}],
                    }
                ]
            )
        )
        _, errors = validator.load_scan_report(report_file)
        assert any("'description' must be a string if present" in e for e in errors)


class TestScannerReportConsistencyAndMain:
    """Tests for scanner/report consistency and end-to-end main() behavior."""

    def test_clean_scan_consistency(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        reg_file = tmp_path / "exceptions.json"
        reg_file.write_text('{"version": "1.0", "exceptions": []}')
        report_file = tmp_path / "report.json"
        report_file.write_text('[{"name": "fastapi", "version": "0.162.0", "vulns": []}]')
        summary_file = tmp_path / "summary.md"

        monkeypatch.setattr(
            sys,
            "argv",
            [
                "validate_dependency_audit.py",
                "--report",
                str(report_file),
                "--exceptions",
                str(reg_file),
                "--audit-status",
                "0",
                "--summary",
                str(summary_file),
            ],
        )
        exit_code = validator.main()
        assert exit_code == 0
        summary_content = summary_file.read_text()
        assert "All audited dependencies satisfy the DocVault zero-vulnerability security policy" in summary_content

    def test_inconsistency_exit0_with_findings(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        reg_file = tmp_path / "exceptions.json"
        reg_file.write_text('{"version": "1.0", "exceptions": []}')
        report_file = tmp_path / "report.json"
        report_file.write_text(
            json.dumps([{"name": "pypdf", "version": "6.21.4", "vulns": [{"id": "CVE-2024-12345"}]}])
        )
        summary_file = tmp_path / "summary.md"

        monkeypatch.setattr(
            sys,
            "argv",
            [
                "validate_dependency_audit.py",
                "--report",
                str(report_file),
                "--exceptions",
                str(reg_file),
                "--audit-status",
                "0",
                "--summary",
                str(summary_file),
            ],
        )
        exit_code = validator.main()
        assert exit_code == 1
        summary_content = summary_file.read_text()
        assert "Inconsistency failure: pip-audit exited 0 (clean) but report contains 1 vulnerabilities" in summary_content

    def test_inconsistency_exit1_with_zero_findings(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        reg_file = tmp_path / "exceptions.json"
        reg_file.write_text('{"version": "1.0", "exceptions": []}')
        report_file = tmp_path / "report.json"
        report_file.write_text('[{"name": "fastapi", "version": "0.162.0", "vulns": []}]')
        summary_file = tmp_path / "summary.md"

        monkeypatch.setattr(
            sys,
            "argv",
            [
                "validate_dependency_audit.py",
                "--report",
                str(report_file),
                "--exceptions",
                str(reg_file),
                "--audit-status",
                "1",
                "--summary",
                str(summary_file),
            ],
        )
        exit_code = validator.main()
        assert exit_code == 1
        summary_content = summary_file.read_text()
        assert "Inconsistency failure: pip-audit exited 1 (findings detected) but report contains 0 vulnerabilities" in summary_content

    def test_authorized_vulnerability_matching_primary_id(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        future_date = (datetime.now(UTC).date() + timedelta(days=30)).strftime("%Y-%m-%d")
        reg_payload = {
            "version": "1.0",
            "exceptions": [
                {
                    "vulnerability_id": "GHSA-72p3-jq4q-78hx",
                    "package_name": "pypdf",
                    "affected_version": "6.21.4",
                    "technical_justification": "DocVault strictly validates PDF trailers and runs in read-only container.",
                    "compensating_controls": "Read-only root filesystem.",
                    "reviewer_approval": "Reviewer",
                    "tracking_issue": "https://issue/1",
                    "expiration_date": future_date,
                }
            ],
        }
        reg_file = tmp_path / "exceptions.json"
        reg_file.write_text(json.dumps(reg_payload))

        report_file = tmp_path / "report.json"
        report_file.write_text(
            json.dumps([{"name": "pypdf", "version": "6.21.4", "vulns": [{"id": "ghsa-72p3-jq4q-78hx"}]}])
        )
        summary_file = tmp_path / "summary.md"

        monkeypatch.setattr(
            sys,
            "argv",
            [
                "validate_dependency_audit.py",
                "--report",
                str(report_file),
                "--exceptions",
                str(reg_file),
                "--audit-status",
                "1",
                "--summary",
                str(summary_file),
            ],
        )
        exit_code = validator.main()
        assert exit_code == 0
        summary_content = summary_file.read_text()
        assert "Approved Exceptions Applied" in summary_content

    def test_authorized_vulnerability_matching_alias(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        future_date = (datetime.now(UTC).date() + timedelta(days=30)).strftime("%Y-%m-%d")
        reg_payload = {
            "version": "1.0",
            "exceptions": [
                {
                    "vulnerability_id": "CVE-2024-99999",  # Exception references CVE
                    "package_name": "pypdf",
                    "affected_version": "6.21.4",
                    "technical_justification": "DocVault strictly validates PDF trailers and runs in read-only container.",
                    "compensating_controls": "Read-only root filesystem.",
                    "reviewer_approval": "Reviewer",
                    "tracking_issue": "https://issue/1",
                    "expiration_date": future_date,
                }
            ],
        }
        reg_file = tmp_path / "exceptions.json"
        reg_file.write_text(json.dumps(reg_payload))

        # Report has primary ID GHSA, but lists CVE in aliases
        report_file = tmp_path / "report.json"
        report_file.write_text(
            json.dumps(
                [
                    {
                        "name": "pypdf",
                        "version": "6.21.4",
                        "vulns": [{"id": "GHSA-72p3-jq4q-78hx", "aliases": ["cve-2024-99999"]}],
                    }
                ]
            )
        )
        summary_file = tmp_path / "summary.md"

        monkeypatch.setattr(
            sys,
            "argv",
            [
                "validate_dependency_audit.py",
                "--report",
                str(report_file),
                "--exceptions",
                str(reg_file),
                "--audit-status",
                "1",
                "--summary",
                str(summary_file),
            ],
        )
        exit_code = validator.main()
        assert exit_code == 0
        summary_content = summary_file.read_text()
        assert "Approved Exceptions Applied" in summary_content

    def test_unauthorized_vulnerability_blocks_gate(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        reg_file = tmp_path / "exceptions.json"
        reg_file.write_text('{"version": "1.0", "exceptions": []}')
        report_file = tmp_path / "report.json"
        report_file.write_text(
            json.dumps([{"name": "pypdf", "version": "6.21.4", "vulns": [{"id": "CVE-2024-12345"}]}])
        )
        summary_file = tmp_path / "summary.md"

        monkeypatch.setattr(
            sys,
            "argv",
            [
                "validate_dependency_audit.py",
                "--report",
                str(report_file),
                "--exceptions",
                str(reg_file),
                "--audit-status",
                "1",
                "--summary",
                str(summary_file),
            ],
        )
        exit_code = validator.main()
        assert exit_code == 1
        summary_content = summary_file.read_text()
        assert "Unauthorized Vulnerabilities (Gate Blocked)" in summary_content

    def test_unused_exception_emits_warning(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
        future_date = (datetime.now(UTC).date() + timedelta(days=30)).strftime("%Y-%m-%d")
        reg_payload = {
            "version": "1.0",
            "exceptions": [
                {
                    "vulnerability_id": "CVE-2024-12345",
                    "package_name": "fastapi",
                    "affected_version": "0.162.0",
                    "technical_justification": "DocVault strictly validates PDF trailers and runs in read-only container.",
                    "compensating_controls": "Read-only root filesystem.",
                    "reviewer_approval": "Reviewer",
                    "tracking_issue": "https://issue/1",
                    "expiration_date": future_date,
                }
            ],
        }
        reg_file = tmp_path / "exceptions.json"
        reg_file.write_text(json.dumps(reg_payload))

        report_file = tmp_path / "report.json"
        report_file.write_text('[{"name": "fastapi", "version": "0.162.0", "vulns": []}]')
        summary_file = tmp_path / "summary.md"

        monkeypatch.setattr(
            sys,
            "argv",
            [
                "validate_dependency_audit.py",
                "--report",
                str(report_file),
                "--exceptions",
                str(reg_file),
                "--audit-status",
                "0",
                "--summary",
                str(summary_file),
            ],
        )
        exit_code = validator.main()
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "::warning::Unused exception for package 'fastapi'" in captured.out
        summary_content = summary_file.read_text()
        assert "Warnings (Unused Exceptions)" in summary_content
