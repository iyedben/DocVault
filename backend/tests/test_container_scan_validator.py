"""Unit and integration tests for the Grype container vulnerability scan validator.

Validates report parsing, severity policy enforcement, exception register
semantics, GitHub Step Summary generation, and deterministic exit-code contracts.
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
import validate_container_scan as vcs


def build_grype_match(
    vuln_id: str,
    pkg_name: str,
    pkg_version: str,
    severity: str,
    pkg_type: str = "deb",
    aliases: list[str] | None = None,
    fix_versions: list[str] | None = None,
) -> dict[str, Any]:
    """Helper to create a realistic Grype match object."""
    match: dict[str, Any] = {
        "vulnerability": {
            "id": vuln_id,
            "severity": severity,
            "description": f"Vulnerability {vuln_id} affecting {pkg_name}",
            "dataSource": "https://security-tracker.debian.org",
            "fix": {
                "versions": fix_versions or [],
                "state": "fixed" if fix_versions else "not-fixed",
            },
        },
        "artifact": {
            "name": pkg_name,
            "version": pkg_version,
            "type": pkg_type,
            "locations": [{"path": f"/usr/share/doc/{pkg_name}"}],
            "purl": f"pkg:{pkg_type}/{pkg_name}@{pkg_version}",
        },
        "relatedVulnerabilities": [{"id": alias} for alias in (aliases or [])],
        "matchDetails": [{"type": "exact-version-match"}],
    }
    return match


def build_grype_report(matches: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Helper to create a complete Grype JSON report."""
    return {
        "matches": matches if matches is not None else [],
        "source": {
            "type": "image",
            "target": {
                "userInput": "docvault-api:local",
                "imageID": "sha256:771520449f9fb88f345741f97c01d127c48d80c985af01289d3cdcbac3ca353a",
            },
        },
        "distro": {
            "name": "debian",
            "version": "13",
            "idLike": ["debian"],
        },
        "descriptor": {
            "name": "grype",
            "version": "0.88.0",
        },
    }


class TestValidatorHelpers:
    """Tests for advisory, package normalization, and date parsing utilities."""

    def test_valid_advisory_identifiers(self) -> None:
        assert vcs.is_valid_advisory_id("CVE-2026-12345")
        assert vcs.is_valid_advisory_id("cve-2024-0001")
        assert vcs.is_valid_advisory_id("GHSA-2345-6789-cfgh")
        assert vcs.is_valid_advisory_id("ghsa-jmpq-rvwx-2345")

    def test_invalid_advisory_identifiers(self) -> None:
        assert not vcs.is_valid_advisory_id("CVE-24-123")  # bad year
        assert not vcs.is_valid_advisory_id("INVALID-123")
        assert not vcs.is_valid_advisory_id("GHSA-xxxx-yyyy-zzzz")  # invalid chars (y, z)
        assert not vcs.is_valid_advisory_id("")
        assert not vcs.is_valid_advisory_id("   ")

    def test_package_name_normalization(self) -> None:
        assert vcs.normalize_package_name("LibC6", "deb") == "libc6"
        assert vcs.normalize_package_name("OpenSSL", "deb") == "openssl"
        assert vcs.normalize_package_name("Pydantic_Core", "python") == "pydantic-core"
        assert vcs.normalize_package_name("PyPDF.Tool", "wheel") == "pypdf-tool"

    def test_canonical_date_parsing_and_expiration(self) -> None:
        now_utc = datetime(2026, 11, 10, 12, 0, 0, tzinfo=UTC)

        # Same day is active through 23:59:59 UTC
        active, _ = vcs.is_exception_active("2026-11-10", now_utc)
        assert active is True

        # Future date is active
        active, _ = vcs.is_exception_active("2026-12-31", now_utc)
        assert active is True

        # Past date is expired
        active, msg = vcs.is_exception_active("2026-11-09", now_utc)
        assert active is False
        assert "expired" in msg.lower()

        # Malformed format
        active, msg = vcs.is_exception_active("10/11/2026", now_utc)
        assert active is False
        assert "invalid" in msg.lower()


class TestExceptionRegisterValidation:
    """Tests for validating container-exceptions.json files."""

    def test_valid_empty_register(self, tmp_path: Path) -> None:
        path = tmp_path / "exceptions.json"
        path.write_text(json.dumps({"version": "1.0", "exceptions": []}))
        now_utc = datetime(2026, 11, 10, tzinfo=UTC)
        valid, errors = vcs.validate_exception_register(str(path), now_utc)
        assert errors == []
        assert valid == []

    def test_valid_populated_register(self, tmp_path: Path) -> None:
        path = tmp_path / "exceptions.json"
        data = {
            "version": "1.0",
            "exceptions": [
                {
                    "vulnerability_id": "CVE-2026-9999",
                    "package_name": "libc6",
                    "affected_version": "2.36-9+deb12u7",
                    "severity": "HIGH",
                    "reason": "Hardware flaw not reachable inside container",
                    "expires_at": "2026-12-31",
                }
            ],
        }
        path.write_text(json.dumps(data))
        now_utc = datetime(2026, 11, 10, tzinfo=UTC)
        valid, errors = vcs.validate_exception_register(str(path), now_utc)
        assert errors == []
        assert len(valid) == 1
        assert valid[0]["vulnerability_id"] == "CVE-2026-9999"

    def test_root_structure_validation(self, tmp_path: Path) -> None:
        now_utc = datetime(2026, 11, 10, tzinfo=UTC)

        # Missing version
        p1 = tmp_path / "e1.json"
        p1.write_text(json.dumps({"exceptions": []}))
        _, err1 = vcs.validate_exception_register(str(p1), now_utc)
        assert any("missing mandatory root key" in e.lower() for e in err1)

        # Unexpected root key
        p2 = tmp_path / "e2.json"
        p2.write_text(json.dumps({"version": "1.0", "exceptions": [], "extra": 123}))
        _, err2 = vcs.validate_exception_register(str(p2), now_utc)
        assert any("unexpected root key" in e.lower() for e in err2)

        # Invalid version string
        p3 = tmp_path / "e3.json"
        p3.write_text(json.dumps({"version": "2.0", "exceptions": []}))
        _, err3 = vcs.validate_exception_register(str(p3), now_utc)
        assert any("unsupported exception register version" in e.lower() for e in err3)

    def test_entry_required_and_unknown_fields(self, tmp_path: Path) -> None:
        now_utc = datetime(2026, 11, 10, tzinfo=UTC)
        path = tmp_path / "e.json"

        # Missing 'reason'
        entry = {
            "vulnerability_id": "CVE-2026-1111",
            "package_name": "openssl",
            "affected_version": "3.0.11",
            "severity": "CRITICAL",
            "expires_at": "2026-12-31",
        }
        path.write_text(json.dumps({"version": "1.0", "exceptions": [entry]}))
        _, errors = vcs.validate_exception_register(str(path), now_utc)
        assert any("missing required field" in e.lower() and "reason" in e for e in errors)

        # Unexpected field
        entry["reason"] = "Valid justification"
        entry["unknown_field"] = "bad"
        path.write_text(json.dumps({"version": "1.0", "exceptions": [entry]}))
        _, errors = vcs.validate_exception_register(str(path), now_utc)
        assert any("unexpected field" in e.lower() and "unknown_field" in e for e in errors)

    def test_strict_string_type_and_severity_validation(self, tmp_path: Path) -> None:
        now_utc = datetime(2026, 11, 10, tzinfo=UTC)
        path = tmp_path / "e.json"

        entry = {
            "vulnerability_id": "CVE-2026-1111",
            "package_name": "openssl",
            "affected_version": "3.0.11",
            "severity": "INVALID_SEV",
            "reason": "Valid reason",
            "expires_at": "2026-12-31",
        }
        path.write_text(json.dumps({"version": "1.0", "exceptions": [entry]}))
        _, errors = vcs.validate_exception_register(str(path), now_utc)
        assert any("invalid severity" in e.lower() for e in errors)

    def test_duplicate_exception_rejection(self, tmp_path: Path) -> None:
        now_utc = datetime(2026, 11, 10, tzinfo=UTC)
        path = tmp_path / "e.json"
        entry = {
            "vulnerability_id": "CVE-2026-1111",
            "package_name": "openssl",
            "affected_version": "3.0.11",
            "severity": "HIGH",
            "reason": "First declaration",
            "expires_at": "2026-12-31",
        }
        entry_dup = dict(entry)
        entry_dup["reason"] = "Second duplicate declaration"
        path.write_text(json.dumps({"version": "1.0", "exceptions": [entry, entry_dup]}))
        _, errors = vcs.validate_exception_register(str(path), now_utc)
        assert any("duplicate exception" in e.lower() for e in errors)

    def test_expired_exception_rejection(self, tmp_path: Path) -> None:
        now_utc = datetime(2026, 11, 10, tzinfo=UTC)
        path = tmp_path / "e.json"
        entry = {
            "vulnerability_id": "CVE-2026-1111",
            "package_name": "openssl",
            "affected_version": "3.0.11",
            "severity": "HIGH",
            "reason": "Expired last week",
            "expires_at": "2026-11-01",
        }
        path.write_text(json.dumps({"version": "1.0", "exceptions": [entry]}))
        _, errors = vcs.validate_exception_register(str(path), now_utc)
        assert any("expired" in e.lower() for e in errors)


class TestReportParsingAndValidation:
    """Tests for parsing Grype JSON scan reports."""

    def test_valid_clean_report(self, tmp_path: Path) -> None:
        p = tmp_path / "grype.json"
        p.write_text(json.dumps(build_grype_report([])))
        _, findings, errors = vcs.parse_and_validate_grype_report(str(p))
        assert errors == []
        assert findings == []

    def test_valid_vulnerable_report(self, tmp_path: Path) -> None:
        p = tmp_path / "grype.json"
        match = build_grype_match(
            "CVE-2026-1234",
            "zlib1g",
            "1:1.2.13.dfsg-1",
            "Critical",
            aliases=["GHSA-2345-6789-cfgh"],
            fix_versions=["1:1.2.13.dfsg-2"],
        )
        p.write_text(json.dumps(build_grype_report([match])))
        _, findings, errors = vcs.parse_and_validate_grype_report(str(p))
        assert errors == []
        assert len(findings) == 1
        f = findings[0]
        assert f["id"] == "CVE-2026-1234"
        assert f["severity"] == "CRITICAL"
        assert f["package_name"] == "zlib1g"
        assert f["aliases"] == ["GHSA-2345-6789-CFGH"]
        assert f["fix_versions"] == ["1:1.2.13.dfsg-2"]

    def test_report_missing_or_malformed(self, tmp_path: Path) -> None:
        # Non-existent
        _, _, err1 = vcs.parse_and_validate_grype_report(str(tmp_path / "none.json"))
        assert any("does not exist" in e.lower() for e in err1)

        # Malformed JSON
        p2 = tmp_path / "bad.json"
        p2.write_text("not json {")
        _, _, err2 = vcs.parse_and_validate_grype_report(str(p2))
        assert any("failed to parse" in e.lower() for e in err2)

        # Missing matches list
        p3 = tmp_path / "no_matches.json"
        p3.write_text(json.dumps({"source": {}}))
        _, _, err3 = vcs.parse_and_validate_grype_report(str(p3))
        assert any("missing mandatory top-level 'matches'" in e.lower() for e in err3)


class TestPolicyEvaluationAndMainIntegration:
    """End-to-end integration tests for command-line execution and exit codes."""

    def run_validator(
        self,
        report_path: Path,
        exceptions_path: Path,
        scanner_status: int = 0,
        summary_path: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        cmd = [
            sys.executable,
            str(Path(vcs.__file__).resolve()),
            "--report",
            str(report_path),
            "--exceptions",
            str(exceptions_path),
            "--scanner-status",
            str(scanner_status),
        ]
        if summary_path:
            cmd.extend(["--summary", str(summary_path)])
        return subprocess.run(cmd, check=False, capture_output=True, text=True)

    def test_clean_report_passes(self, tmp_path: Path) -> None:
        rep = tmp_path / "rep.json"
        exc = tmp_path / "exc.json"
        rep.write_text(json.dumps(build_grype_report([])))
        exc.write_text(json.dumps({"version": "1.0", "exceptions": []}))

        res = self.run_validator(rep, exc, scanner_status=0)
        assert res.returncode == vcs.EXIT_SUCCESS
        assert "Policy compliant" in res.stdout

    def test_critical_finding_blocks(self, tmp_path: Path) -> None:
        rep = tmp_path / "rep.json"
        exc = tmp_path / "exc.json"
        m = build_grype_match("CVE-2026-9999", "libc6", "2.36", "Critical")
        rep.write_text(json.dumps(build_grype_report([m])))
        exc.write_text(json.dumps({"version": "1.0", "exceptions": []}))

        res = self.run_validator(rep, exc, scanner_status=0)
        assert res.returncode == vcs.EXIT_POLICY_VIOLATION
        assert "Policy violation" in res.stdout
        assert "CVE-2026-9999" in res.stdout

    def test_high_finding_blocks(self, tmp_path: Path) -> None:
        rep = tmp_path / "rep.json"
        exc = tmp_path / "exc.json"
        m = build_grype_match("CVE-2026-8888", "openssl", "3.0.11", "High")
        rep.write_text(json.dumps(build_grype_report([m])))
        exc.write_text(json.dumps({"version": "1.0", "exceptions": []}))

        res = self.run_validator(rep, exc, scanner_status=0)
        assert res.returncode == vcs.EXIT_POLICY_VIOLATION
        assert "Policy violation" in res.stdout

    def test_medium_low_negligible_unknown_are_non_blocking(self, tmp_path: Path) -> None:
        rep = tmp_path / "rep.json"
        exc = tmp_path / "exc.json"
        matches = [
            build_grype_match("CVE-2026-0001", "pkg1", "1.0", "Medium"),
            build_grype_match("CVE-2026-0002", "pkg2", "1.0", "Low"),
            build_grype_match("CVE-2026-0003", "pkg3", "1.0", "Negligible"),
            build_grype_match("CVE-2026-0004", "pkg4", "1.0", "Unknown"),
        ]
        rep.write_text(json.dumps(build_grype_report(matches)))
        exc.write_text(json.dumps({"version": "1.0", "exceptions": []}))

        res = self.run_validator(rep, exc, scanner_status=0)
        assert res.returncode == vcs.EXIT_SUCCESS
        assert "Policy compliant" in res.stdout
        assert "Monitored (Medium/Low/Negligible):   4" in res.stdout

    def test_valid_active_exception_permits_critical_and_high(self, tmp_path: Path) -> None:
        rep = tmp_path / "rep.json"
        exc = tmp_path / "exc.json"
        m = build_grype_match("CVE-2026-7777", "curl", "7.88.1", "High")
        rep.write_text(json.dumps(build_grype_report([m])))

        exc_data = {
            "version": "1.0",
            "exceptions": [
                {
                    "vulnerability_id": "CVE-2026-7777",
                    "package_name": "curl",
                    "affected_version": "7.88.1",
                    "severity": "HIGH",
                    "reason": "Curl binary is not exposed in production web workflow",
                    "expires_at": "2099-12-31",
                }
            ],
        }
        exc.write_text(json.dumps(exc_data))

        res = self.run_validator(rep, exc, scanner_status=0)
        assert res.returncode == vcs.EXIT_SUCCESS
        assert "Approved active exceptions:          1" in res.stdout

    def test_exception_matching_via_alias(self, tmp_path: Path) -> None:
        rep = tmp_path / "rep.json"
        exc = tmp_path / "exc.json"
        # Match has primary ID CVE-2026-5555 and alias GHSA-2345-6789-cfgh
        m = build_grype_match(
            "CVE-2026-5555",
            "urllib3",
            "2.2.0",
            "High",
            pkg_type="python",
            aliases=["GHSA-2345-6789-cfgh"],
        )
        rep.write_text(json.dumps(build_grype_report([m])))

        # Exception registered under GHSA alias
        exc_data = {
            "version": "1.0",
            "exceptions": [
                {
                    "vulnerability_id": "GHSA-2345-6789-cfgh",
                    "package_name": "urllib3",
                    "affected_version": "2.2.0",
                    "severity": "HIGH",
                    "reason": "Verified non-exploitable",
                    "expires_at": "2099-12-31",
                }
            ],
        }
        exc.write_text(json.dumps(exc_data))

        res = self.run_validator(rep, exc, scanner_status=0)
        assert res.returncode == vcs.EXIT_SUCCESS
        assert "Approved active exceptions:          1" in res.stdout

    def test_exception_version_mismatch_blocks(self, tmp_path: Path) -> None:
        rep = tmp_path / "rep.json"
        exc = tmp_path / "exc.json"
        m = build_grype_match("CVE-2026-7777", "curl", "7.88.2", "High")
        rep.write_text(json.dumps(build_grype_report([m])))

        exc_data = {
            "version": "1.0",
            "exceptions": [
                {
                    "vulnerability_id": "CVE-2026-7777",
                    "package_name": "curl",
                    "affected_version": "7.88.1",  # Different version
                    "severity": "HIGH",
                    "reason": "Exemption for 7.88.1 only",
                    "expires_at": "2099-12-31",
                }
            ],
        }
        exc.write_text(json.dumps(exc_data))

        res = self.run_validator(rep, exc, scanner_status=0)
        assert res.returncode == vcs.EXIT_POLICY_VIOLATION
        assert "Unapproved Critical or High vulnerabilities found" in res.stdout
        assert "Unused exceptions (warnings):        1" in res.stdout

    def test_unused_exception_emits_warning(self, tmp_path: Path) -> None:
        rep = tmp_path / "rep.json"
        exc = tmp_path / "exc.json"
        rep.write_text(json.dumps(build_grype_report([])))

        exc_data = {
            "version": "1.0",
            "exceptions": [
                {
                    "vulnerability_id": "CVE-2026-1111",
                    "package_name": "unused-pkg",
                    "affected_version": "1.0.0",
                    "severity": "HIGH",
                    "reason": "Not present in report",
                    "expires_at": "2099-12-31",
                }
            ],
        }
        exc.write_text(json.dumps(exc_data))

        res = self.run_validator(rep, exc, scanner_status=0)
        assert res.returncode == vcs.EXIT_SUCCESS
        assert "Unused exceptions (warnings):        1" in res.stdout
        assert "[WARNING] The following exceptions were unused in this scan" in res.stdout

    def test_scanner_execution_failure_fails_gate(self, tmp_path: Path) -> None:
        rep = tmp_path / "rep.json"
        exc = tmp_path / "exc.json"
        rep.write_text(json.dumps(build_grype_report([])))
        exc.write_text(json.dumps({"version": "1.0", "exceptions": []}))

        # Scanner failed with exit status 2
        res = self.run_validator(rep, exc, scanner_status=2)
        assert res.returncode == vcs.EXIT_OPERATIONAL_ERROR
        assert "Grype scanner terminated with unexpected failure status: 2" in res.stdout

    def test_step_summary_generation(self, tmp_path: Path) -> None:
        rep = tmp_path / "rep.json"
        exc = tmp_path / "exc.json"
        summary = tmp_path / "step_summary.md"

        m = build_grype_match("CVE-2026-9999", "libc6", "2.36", "Critical")
        rep.write_text(json.dumps(build_grype_report([m])))
        exc.write_text(json.dumps({"version": "1.0", "exceptions": []}))

        res = self.run_validator(rep, exc, scanner_status=0, summary_path=summary)
        assert res.returncode == vcs.EXIT_POLICY_VIOLATION
        assert summary.exists()
        content = summary.read_text(encoding="utf-8")
        assert "# DocVault Container Image Security Audit" in content
        assert "FAILED (Policy Violation)" in content
        assert "CVE-2026-9999" in content
        assert "libc6" in content
