#!/usr/bin/env python3
"""DocVault Container Security Scan Validator.

Validates Grype container image vulnerability scan reports against a strict
security exception register, enforces severity policies (blocking on Critical
and High unless authorized), and generates a comprehensive GitHub Step Summary.

Exit code contract:
  0: Scan report is valid, and all findings comply with security policy.
  1: Scan report is valid, but contains unapproved Critical or High findings.
  2: Malformed report, invalid exception register, invalid policy, or scanner error.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import UTC, datetime
from typing import Any

# Exit codes
EXIT_SUCCESS = 0
EXIT_POLICY_VIOLATION = 1
EXIT_OPERATIONAL_ERROR = 2

# Allowed severity enumerations
BLOCKING_SEVERITIES = {"CRITICAL", "HIGH"}
MONITORED_SEVERITIES = {"MEDIUM", "LOW", "NEGLIGIBLE", "UNKNOWN"}
ALL_SEVERITIES = BLOCKING_SEVERITIES | MONITORED_SEVERITIES

# Identifier validation patterns
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
GHSA_PATTERN = re.compile(
    r"^GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}$",
    re.IGNORECASE,
)
CANONICAL_DATE_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def normalize_advisory_id(advisory_id: str) -> str:
    """Normalize advisory ID to uppercase canonical form."""
    return advisory_id.strip().upper()


def is_valid_advisory_id(advisory_id: str) -> bool:
    """Check if an advisory ID matches supported CVE or GHSA patterns."""
    normalized = normalize_advisory_id(advisory_id)
    return bool(CVE_PATTERN.match(normalized) or GHSA_PATTERN.match(normalized))


def normalize_package_name(package_name: str, package_type: str = "") -> str:
    """Normalize package names (PEP 503 for Python, lowercase for OS packages)."""
    clean_name = package_name.strip()
    if package_type.lower() in {"python", "wheel", "egg-info"}:
        return re.sub(r"[-_.]+", "-", clean_name).lower()
    return clean_name.lower()


def parse_canonical_date(date_str: str) -> datetime | None:
    """Validate canonical YYYY-MM-DD date format and return UTC date."""
    if not isinstance(date_str, str) or not CANONICAL_DATE_PATTERN.match(date_str.strip()):
        return None
    try:
        dt = datetime.strptime(date_str.strip(), "%Y-%m-%d").replace(tzinfo=UTC)
        return dt
    except ValueError:
        return None


def is_exception_active(expires_at_str: str, now_utc: datetime) -> tuple[bool, str]:
    """Check if an exception is active under UTC calendar day semantics."""
    dt = parse_canonical_date(expires_at_str)
    if dt is None:
        return False, f"Invalid canonical date format: '{expires_at_str}'"
    # An exception is valid through 23:59:59 UTC of the stated expiration date
    expiration_end = dt.replace(hour=23, minute=59, second=59, microsecond=999999)
    if now_utc > expiration_end:
        return False, f"Exception expired on {expires_at_str} (UTC cutoff: {expiration_end.isoformat()})"
    return True, "Active"


def validate_exception_register(
    exceptions_path: str, now_utc: datetime
) -> tuple[list[dict[str, Any]], list[str]]:
    """Validate the container vulnerability exception register.

    Returns:
      (valid_active_exceptions, validation_errors)
    """
    errors: list[str] = []
    if not os.path.exists(exceptions_path):
        return [], [f"Exception register file not found: {exceptions_path}"]

    try:
        with open(exceptions_path, encoding="utf-8") as f:
            raw_data = json.load(f)
    except (json.JSONDecodeError, OSError, UnicodeDecodeError) as e:
        return [], [f"Failed to parse exception register as JSON: {e}"]

    if not isinstance(raw_data, dict):
        return [], ["Exception register root must be a JSON object."]

    # Root key validation: exactly 'version' and 'exceptions'
    allowed_root_keys = {"version", "exceptions"}
    actual_root_keys = set(raw_data.keys())
    if actual_root_keys != allowed_root_keys:
        unexpected = actual_root_keys - allowed_root_keys
        missing = allowed_root_keys - actual_root_keys
        if unexpected:
            errors.append(f"Unexpected root key(s) in exception register: {sorted(unexpected)}")
        if missing:
            errors.append(f"Missing mandatory root key(s) in exception register: {sorted(missing)}")
        return [], errors

    if raw_data["version"] != "1.0":
        errors.append(f"Unsupported exception register version: '{raw_data['version']}'. Expected '1.0'.")

    exceptions_list = raw_data.get("exceptions")
    if not isinstance(exceptions_list, list):
        errors.append("Root 'exceptions' key must be a list.")
        return [], errors

    valid_exceptions: list[dict[str, Any]] = []
    seen_entries: set[tuple[str, str, str]] = set()
    mandatory_fields = {
        "vulnerability_id",
        "package_name",
        "affected_version",
        "severity",
        "reason",
        "expires_at",
    }

    for idx, entry in enumerate(exceptions_list):
        prefix = f"Exception entry #{idx + 1}"
        if not isinstance(entry, dict):
            errors.append(f"{prefix} must be a JSON object.")
            continue

        entry_keys = set(entry.keys())
        missing_fields = mandatory_fields - entry_keys
        unexpected_fields = entry_keys - mandatory_fields
        if missing_fields:
            errors.append(f"{prefix} missing required field(s): {sorted(missing_fields)}")
            continue
        if unexpected_fields:
            errors.append(f"{prefix} contains unexpected field(s): {sorted(unexpected_fields)}")
            continue

        # Strict string type check
        type_invalid = False
        for field in mandatory_fields:
            val = entry[field]
            if not isinstance(val, str) or not val.strip():
                errors.append(f"{prefix} field '{field}' must be a non-empty string.")
                type_invalid = True
        if type_invalid:
            continue

        vuln_id = normalize_advisory_id(entry["vulnerability_id"])
        pkg_name = entry["package_name"].strip()
        aff_version = entry["affected_version"].strip()
        sev = entry["severity"].strip().upper()
        reason = entry["reason"].strip()
        expires_at = entry["expires_at"].strip()

        # Vulnerability ID format validation
        if not is_valid_advisory_id(vuln_id):
            errors.append(f"{prefix} has invalid vulnerability_id format: '{entry['vulnerability_id']}'")

        # Severity enumeration check
        if sev not in ALL_SEVERITIES:
            errors.append(
                f"{prefix} has invalid severity: '{entry['severity']}'. Expected one of {sorted(ALL_SEVERITIES)}."
            )

        # Expiration date check
        active, reason_exp = is_exception_active(expires_at, now_utc)
        if not active:
            errors.append(f"{prefix} ({vuln_id} on {pkg_name} {aff_version}) is inactive: {reason_exp}")

        # Duplicate detection (package + version + vuln_id)
        dedup_key = (pkg_name.lower(), aff_version, vuln_id)
        if dedup_key in seen_entries:
            errors.append(f"{prefix} is a duplicate exception for {vuln_id} on {pkg_name}=={aff_version}.")
        seen_entries.add(dedup_key)

        valid_exceptions.append(
            {
                "vulnerability_id": vuln_id,
                "package_name": pkg_name,
                "affected_version": aff_version,
                "severity": sev,
                "reason": reason,
                "expires_at": expires_at,
                "raw_entry": entry,
            }
        )

    return valid_exceptions, errors


def parse_and_validate_grype_report(
    report_path: str,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[str]]:
    """Parse Grype JSON report and validate structure.

    Returns:
      (raw_report, extracted_vulnerabilities, validation_errors)
    """
    errors: list[str] = []
    if not os.path.exists(report_path):
        return {}, [], [f"Grype report file does not exist: {report_path}"]

    try:
        with open(report_path, encoding="utf-8") as f:
            raw_data = json.load(f)
    except (json.JSONDecodeError, OSError, UnicodeDecodeError) as e:
        return {}, [], [f"Failed to parse Grype report as JSON: {e}"]

    if not isinstance(raw_data, dict):
        return {}, [], ["Grype report root must be a JSON object."]

    # Validate mandatory top-level keys in Grype JSON specification
    if "matches" not in raw_data or not isinstance(raw_data["matches"], list):
        return {}, [], ["Grype report is missing mandatory top-level 'matches' list."]

    matches = raw_data["matches"]
    extracted: list[dict[str, Any]] = []

    for idx, match in enumerate(matches):
        prefix = f"Grype match #{idx + 1}"
        if not isinstance(match, dict):
            errors.append(f"{prefix} must be a JSON object.")
            continue

        vuln = match.get("vulnerability")
        artifact = match.get("artifact")

        if not isinstance(vuln, dict):
            errors.append(f"{prefix} missing 'vulnerability' object.")
            continue
        if not isinstance(artifact, dict):
            errors.append(f"{prefix} missing 'artifact' object.")
            continue

        vuln_id = vuln.get("id")
        severity = vuln.get("severity")
        pkg_name = artifact.get("name")
        pkg_version = artifact.get("version")
        pkg_type = artifact.get("type", "")

        if not isinstance(vuln_id, str) or not vuln_id.strip():
            errors.append(f"{prefix} missing or invalid vulnerability 'id'.")
            continue
        if not isinstance(severity, str) or not severity.strip():
            errors.append(f"{prefix} missing or invalid vulnerability 'severity'.")
            continue
        if not isinstance(pkg_name, str) or not pkg_name.strip():
            errors.append(f"{prefix} missing or invalid artifact 'name'.")
            continue
        if not isinstance(pkg_version, str) or not pkg_version.strip():
            errors.append(f"{prefix} missing or invalid artifact 'version'.")
            continue

        # Extract related vulnerability aliases (e.g. GHSA or upstream CVEs)
        related_ids: list[str] = []
        for rv in match.get("relatedVulnerabilities", []):
            if isinstance(rv, dict) and isinstance(rv.get("id"), str):
                related_ids.append(normalize_advisory_id(rv["id"]))

        # Extract fix versions if available
        fix_versions: list[str] = []
        fix_obj = vuln.get("fix")
        if isinstance(fix_obj, dict):
            v_list = fix_obj.get("versions")
            if isinstance(v_list, list):
                fix_versions = [str(v) for v in v_list if v is not None]

        extracted.append(
            {
                "id": normalize_advisory_id(vuln_id),
                "aliases": related_ids,
                "severity": severity.strip().upper(),
                "package_name": pkg_name.strip(),
                "package_type": pkg_type.strip(),
                "version": pkg_version.strip(),
                "description": vuln.get("description", ""),
                "fix_versions": fix_versions,
                "raw_match": match,
            }
        )

    return raw_data, extracted, errors


def evaluate_findings(
    findings: list[dict[str, Any]],
    exceptions: list[dict[str, Any]],
) -> tuple[
    list[dict[str, Any]],  # unapproved_blocking (Critical / High)
    list[dict[str, Any]],  # approved_blocking (Critical / High with valid exception)
    list[dict[str, Any]],  # monitored (Medium / Low / Negligible / Unknown)
    list[dict[str, Any]],  # unused_exceptions
]:
    """Evaluate findings against severity policy and authorized exceptions."""
    unapproved_blocking: list[dict[str, Any]] = []
    approved_blocking: list[dict[str, Any]] = []
    monitored: list[dict[str, Any]] = []
    matched_exceptions: set[int] = set()

    for finding in findings:
        sev = finding["severity"]
        pkg_norm = normalize_package_name(finding["package_name"], finding["package_type"])
        finding_ids = {finding["id"]} | set(finding["aliases"])

        # Check for matching exception
        applied_exception: dict[str, Any] | None = None
        for ex_idx, exc in enumerate(exceptions):
            exc_pkg_norm = normalize_package_name(exc["package_name"], finding["package_type"])
            if exc_pkg_norm != pkg_norm:
                continue
            if exc["affected_version"] != finding["version"]:
                continue
            if exc["vulnerability_id"] not in finding_ids:
                continue
            if exc["severity"] != sev:
                continue

            # Matched active exception
            applied_exception = exc
            matched_exceptions.add(ex_idx)
            break

        if sev in BLOCKING_SEVERITIES:
            if applied_exception is not None:
                approved_blocking.append(
                    {
                        "finding": finding,
                        "exception": applied_exception,
                    }
                )
            else:
                unapproved_blocking.append(finding)
        else:
            monitored.append(finding)

    unused_exceptions = [
        exc for ex_idx, exc in enumerate(exceptions) if ex_idx not in matched_exceptions
    ]

    return unapproved_blocking, approved_blocking, monitored, unused_exceptions


def build_markdown_summary(
    total_findings: int,
    unapproved_blocking: list[dict[str, Any]],
    approved_blocking: list[dict[str, Any]],
    monitored: list[dict[str, Any]],
    unused_exceptions: list[dict[str, Any]],
    validation_errors: list[str],
    scanner_status: int,
) -> str:
    """Generate a GitHub Step Summary Markdown report."""
    lines: list[str] = [
        "# DocVault Container Image Security Audit",
        "",
    ]

    if validation_errors:
        lines.extend([
            "### :x: Container Scan Validation Failed",
            "",
            "The validator encountered operational or schema errors:",
            "",
        ])
        for err in validation_errors:
            lines.append(f"- :heavy_exclamation_mark: `{err}`")
        lines.append("")
        return "\n".join(lines)

    status_icon = ":white_check_mark:" if not unapproved_blocking else ":x:"
    status_text = "PASSED" if not unapproved_blocking else "FAILED (Policy Violation)"

    lines.extend([
        f"### {status_icon} Container Vulnerability Gate: **{status_text}**",
        "",
        "| Audit Metric | Count | Pipeline Action |",
        "| :--- | :---: | :--- |",
        f"| **Total Vulnerabilities Detected** | `{total_findings}` | Informational |",
        f"| **Unapproved Critical / High Findings** | `{len(unapproved_blocking)}` | **BLOCKING (Gate Failure)** |",
        f"| **Approved Critical / High Exceptions** | `{len(approved_blocking)}` | Permitted via Exception Register |",
        f"| **Monitored (Medium / Low / Negligible)** | `{len(monitored)}` | Non-blocking (Monitored) |",
        f"| **Unused Exception Warnings** | `{len(unused_exceptions)}` | Non-blocking Warning |",
        "",
    ])

    if unapproved_blocking:
        lines.extend([
            "#### :no_entry: Unapproved Critical and High Vulnerabilities",
            "",
            "| Advisory ID | Package | Installed Version | Severity | Fix Version(s) |",
            "| :--- | :--- | :--- | :---: | :--- |",
        ])
        for f in unapproved_blocking:
            fixes = ", ".join(f["fix_versions"]) if f["fix_versions"] else "None (Unfixed)"
            lines.append(
                f"| `{f['id']}` | `{f['package_name']}` | `{f['version']}` | **{f['severity']}** | {fixes} |"
            )
        lines.append("")

    if approved_blocking:
        lines.extend([
            "#### :white_check_mark: Approved Active Exceptions",
            "",
            "| Advisory ID | Package | Version | Severity | Justification | Expires (UTC) |",
            "| :--- | :--- | :--- | :---: | :--- | :---: |",
        ])
        for item in approved_blocking:
            f = item["finding"]
            exc = item["exception"]
            lines.append(
                f"| `{f['id']}` | `{f['package_name']}` | `{f['version']}` | {f['severity']} | {exc['reason']} | `{exc['expires_at']}` |"
            )
        lines.append("")

    if monitored:
        lines.extend([
            "#### :warning: Monitored Findings (Medium, Low, Negligible, Unknown)",
            "",
            "| Advisory ID | Package | Version | Severity | Fix Version(s) |",
            "| :--- | :--- | :--- | :---: | :--- |",
        ])
        for f in monitored:
            fixes = ", ".join(f["fix_versions"]) if f["fix_versions"] else "None"
            lines.append(
                f"| `{f['id']}` | `{f['package_name']}` | `{f['version']}` | {f['severity']} | {fixes} |"
            )
        lines.append("")

    if unused_exceptions:
        lines.extend([
            "#### :information_source: Unused Exception Warnings",
            "",
            "The following exceptions in `.github/security/container-exceptions.json` did not match any finding in this scan:",
            "",
        ])
        for exc in unused_exceptions:
            lines.append(
                f"- `{exc['vulnerability_id']}` on `{exc['package_name']}=={exc['affected_version']}` (Reason: {exc['reason']})"
            )
        lines.append("")

    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate Grype container image vulnerability scan report against DocVault security policy."
    )
    parser.add_argument("--report", required=True, help="Path to Grype JSON report file")
    parser.add_argument(
        "--exceptions",
        required=True,
        help="Path to container-exceptions.json register",
    )
    parser.add_argument(
        "--scanner-status",
        type=int,
        default=0,
        help="Exit status returned by the Grype scanner command",
    )
    parser.add_argument(
        "--summary",
        default="",
        help="Path to GitHub Step Summary file ($GITHUB_STEP_SUMMARY)",
    )

    args = parser.parse_args()
    now_utc = datetime.now(UTC)
    validation_errors: list[str] = []

    # Check scanner execution status first
    # Note: Grype standard exit status is 0 (clean/no fail-on match) or 1 (vulnerabilities found if fail-on used)
    # Any status >= 2 or negative is an operational scanner crash/error.
    if args.scanner_status not in (0, 1):
        validation_errors.append(
            f"Grype scanner terminated with unexpected failure status: {args.scanner_status}."
        )

    # Validate exception register
    valid_exceptions, exception_errors = validate_exception_register(args.exceptions, now_utc)
    validation_errors.extend(exception_errors)

    # Validate Grype report
    _, findings, report_errors = parse_and_validate_grype_report(args.report)
    validation_errors.extend(report_errors)

    if validation_errors:
        print("[ERROR] Container vulnerability validation failed due to operational or schema errors:")
        for err in validation_errors:
            print(f"  - {err}")
        if args.summary:
            summary_md = build_markdown_summary(
                0, [], [], [], [], validation_errors, args.scanner_status
            )
            try:
                with open(args.summary, "a", encoding="utf-8") as summary_file:
                    summary_file.write(summary_md + "\n")
            except OSError as e:
                print(f"[WARN] Failed to write step summary: {e}", file=sys.stderr)
        return EXIT_OPERATIONAL_ERROR

    # Evaluate findings against policy
    unapproved_blocking, approved_blocking, monitored, unused_exceptions = evaluate_findings(
        findings, valid_exceptions
    )

    # Print console summary
    print("=" * 60)
    print("           DocVault Container Image Security Report          ")
    print("=" * 60)
    print(f"Total vulnerabilities detected:       {len(findings)}")
    print(f"Unapproved Critical / High findings:  {len(unapproved_blocking)}")
    print(f"Approved active exceptions:          {len(approved_blocking)}")
    print(f"Monitored (Medium/Low/Negligible):   {len(monitored)}")
    print(f"Unused exceptions (warnings):        {len(unused_exceptions)}")
    print("-" * 60)

    if unused_exceptions:
        print("[WARNING] The following exceptions were unused in this scan:")
        for exc in unused_exceptions:
            print(f"  - {exc['vulnerability_id']} on {exc['package_name']}=={exc['affected_version']}")

    if unapproved_blocking:
        print("[FAIL] Unapproved Critical or High vulnerabilities found:")
        for finding in unapproved_blocking:
            fixes = ", ".join(finding["fix_versions"]) if finding["fix_versions"] else "None (Unfixed)"
            print(f"  - [{finding['severity']}] {finding['id']} on {finding['package_name']}=={finding['version']} (Fix: {fixes})")

    # Generate GitHub Step Summary if requested
    if args.summary:
        summary_md = build_markdown_summary(
            len(findings),
            unapproved_blocking,
            approved_blocking,
            monitored,
            unused_exceptions,
            [],
            args.scanner_status,
        )
        try:
            with open(args.summary, "a", encoding="utf-8") as summary_file:
                summary_file.write(summary_md + "\n")
        except OSError as e:
            print(f"[WARN] Failed to write step summary: {e}", file=sys.stderr)

    if unapproved_blocking:
        print(f"\nPolicy violation: {len(unapproved_blocking)} unapproved Critical/High vulnerability(ies) present.")
        return EXIT_POLICY_VIOLATION

    print("\nPolicy compliant: All Critical/High findings are approved or zero vulnerabilities detected.")
    return EXIT_SUCCESS


if __name__ == "__main__":
    sys.exit(main())
