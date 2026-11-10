#!/usr/bin/env python3
"""Validate pip-audit JSON report against DocVault exception register and generate Step Summary.

This validator enforces:
1. Complete structural validation of pip-audit JSON report containing 'dependencies' and 'fixes' arrays.
2. Rejection of skipped dependencies to ensure 100% complete audit coverage.
3. Strict JSON typing and PEP 508 / PEP 503 validation on the exception register.
4. Family-specific advisory identifier validation (CVE, GHSA, PYSEC).
5. Bidirectional scanner / report consistency verification.
6. UTC calendar-day expiration rules.
7. Universal GitHub Step Summary generation for all exit paths.
8. Explicit console error annotations.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# Advisory identifier validation patterns (CVE, GHSA, PYSEC)
ADVISORY_PATTERNS = {
    "CVE": re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE),
    "GHSA": re.compile(
        r"^GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}$",
        re.IGNORECASE,
    ),
    "PYSEC": re.compile(r"^PYSEC-\d{4}-\d+$", re.IGNORECASE),
}

PEP508_PACKAGE_PATTERN = re.compile(r"^[A-Z0-9]([A-Z0-9._-]*[A-Z0-9])?$", re.IGNORECASE)
DATE_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}$")

ROOT_ALLOWED_KEYS = {"version", "exceptions"}
REPORT_ALLOWED_ROOT_KEYS = {"dependencies", "fixes"}
REQUIRED_EXCEPTION_FIELDS = {
    "vulnerability_id",
    "package_name",
    "affected_version",
    "technical_justification",
    "compensating_controls",
    "reviewer_approval",
    "tracking_issue",
    "expiration_date",
}
ALLOWED_EXCEPTION_FIELDS = REQUIRED_EXCEPTION_FIELDS | {"severity"}
VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}


def is_non_empty_str(val: Any) -> bool:
    """Validate that val is a genuine JSON string and not empty or whitespace-only."""
    return isinstance(val, str) and bool(val.strip())


def is_valid_advisory_id(val: str) -> bool:
    """Full-string match against supported CVE, GHSA, or PYSEC patterns."""
    return any(p.fullmatch(val) is not None for p in ADVISORY_PATTERNS.values())


def is_valid_package_name(name: str) -> bool:
    """Strict full-string validation of package name per PEP 508."""
    return PEP508_PACKAGE_PATTERN.fullmatch(name) is not None


def normalize_package_name(name: str) -> str:
    """Normalize package name per PEP 503."""
    return re.sub(r"[-_.]+", "-", name).lower()


def normalize_advisory_id(val: str) -> str:
    """Canonical uppercase normalization of advisory identifier."""
    return val.strip().upper()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate pip-audit report against exception register.")
    parser.add_argument("--report", default="pip-audit-report.json", help="Path to pip-audit JSON report.")
    parser.add_argument(
        "--exceptions",
        default=".github/security/dependency-exceptions.json",
        help="Path to machine-readable exception register.",
    )
    parser.add_argument("--audit-status", type=int, default=0, help="Raw exit code from pip-audit execution.")
    parser.add_argument("--summary", default="", help="Path to GITHUB_STEP_SUMMARY markdown file.")
    return parser.parse_args()


def load_exception_register(path: Path) -> tuple[list[dict[str, Any]], list[str]]:
    """Load and validate the exception register. Returns (valid_exceptions, fatal_errors)."""
    errors: list[str] = []
    if not path.is_file():
        return [], [f"Exception register not found at '{path}'."]

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        return [], [f"Failed to parse exception register '{path}': {e}"]

    if not isinstance(data, dict):
        return [], [f"Exception register root must be a JSON object, got {type(data).__name__}."]

    root_keys = set(data.keys())
    if root_keys != ROOT_ALLOWED_KEYS:
        unknown = root_keys - ROOT_ALLOWED_KEYS
        missing = ROOT_ALLOWED_KEYS - root_keys
        if unknown:
            errors.append(f"Exception register root contains forbidden unknown keys: {sorted(unknown)}.")
        if missing:
            errors.append(f"Exception register root is missing required keys: {sorted(missing)}.")

    version = data.get("version")
    if not is_non_empty_str(version) or version != "1.0":
        errors.append(f"Exception register 'version' must be literal '1.0', got {version!r}.")

    exceptions = data.get("exceptions")
    if not isinstance(exceptions, list):
        return [], errors + [f"Exception register 'exceptions' must be a JSON array, got {type(exceptions).__name__}."]

    validated_exceptions: list[dict[str, Any]] = []
    seen_keys: set[tuple[str, str, str]] = set()
    today_utc = datetime.now(UTC).date()

    for idx, entry in enumerate(exceptions):
        if not isinstance(entry, dict):
            errors.append(f"Exception entry [{idx}] must be a JSON object, got {type(entry).__name__}.")
            continue

        entry_keys = set(entry.keys())
        unknown_fields = entry_keys - ALLOWED_EXCEPTION_FIELDS
        if unknown_fields:
            errors.append(f"Exception entry [{idx}] contains forbidden unknown fields: {sorted(unknown_fields)}.")
            continue

        missing_fields = REQUIRED_EXCEPTION_FIELDS - entry_keys
        if missing_fields:
            errors.append(f"Exception entry [{idx}] is missing required fields: {sorted(missing_fields)}.")
            continue

        field_type_invalid = False
        for field in REQUIRED_EXCEPTION_FIELDS:
            if not is_non_empty_str(entry[field]):
                errors.append(
                    f"Exception entry [{idx}] field '{field}' must be a non-empty string, got {entry[field]!r}."
                )
                field_type_invalid = True

        if field_type_invalid:
            continue

        vuln_id = entry["vulnerability_id"].strip()
        pkg_raw = entry["package_name"].strip()
        pkg_ver = entry["affected_version"].strip()
        exp_str = entry["expiration_date"].strip()
        justification = entry["technical_justification"].strip()

        if len(justification) < 20:
            errors.append(f"Exception entry [{idx}] 'technical_justification' must be at least 20 characters.")
            continue

        if not is_valid_advisory_id(vuln_id):
            errors.append(
                f"Exception entry [{idx}] contains invalid advisory identifier '{vuln_id}'. "
                "Must match supported CVE, GHSA, or PYSEC patterns."
            )
            continue

        if not is_valid_package_name(pkg_raw):
            errors.append(
                f"Exception entry [{idx}] contains invalid package name '{pkg_raw}' per PEP 508."
            )
            continue

        pkg_name = normalize_package_name(pkg_raw)

        if "severity" in entry:
            sev = entry["severity"]
            if not isinstance(sev, str) or sev not in VALID_SEVERITIES:
                errors.append(
                    f"Exception entry [{idx}] optional field 'severity' must be exactly one of {sorted(VALID_SEVERITIES)} "
                    f"(exact casing, no whitespace padding), got {sev!r}."
                )
                continue

        unique_key = (normalize_advisory_id(vuln_id), pkg_name, pkg_ver)
        if unique_key in seen_keys:
            errors.append(
                f"Duplicate exception entry [{idx}] for ID '{vuln_id}', package '{pkg_name}', version '{pkg_ver}'."
            )
            continue
        seen_keys.add(unique_key)

        if not DATE_PATTERN.fullmatch(exp_str):
            errors.append(
                f"Exception entry [{idx}] date '{exp_str}' does not conform to canonical 'YYYY-MM-DD' format."
            )
            continue

        try:
            exp_date = datetime.strptime(exp_str, "%Y-%m-%d").date()
        except ValueError:
            errors.append(f"Exception entry [{idx}] contains invalid calendar date '{exp_str}'.")
            continue

        if today_utc > exp_date:
            errors.append(
                f"EXPIRED EXCEPTION: Entry [{idx}] for '{vuln_id}' ({pkg_name}=={pkg_ver}) expired on {exp_str}."
            )
            continue

        validated_exceptions.append(
            {
                "vulnerability_id": vuln_id,
                "package_name": pkg_name,
                "affected_version": pkg_ver,
                "expiration_date": exp_str,
                "reviewer_approval": entry["reviewer_approval"].strip(),
                "tracking_issue": entry["tracking_issue"].strip(),
            }
        )

    return validated_exceptions, errors


def load_scan_report(path: Path) -> tuple[list[dict[str, Any]], list[str]]:
    """Load and structurally validate pip-audit JSON report containing 'dependencies' and 'fixes'.

    Returns (packages, fatal_errors).
    """
    if not path.is_file():
        return [], [f"pip-audit report file '{path}' does not exist."]

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        return [], [f"Failed to parse pip-audit report '{path}': {e}"]

    if not isinstance(data, dict):
        return [], [f"pip-audit report root must be a JSON object, got {type(data).__name__}."]

    errors: list[str] = []
    root_keys = set(data.keys())
    if root_keys != REPORT_ALLOWED_ROOT_KEYS:
        missing = REPORT_ALLOWED_ROOT_KEYS - root_keys
        unknown = root_keys - REPORT_ALLOWED_ROOT_KEYS
        if missing:
            errors.append(f"pip-audit report root is missing required keys: {sorted(missing)}.")
        if unknown:
            errors.append(f"pip-audit report root contains unexpected keys: {sorted(unknown)}.")
        return [], errors

    deps = data.get("dependencies")
    if not isinstance(deps, list):
        errors.append(f"pip-audit report 'dependencies' must be a JSON array, got {type(deps).__name__}.")

    fixes = data.get("fixes")
    if not isinstance(fixes, list):
        errors.append(f"pip-audit report 'fixes' must be a JSON array, got {type(fixes).__name__}.")

    if errors:
        return [], errors

    for f_idx, fix in enumerate(fixes):
        if not isinstance(fix, dict):
            errors.append(f"Report fix [{f_idx}] must be a JSON object, got {type(fix).__name__}.")

    validated_packages: list[dict[str, Any]] = []

    for p_idx, pkg in enumerate(deps):
        if not isinstance(pkg, dict):
            errors.append(f"Report package [{p_idx}] must be a JSON object, got {type(pkg).__name__}.")
            continue

        if "skip_reason" in pkg or pkg.get("skip_reason") is not None:
            pkg_name = pkg.get("name", f"dependency[{p_idx}]")
            reason = pkg.get("skip_reason", "unspecified reason")
            errors.append(
                f"Incomplete audit failure: Package '{pkg_name}' was skipped by scanner: {reason}. "
                "Auditing must evaluate 100% of declared dependencies."
            )
            continue

        name = pkg.get("name")
        version = pkg.get("version")
        vulns = pkg.get("vulns")

        if not is_non_empty_str(name) or not is_valid_package_name(name):
            errors.append(f"Report package [{p_idx}] contains invalid or missing 'name': {name!r}.")
            continue

        if not is_non_empty_str(version):
            errors.append(f"Report package [{p_idx}] contains invalid or missing 'version': {version!r}.")
            continue

        if not isinstance(vulns, list):
            errors.append(f"Report package [{p_idx}] 'vulns' must be a JSON array, got {type(vulns).__name__}.")
            continue

        validated_vulns: list[dict[str, Any]] = []
        for v_idx, v in enumerate(vulns):
            if not isinstance(v, dict):
                errors.append(f"Package '{name}' vuln [{v_idx}] must be a JSON object, got {type(v).__name__}.")
                continue

            v_id = v.get("id")
            if not is_non_empty_str(v_id) or not is_valid_advisory_id(v_id):
                errors.append(f"Package '{name}' vuln [{v_idx}] has invalid advisory ID: {v_id!r}.")
                continue

            if "fix_versions" in v:
                fix_versions = v["fix_versions"]
                if fix_versions is None or not isinstance(fix_versions, list) or not all(is_non_empty_str(fv) for fv in fix_versions):
                    errors.append(
                        f"Package '{name}' vuln '{v_id}' 'fix_versions' must be a list of non-empty strings, got {fix_versions!r}."
                    )
                    continue

            if "aliases" in v:
                aliases = v["aliases"]
                if aliases is None or not isinstance(aliases, list) or not all(is_non_empty_str(al) and is_valid_advisory_id(al) for al in aliases):
                    errors.append(
                        f"Package '{name}' vuln '{v_id}' contains invalid or unsupported alias identifier(s): {aliases!r}."
                    )
                    continue

            if "description" in v:
                desc = v["description"]
                if desc is None or not isinstance(desc, str):
                    errors.append(
                        f"Package '{name}' vuln '{v_id}' 'description' must be a string if present, got {desc!r}."
                    )
                    continue

            validated_vulns.append(v)

        validated_packages.append({"name": name, "version": version, "vulns": validated_vulns})

    if errors:
        return [], errors

    return validated_packages, []


def match_exception(
    vuln_id: str,
    aliases: list[str],
    pkg_name: str,
    pkg_ver: str,
    exceptions: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """Find a matching exception by normalized package name, exact version, and advisory ID or alias."""
    norm_pkg = normalize_package_name(pkg_name)
    target_ids = {normalize_advisory_id(vuln_id)} | {normalize_advisory_id(a) for a in aliases}

    for ex in exceptions:
        if ex["package_name"] == norm_pkg and ex["affected_version"] == pkg_ver and normalize_advisory_id(ex["vulnerability_id"]) in target_ids:
            return ex
    return None


def write_step_summary(
    summary_path: Path | None,
    total_dependencies: int,
    total_vulns: int,
    suppressed_vulns: list[dict[str, Any]],
    unauthorized_vulns: list[dict[str, Any]],
    warnings: list[str],
    fatal_errors: list[str],
) -> None:
    """Write markdown summary to GITHUB_STEP_SUMMARY (supplementary, non-fatal on write errors)."""
    if not summary_path:
        return

    try:
        with summary_path.open("a", encoding="utf-8") as s:
            s.write("## 🛡️ Dependency Vulnerability Audit Summary\n\n")

            if fatal_errors:
                s.write("### ❌ Operational & Validation Failures\n\n")
                for err in fatal_errors:
                    s.write(f"- 🛑 {err}\n")
                s.write("\n")

            s.write(f"- **Audited packages:** `{total_dependencies}`\n")
            s.write(f"- **Total vulnerabilities detected:** `{total_vulns}`\n")
            s.write(f"- **Approved exceptions applied:** `{len(suppressed_vulns)}`\n")
            s.write(f"- **Unauthorized vulnerabilities:** `{len(unauthorized_vulns)}`\n\n")

            if unauthorized_vulns:
                s.write("### 🚨 Unauthorized Vulnerabilities (Gate Blocked)\n\n")
                s.write("| Package | Version | Advisory ID | Fix Versions | Description |\n")
                s.write("|---|---|---|---|---|\n")
                for u in unauthorized_vulns:
                    s.write(f"| `{u['package']}` | `{u['version']}` | **{u['id']}** | `{u['fixes']}` | {u['desc']}... |\n")
                s.write("\n")

            if suppressed_vulns:
                s.write("### ⚠️ Approved Exceptions Applied\n\n")
                s.write("| Package | Version | Advisory ID | Approved By | Expiration Date |\n")
                s.write("|---|---|---|---|---|\n")
                for sup in suppressed_vulns:
                    s.write(f"| `{sup['package']}` | `{sup['version']}` | `{sup['id']}` | {sup['approval']} | `{sup['expires']}` |\n")
                s.write("\n")

            if warnings:
                s.write("### ⚠️ Warnings (Unused Exceptions)\n\n")
                for w in warnings:
                    s.write(f"- {w}\n")
                s.write("\n")

            if not fatal_errors and not unauthorized_vulns:
                s.write("✅ **All audited dependencies satisfy the DocVault zero-vulnerability security policy.**\n")
    except OSError as e:
        print(f"::error::Failed writing step summary (non-fatal): {e}", file=sys.stderr)


def main() -> int:
    args = parse_args()
    report_path = Path(args.report)
    exceptions_path = Path(args.exceptions)
    summary_path = Path(args.summary) if args.summary else None

    fatal_errors: list[str] = []
    warnings: list[str] = []

    # Defensive validation of scanner exit status
    if args.audit_status not in (0, 1):
        fatal_errors.append(
            f"Operational error: pip-audit exited with unexpected status code {args.audit_status}. "
            "Vulnerability scan did not complete cleanly."
        )

    # Load register and report
    active_exceptions, reg_errors = load_exception_register(exceptions_path)
    fatal_errors.extend(reg_errors)

    packages, report_errors = load_scan_report(report_path)
    fatal_errors.extend(report_errors)

    total_dependencies = len(packages)
    total_vulns = sum(len(pkg.get("vulns", [])) for pkg in packages)
    suppressed_vulns: list[dict[str, Any]] = []
    unauthorized_vulns: list[dict[str, Any]] = []

    # Bidirectional Scanner / Report Consistency Enforcement
    if not fatal_errors:
        if args.audit_status == 0 and total_vulns != 0:
            fatal_errors.append(
                f"Inconsistency failure: pip-audit exited 0 (clean) but report contains {total_vulns} vulnerabilities."
            )
        elif args.audit_status == 1 and total_vulns == 0:
            fatal_errors.append(
                "Inconsistency failure: pip-audit exited 1 (findings detected) but report contains 0 vulnerabilities."
            )

    # If fatal errors occurred prior to evaluation, write summary and exit
    if fatal_errors:
        print("=== DEPENDENCY AUDIT VALIDATION FAILED ===", file=sys.stderr)
        for err in fatal_errors:
            print(f"::error::{err}", file=sys.stderr)
        write_step_summary(summary_path, total_dependencies, total_vulns, [], [], [], fatal_errors)
        return 1

    # Match vulnerabilities against exceptions
    used_exceptions: set[tuple[str, str, str]] = set()

    for pkg in packages:
        pkg_name = pkg["name"]
        pkg_version = pkg["version"]
        vulns = pkg["vulns"]

        for v in vulns:
            vuln_id = v["id"]
            aliases = v.get("aliases") or []
            desc = (v.get("description") or "").replace("\n", " ")[:90]
            fixes = ", ".join(v.get("fix_versions") or []) or "None"

            matched_ex = match_exception(vuln_id, aliases, pkg_name, pkg_version, active_exceptions)
            if matched_ex:
                used_exceptions.add((normalize_advisory_id(matched_ex["vulnerability_id"]), matched_ex["package_name"], matched_ex["affected_version"]))
                suppressed_vulns.append({
                    "package": pkg_name,
                    "version": pkg_version,
                    "id": vuln_id,
                    "fixes": fixes,
                    "desc": desc,
                    "approval": matched_ex["reviewer_approval"],
                    "expires": matched_ex["expiration_date"],
                })
            else:
                unauthorized_vulns.append({
                    "package": pkg_name,
                    "version": pkg_version,
                    "id": vuln_id,
                    "fixes": fixes,
                    "desc": desc,
                })

    # Detect unused exceptions
    for ex in active_exceptions:
        key = (normalize_advisory_id(ex["vulnerability_id"]), ex["package_name"], ex["affected_version"])
        if key not in used_exceptions:
            msg = f"Unused exception for package '{ex['package_name']}' (ID: '{ex['vulnerability_id']}')."
            warnings.append(msg)
            print(f"::warning::{msg}")

    # Console Output
    print("\n========================================================")
    print("        DocVault Dependency Security Audit Report       ")
    print("========================================================")
    print(f"Total packages audited:      {total_dependencies}")
    print(f"Total vulnerabilities found:  {total_vulns}")
    print(f"Approved active exceptions:   {len(suppressed_vulns)}")
    print(f"Unauthorized vulnerabilities: {len(unauthorized_vulns)}")
    print(f"Unused exceptions (warnings): {len(warnings)}")
    print("--------------------------------------------------------")

    if unauthorized_vulns:
        print("\nUNAUTHORIZED VULNERABILITIES (FAILING CI GATE):")
        for u in unauthorized_vulns:
            print(f"  - {u['package']}=={u['version']} | {u['id']} | Fixed in: {u['fixes']}")
            print(f"    Desc: {u['desc']}...")

    if suppressed_vulns:
        print("\nAPPROVED EXCEPTIONS (ACTIVE):")
        for s in suppressed_vulns:
            print(f"  - {s['package']}=={s['version']} | {s['id']} | Approved by: {s['approval']} (Expires: {s['expires']})")

    # Step Summary Output
    write_step_summary(summary_path, total_dependencies, total_vulns, suppressed_vulns, unauthorized_vulns, warnings, fatal_errors)

    if unauthorized_vulns:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
