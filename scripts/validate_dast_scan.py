#!/usr/bin/env python3
"""DocVault OWASP ZAP DAST Scan Validator.

Validates OWASP ZAP DAST scan reports against a strict security exception register,
enforces severity policies (blocking on Critical, High, and Medium findings unless
explicitly approved with non-blanket endpoint targeting), rejects expired or duplicate
exceptions, and generates a comprehensive GitHub Step Summary.

Exit code contract:
  0: All findings comply with policy (no unapproved High/Medium findings, no expired exceptions).
  1: Policy violation: unapproved High/Medium findings or expired exceptions present.
  2: Operational or configuration failure: missing/malformed report, invalid register schema,
     malformed alert structure, unknown severity, duplicate exceptions, or scanner error.
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

# Allowed severity levels
BLOCKING_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM"}
MONITORED_SEVERITIES = {"LOW", "INFORMATIONAL"}
ALL_SEVERITIES = BLOCKING_SEVERITIES | MONITORED_SEVERITIES

# Canonical date pattern (YYYY-MM-DD)
CANONICAL_DATE_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}$")

# Risk code to severity mapping (ZAP risk codes: 3=High, 2=Medium, 1=Low, 0=Informational)
RISK_CODE_MAP: dict[int | str, str] = {
    0: "INFORMATIONAL",
    1: "LOW",
    2: "MEDIUM",
    3: "HIGH",
    "0": "INFORMATIONAL",
    "1": "LOW",
    "2": "MEDIUM",
    "3": "HIGH",
}

# Standard severity name mapping
SEVERITY_NAME_MAP: dict[str, str] = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "INFORMATIONAL": "INFORMATIONAL",
    "INFO": "INFORMATIONAL",
}

# Disallowed blanket suppression patterns
BLANKET_PATTERNS = {
    ".*",
    "^.*$",
    "^.*",
    ".*$",
    ".+",
    "^.+$",
    "^.+",
    ".+$",
    "*",
    "",
    ".*?",
    ".+?",
}


def parse_canonical_date(date_str: str) -> datetime | None:
    """Validate canonical YYYY-MM-DD date format and return UTC date."""
    if not isinstance(date_str, str) or not CANONICAL_DATE_PATTERN.match(date_str.strip()):
        return None
    try:
        return datetime.strptime(date_str.strip(), "%Y-%m-%d").replace(tzinfo=UTC)
    except ValueError:
        return None


def is_exception_active(expires_at_str: str, now_utc: datetime) -> tuple[bool, str]:
    """Check if an exception is active under UTC calendar day semantics."""
    dt = parse_canonical_date(expires_at_str)
    if dt is None:
        return False, f"Invalid canonical date format: '{expires_at_str}' (expected YYYY-MM-DD)"
    # Valid through 23:59:59 UTC of the expiration date
    expiration_end = dt.replace(hour=23, minute=59, second=59, microsecond=999999)
    if now_utc > expiration_end:
        return False, f"Exception expired on {expires_at_str} (UTC cutoff: {expiration_end.isoformat()})"
    return True, "Active"


def is_blanket_suppression(pattern: str) -> bool:
    """Check if a target URL pattern is an overly broad blanket suppression."""
    stripped = pattern.strip()
    if stripped in BLANKET_PATTERNS:
        return True

    # Strip regex anchor boundaries
    norm = stripped.lstrip("^").rstrip("$")

    # Strip optional scheme + host prefix (e.g., http://127.0.0.1:8002 or https?://[^/]+)
    norm = re.sub(r"^https?://(\[[^\]]+\]|[^/]+)", "", norm, flags=re.IGNORECASE)

    # Check remaining path component
    norm = norm.strip()
    return norm in {"", "/.*", "/.+", "/.*?", "/.+?", ".*", ".+", "*"}


def normalize_severity(raw_severity: Any) -> str:
    """Normalize raw ZAP severity representation to canonical uppercase string.

    Raises:
        ValueError: If raw_severity is missing, malformed, or unrecognized.
    """
    if raw_severity is None:
        raise ValueError("Severity is missing or None")

    if isinstance(raw_severity, int) and raw_severity in RISK_CODE_MAP:
        return RISK_CODE_MAP[raw_severity]

    if isinstance(raw_severity, str):
        clean = raw_severity.strip()
        if not clean:
            raise ValueError("Severity string is empty")

        if clean in RISK_CODE_MAP:
            return RISK_CODE_MAP[clean]

        # Extract primary risk word, e.g. "High (Medium)" -> "High"
        primary = re.split(r"[\s(]+", clean)[0].strip().upper()
        if primary in SEVERITY_NAME_MAP:
            return SEVERITY_NAME_MAP[primary]

    raise ValueError(f"Unknown or invalid severity value: '{raw_severity}'")


def validate_exception_register(
    exceptions_path: str, now_utc: datetime
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    """Validate DAST exception register schema, dates, and non-blanket constraints.

    Returns:
        (active_exceptions, expired_exceptions, operational_errors)
    """
    errors: list[str] = []
    active_exceptions: list[dict[str, Any]] = []
    expired_exceptions: list[dict[str, Any]] = []

    if not os.path.exists(exceptions_path):
        return [], [], [f"Exception register file not found: {exceptions_path}"]

    try:
        with open(exceptions_path, encoding="utf-8") as f:
            raw_data = json.load(f)
    except (json.JSONDecodeError, OSError, UnicodeDecodeError) as e:
        return [], [], [f"Failed to parse exception register JSON ({exceptions_path}): {e}"]

    if not isinstance(raw_data, dict):
        return [], [], ["Exception register root must be a JSON object"]

    if raw_data.get("version") != "1.0":
        errors.append(f"Invalid exception register version: expected '1.0', got '{raw_data.get('version')}'")

    exceptions_list = raw_data.get("exceptions")
    if not isinstance(exceptions_list, list):
        errors.append("Field 'exceptions' must be a JSON array")
        return [], [], errors

    required_fields = {
        "zap_rule_id",
        "alert_name",
        "target_url_pattern",
        "severity",
        "reason",
        "expires_at",
    }
    seen_keys: set[tuple[str, str]] = set()

    for idx, exc in enumerate(exceptions_list):
        prefix = f"Exception entry #{idx + 1}"
        if not isinstance(exc, dict):
            errors.append(f"{prefix} is not a JSON object")
            continue

        missing = required_fields - set(exc.keys())
        if missing:
            errors.append(f"{prefix} missing required field(s): {', '.join(sorted(missing))}")
            continue

        rule_id_raw = exc.get("zap_rule_id")
        if isinstance(rule_id_raw, (int, str)) and str(rule_id_raw).strip():
            rule_id = str(rule_id_raw).strip()
        else:
            errors.append(f"{prefix}: 'zap_rule_id' must be a non-empty string or integer")
            continue

        alert_name = exc.get("alert_name")
        if not isinstance(alert_name, str) or not alert_name.strip():
            errors.append(f"{prefix}: 'alert_name' must be a non-empty string")

        url_pattern = exc.get("target_url_pattern")
        if not isinstance(url_pattern, str) or not url_pattern.strip():
            errors.append(f"{prefix}: 'target_url_pattern' must be a non-empty string")
            continue

        # Prevent blanket wildcard suppressions
        if is_blanket_suppression(url_pattern):
            errors.append(
                f"{prefix}: Blanket suppression pattern '{url_pattern}' is not permitted; "
                "exceptions must specify a targeted endpoint or path pattern."
            )
            continue

        # Validate regex compilability
        try:
            re.compile(url_pattern)
        except re.error as e:
            errors.append(f"{prefix}: Invalid regular expression in 'target_url_pattern' ('{url_pattern}'): {e}")
            continue

        # Check for duplicate exceptions
        dup_key = (rule_id, url_pattern.strip())
        if dup_key in seen_keys:
            errors.append(
                f"{prefix}: Duplicate exception entry for rule '{rule_id}' with pattern '{url_pattern}'."
            )
            continue
        seen_keys.add(dup_key)

        # Validate severity
        sev_raw = exc.get("severity")
        if not isinstance(sev_raw, str) or sev_raw.strip().upper() not in BLOCKING_SEVERITIES:
            errors.append(
                f"{prefix}: 'severity' must be one of {sorted(BLOCKING_SEVERITIES)}, got '{sev_raw}'"
            )
            continue
        norm_sev = sev_raw.strip().upper()

        # Validate reason
        reason = exc.get("reason")
        if not isinstance(reason, str) or len(reason.strip()) < 10:
            errors.append(f"{prefix}: 'reason' must be a descriptive string of at least 10 characters")

        # Validate expiration date
        expires_at = exc.get("expires_at")
        if not isinstance(expires_at, str) or parse_canonical_date(expires_at) is None:
            errors.append(f"{prefix}: 'expires_at' must be a canonical YYYY-MM-DD date, got '{expires_at}'")
            continue

        is_active, status_msg = is_exception_active(expires_at, now_utc)
        exc_record = {
            "zap_rule_id": rule_id,
            "alert_name": str(alert_name).strip() if alert_name else "",
            "target_url_pattern": url_pattern.strip(),
            "severity": norm_sev,
            "reason": str(reason).strip() if reason else "",
            "expires_at": expires_at.strip(),
            "status": status_msg,
        }

        if is_active:
            active_exceptions.append(exc_record)
        else:
            expired_exceptions.append(exc_record)

    return active_exceptions, expired_exceptions, errors


def parse_zap_report(report_path: str) -> tuple[list[dict[str, Any]], list[str]]:
    """Parse an OWASP ZAP JSON scan report and extract alert instances.

    Returns:
        (findings, operational_errors)
    """
    errors: list[str] = []
    findings: list[dict[str, Any]] = []

    if not os.path.exists(report_path):
        return [], [f"ZAP report file not found: {report_path}"]

    try:
        with open(report_path, encoding="utf-8") as f:
            raw_data = json.load(f)
    except (json.JSONDecodeError, OSError, UnicodeDecodeError) as e:
        return [], [f"Failed to parse ZAP report JSON ({report_path}): {e}"]

    if not isinstance(raw_data, dict):
        return [], ["ZAP report root must be a JSON object"]

    # Extract alerts from standard ZAP JSON structures
    alerts_to_process: list[dict[str, Any]] = []

    if "site" in raw_data:
        sites = raw_data["site"]
        if isinstance(sites, dict):
            sites = [sites]
        elif not isinstance(sites, list):
            return [], ["Field 'site' in ZAP report must be a list or object"]

        for site_idx, site in enumerate(sites):
            if not isinstance(site, dict):
                errors.append(f"Site entry #{site_idx + 1} is not a JSON object")
                continue
            site_alerts = site.get("alerts", [])
            if isinstance(site_alerts, dict):
                site_alerts = [site_alerts]
            elif not isinstance(site_alerts, list):
                errors.append(f"Site '{site.get('@name', site_idx)}' alerts field must be a list or object")
                continue
            alerts_to_process.extend(site_alerts)
    elif "alerts" in raw_data:
        top_alerts = raw_data["alerts"]
        if isinstance(top_alerts, dict):
            top_alerts = [top_alerts]
        elif not isinstance(top_alerts, list):
            return [], ["Field 'alerts' in ZAP report must be a list or object"]
        alerts_to_process.extend(top_alerts)
    elif not raw_data:
        # Empty report represents 0 findings
        return [], []
    else:
        # Check if report has any recognized alerts structure or is a clean report
        # If it has keys like @version or @generated with no site/alerts, that's clean
        known_top_keys = {"@version", "@generated", "generated", "version"}
        if set(raw_data.keys()).issubset(known_top_keys):
            return [], []
        return [], ["ZAP report does not contain recognizable 'site' or 'alerts' structures"]

    for alert_idx, alert in enumerate(alerts_to_process):
        prefix = f"Alert #{alert_idx + 1}"
        if not isinstance(alert, dict):
            errors.append(f"{prefix} is not a JSON object")
            continue

        # Extract rule ID
        rule_id_raw = (
            alert.get("pluginid")
            or alert.get("alertRef")
            or alert.get("rule_id")
            or alert.get("id")
        )
        if rule_id_raw is None or not str(rule_id_raw).strip():
            errors.append(f"{prefix}: Missing or empty rule identifier ('pluginid'/'alertRef')")
            continue
        rule_id = str(rule_id_raw).strip()

        # Extract alert name
        alert_name = alert.get("alert") or alert.get("name")
        if not isinstance(alert_name, str) or not alert_name.strip():
            errors.append(f"{prefix} (rule {rule_id}): Missing or empty alert name")
            alert_name = f"Unknown Alert (Rule {rule_id})"
        else:
            alert_name = alert_name.strip()

        # Extract and normalize severity
        raw_sev = (
            alert.get("riskdesc")
            if alert.get("riskdesc") is not None
            else alert.get("riskcode")
            if alert.get("riskcode") is not None
            else alert.get("risk")
            if alert.get("risk") is not None
            else alert.get("severity")
        )

        try:
            severity = normalize_severity(raw_sev)
        except ValueError as e:
            errors.append(f"{prefix} ('{alert_name}', rule {rule_id}): {e}")
            continue

        # Extract instances
        instances = alert.get("instances")
        instance_list: list[dict[str, Any]] = []
        if isinstance(instances, list) and instances:
            for inst_idx, inst in enumerate(instances):
                if not isinstance(inst, dict):
                    errors.append(f"{prefix} ('{alert_name}'): Instance #{inst_idx + 1} is not a JSON object")
                    continue
                uri = inst.get("uri") or inst.get("url")
                if not isinstance(uri, str) or not uri.strip():
                    errors.append(f"{prefix} ('{alert_name}'): Instance #{inst_idx + 1} missing 'uri'")
                    continue
                instance_list.append(
                    {
                        "uri": uri.strip(),
                        "method": str(inst.get("method", "GET")).strip(),
                        "param": str(inst.get("param", "")).strip(),
                    }
                )
        elif isinstance(instances, dict):
            uri = instances.get("uri") or instances.get("url")
            if isinstance(uri, str) and uri.strip():
                instance_list.append(
                    {
                        "uri": uri.strip(),
                        "method": str(instances.get("method", "GET")).strip(),
                        "param": str(instances.get("param", "")).strip(),
                    }
                )
        elif alert.get("uri") or alert.get("url"):
            uri = alert.get("uri") or alert.get("url")
            if isinstance(uri, str) and uri.strip():
                instance_list.append(
                    {
                        "uri": uri.strip(),
                        "method": str(alert.get("method", "GET")).strip(),
                        "param": str(alert.get("param", "")).strip(),
                    }
                )

        if not instance_list:
            errors.append(
                f"{prefix} ('{alert_name}', rule {rule_id}): Malformed alert structure: "
                "no valid instances or URI found"
            )
            continue

        for inst in instance_list:
            findings.append(
                {
                    "rule_id": rule_id,
                    "name": alert_name,
                    "severity": severity,
                    "uri": inst["uri"],
                    "method": inst["method"],
                    "param": inst["param"],
                    "solution": str(alert.get("solution", "")).strip(),
                    "cweid": str(alert.get("cweid", "")).strip(),
                }
            )

    return findings, errors


def evaluate_dast_findings(
    findings: list[dict[str, Any]],
    active_exceptions: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Evaluate findings against active exceptions and severity thresholds.

    Returns:
        (unapproved_blocking, approved_blocking, monitored, unused_exceptions)
    """
    unapproved_blocking: list[dict[str, Any]] = []
    approved_blocking: list[dict[str, Any]] = []
    monitored: list[dict[str, Any]] = []
    used_exception_ids: set[int] = set()

    for finding in findings:
        sev = finding["severity"]
        if sev in MONITORED_SEVERITIES:
            monitored.append(finding)
            continue

        # Must be in BLOCKING_SEVERITIES (CRITICAL, HIGH, MEDIUM)
        matched_exc: dict[str, Any] | None = None
        for exc in active_exceptions:
            # 1. Rule ID match
            if exc["zap_rule_id"] != finding["rule_id"]:
                continue

            # 2. Severity match
            if exc["severity"] != finding["severity"]:
                continue

            # 3. Targeted endpoint pattern match
            if re.search(exc["target_url_pattern"], finding["uri"]) is not None:
                matched_exc = exc
                used_exception_ids.add(id(exc))
                break

        if matched_exc is not None:
            approved_blocking.append({"finding": finding, "matched_exception": matched_exc})
        else:
            unapproved_blocking.append(finding)

    unused_exceptions = [exc for exc in active_exceptions if id(exc) not in used_exception_ids]
    return unapproved_blocking, approved_blocking, monitored, unused_exceptions


def build_markdown_summary(
    total_findings: int,
    unapproved_blocking: list[dict[str, Any]],
    approved_blocking: list[dict[str, Any]],
    monitored: list[dict[str, Any]],
    expired_exceptions: list[dict[str, Any]],
    unused_exceptions: list[dict[str, Any]],
    operational_errors: list[str],
    scanner_status: int,
) -> str:
    """Build a comprehensive GitHub Step Summary in Markdown."""
    lines: list[str] = ["### OWASP ZAP DAST Vulnerability Gate Report\n"]

    if operational_errors:
        lines.append("> [!CAUTION]\n> **DAST Scan Validation Failed (Operational or Schema Error)**\n")
    elif scanner_status != 0:
        lines.append(f"> [!CAUTION]\n> **ZAP Scanner Execution Failed with exit status {scanner_status}**\n")
    elif unapproved_blocking or expired_exceptions:
        lines.append("> [!CAUTION]\n> **DAST Security Policy Violation Detected**\n")
    else:
        lines.append("> [!TIP]\n> **DAST Security Policy Compliant: All findings verified and approved.**\n")

    lines.append("#### Findings and Policy Summary\n")
    lines.append("| Metric | Count | Policy Status |")
    lines.append("|---|---|---|")
    lines.append(f"| **Total Findings Analyzed** | {total_findings} | Monitored |")
    unapproved_status = "❌ Violation" if unapproved_blocking else "✅ Clean"
    lines.append(f"| **Unapproved High / Medium Findings** | {len(unapproved_blocking)} | {unapproved_status} |")
    lines.append(f"| **Approved Active Exceptions** | {len(approved_blocking)} | ℹ️ Approved |")
    lines.append(f"| **Monitored Findings (Low / Informational)** | {len(monitored)} | ℹ️ Monitored |")
    expired_status = "❌ Expired" if expired_exceptions else "✅ None"
    lines.append(f"| **Expired Exceptions** | {len(expired_exceptions)} | {expired_status} |")
    lines.append(f"| **Unused Exceptions (Warnings)** | {len(unused_exceptions)} | ⚠️ Warning |")
    lines.append("\n")

    if operational_errors:
        lines.append("#### Operational & Schema Errors\n")
        for err in operational_errors:
            lines.append(f"- ❌ {err}")
        lines.append("\n")

    if expired_exceptions:
        lines.append("#### Expired Exceptions (Policy Violations)\n")
        lines.append("| Rule ID | Alert Name | Endpoint Pattern | Expiration (UTC) |\n|---|---|---|---|")
        for exc in expired_exceptions:
            lines.append(
                f"| `{exc['zap_rule_id']}` | {exc['alert_name']} | `{exc['target_url_pattern']}` | {exc['expires_at']} |"
            )
        lines.append("\n")

    if unapproved_blocking:
        lines.append("#### Unapproved High & Medium Vulnerabilities\n")
        lines.append("| Severity | Rule ID | Alert Name | Method | Affected URI |\n|---|---|---|---|---|")
        for f in unapproved_blocking:
            lines.append(
                f"| **{f['severity']}** | `{f['rule_id']}` | {f['name']} | `{f['method']}` | `{f['uri']}` |"
            )
        lines.append("\n")

    if approved_blocking:
        lines.append("#### Approved Security Exceptions\n")
        lines.append("| Severity | Rule ID | Alert Name | Affected URI | Reason | Expiration |\n|---|---|---|---|---|---|")
        for item in approved_blocking:
            f = item["finding"]
            exc = item["matched_exception"]
            lines.append(
                f"| {f['severity']} | `{f['rule_id']}` | {f['name']} | `{f['uri']}` | {exc['reason']} | {exc['expires_at']} |"
            )
        lines.append("\n")

    if unused_exceptions:
        lines.append("#### Unused Exceptions (Warnings)\n")
        for exc in unused_exceptions:
            lines.append(
                f"- ⚠️ Rule `{exc['zap_rule_id']}` ({exc['alert_name']}) matching `{exc['target_url_pattern']}` was not encountered in this scan."
            )
        lines.append("\n")

    return "\n".join(lines)


def main() -> int:
    """Main CLI entry point for DAST scan validation."""
    parser = argparse.ArgumentParser(description="Validate OWASP ZAP DAST scan report against exception register.")
    parser.add_argument("--report", required=True, help="Path to ZAP JSON scan report file.")
    parser.add_argument("--exceptions", required=True, help="Path to DAST security exception register JSON.")
    parser.add_argument("--summary", default="", help="Optional path to output GitHub Step Summary markdown.")
    parser.add_argument("--scanner-status", type=int, default=0, help="Exit code of the ZAP scanner process.")
    args = parser.parse_args()

    now_utc = datetime.now(UTC)

    # 1. Validate Exception Register
    active_exceptions, expired_exceptions, register_errors = validate_exception_register(
        args.exceptions, now_utc
    )

    # 2. Parse ZAP Report
    findings, report_errors = parse_zap_report(args.report)

    # Accumulate operational / schema errors
    operational_errors = register_errors + report_errors
    if args.scanner_status != 0:
        operational_errors.append(f"ZAP scanner exited with non-zero status code: {args.scanner_status}")

    if operational_errors:
        print("[ERROR] DAST validation failed due to operational or schema error(s):", file=sys.stderr)
        for err in operational_errors:
            print(f"  - {err}", file=sys.stderr)

        if args.summary:
            summary_md = build_markdown_summary(
                len(findings),
                [],
                [],
                [],
                expired_exceptions,
                [],
                operational_errors,
                args.scanner_status,
            )
            try:
                with open(args.summary, "a", encoding="utf-8") as summary_file:
                    summary_file.write(summary_md + "\n")
            except OSError as e:
                print(f"[WARN] Failed to write step summary: {e}", file=sys.stderr)

        return EXIT_OPERATIONAL_ERROR

    # 3. Evaluate Findings Against Policy
    unapproved_blocking, approved_blocking, monitored, unused_exceptions = evaluate_dast_findings(
        findings, active_exceptions
    )

    # 4. Console Output
    print("=" * 64)
    print("           DocVault OWASP ZAP DAST Validation Report            ")
    print("=" * 64)
    print(f"Total findings analyzed:              {len(findings)}")
    print(f"Unapproved High / Medium findings:    {len(unapproved_blocking)}")
    print(f"Approved active exceptions:          {len(approved_blocking)}")
    print(f"Monitored (Low / Informational):     {len(monitored)}")
    print(f"Expired exceptions:                  {len(expired_exceptions)}")
    print(f"Unused exceptions (warnings):        {len(unused_exceptions)}")
    print("-" * 64)

    if unused_exceptions:
        print("[WARNING] The following exception(s) were unused in this scan:")
        for exc in unused_exceptions:
            print(f"  - Rule {exc['zap_rule_id']} ({exc['alert_name']}) on pattern '{exc['target_url_pattern']}'")

    if expired_exceptions:
        print("[FAIL] Expired exception(s) detected in register:")
        for exc in expired_exceptions:
            print(f"  - Rule {exc['zap_rule_id']} ({exc['alert_name']}) expired on {exc['expires_at']}")

    if unapproved_blocking:
        print("[FAIL] Unapproved High or Medium vulnerabilities found:")
        for finding_item in unapproved_blocking:
            print(
                f"  - [{finding_item['severity']}] Rule {finding_item['rule_id']}: "
                f"{finding_item['name']} on {finding_item['method']} {finding_item['uri']}"
            )

    # 5. Write GitHub Step Summary
    if args.summary:
        summary_md = build_markdown_summary(
            len(findings),
            unapproved_blocking,
            approved_blocking,
            monitored,
            expired_exceptions,
            unused_exceptions,
            [],
            args.scanner_status,
        )
        try:
            with open(args.summary, "a", encoding="utf-8") as summary_file:
                summary_file.write(summary_md + "\n")
        except OSError as e:
            print(f"[WARN] Failed to write step summary: {e}", file=sys.stderr)

    # 6. Determine Exit Code
    if unapproved_blocking or expired_exceptions:
        reasons: list[str] = []
        if unapproved_blocking:
            reasons.append(f"{len(unapproved_blocking)} unapproved High/Medium finding(s)")
        if expired_exceptions:
            reasons.append(f"{len(expired_exceptions)} expired exception(s)")
        print(f"\nPolicy violation: {'; '.join(reasons)}.")
        return EXIT_POLICY_VIOLATION

    print("\nPolicy compliant: All findings comply with DocVault security policy.")
    return EXIT_SUCCESS


if __name__ == "__main__":
    sys.exit(main())
