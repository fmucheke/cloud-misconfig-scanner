"""
report_generator.py

Assembles the outputs of every prior layer — the scan findings (S1-S6),
control mappings (S7-S8), severity scores (S9), per-finding remediation
paragraphs (S10-S11), and the executive summary (S12) — into one
formatted Markdown report.

This file does no analysis of its own. It reads findings.json, calls the
existing remediation/summary functions, and formats the results. All
facts still originate from the deterministic layers; this is purely
presentation.

Usage:
    python report_generator.py
"""

import json
import os
from datetime import datetime, timezone

from remediation_writer import generate_remediation, generate_executive_summary

FINDINGS_FILE = "findings.json"
REPORTS_DIR = "reports"


def format_timestamp_for_report(iso_timestamp):
    """
    Converts the raw ISO 8601 timestamp from scan.py (e.g.
    "2026-08-15T22:27:01.959431+00:00") into a human-readable form for
    the report header. Falls back to the raw string if parsing fails,
    rather than crashing report generation over a formatting nicety.
    """
    try:
        dt = datetime.fromisoformat(iso_timestamp)
        return dt.strftime("%B %d, %Y at %I:%M %p UTC")
    except (ValueError, TypeError):
        return iso_timestamp

# Sort order for severities — CRITICAL first, so the most urgent finding
# is always at the top of the report rather than wherever it happened to
# fall in scan order.
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "UNKNOWN": 3}


def sort_findings_by_severity(findings):
    return sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity"), 99))


def format_control_mapping(control):
    """
    Formats the compliance citation line for one finding. Mirrors the
    same "state it plainly, don't hide an unconfirmed CIS number" rule
    used in the remediation prompt — a report reader deserves the same
    honesty the LLM layer already enforces.
    """
    cis_part = (
        f"CIS AWS Foundations Benchmark {control.get('cis_control')} ({control.get('cis_version')})"
        if control.get("cis_control")
        else "CIS control not confirmed for this check"
    )
    return (
        f"AWS Security Hub `{control.get('security_hub_control')}` "
        f"({control.get('security_hub_title')}) · "
        f"{cis_part} · "
        f"NIST CSF 2.0 `{control.get('nist_csf')}` ({control.get('nist_csf_title')})"
    )


def format_finding_section(finding, remediation_text):
    control = finding.get("control_mapping", {})

    lines = [
        f"### [{finding.get('severity')}] {finding.get('resource_type')}: {finding.get('resource_name')}",
        "",
        f"**Issue:** {finding.get('issue')}",
        "",
        f"**Compliance mapping:** {format_control_mapping(control)}",
        "",
        "**Remediation:**",
        "",
        remediation_text,
        "",
        "---",
        "",
    ]
    return "\n".join(lines)


def generate_report(scan_output):
    """
    Takes the full parsed findings.json contents and returns a complete
    Markdown report as a string.
    """
    findings = scan_output.get("findings", [])
    errors = scan_output.get("errors", [])
    scan_timestamp = scan_output.get("scan_timestamp", "unknown")

    sorted_findings = sort_findings_by_severity(findings)

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "UNKNOWN": 0}
    for f in findings:
        severity_counts[f.get("severity", "UNKNOWN")] += 1

    print("Generating executive summary...")
    executive_summary = generate_executive_summary(findings) if findings else "No findings were identified in this scan."

    report_lines = [
        "# Cloud Misconfiguration Scan Report",
        "",
        f"**Scan performed:** {format_timestamp_for_report(scan_timestamp)}",
        "",
        f"**Total findings:** {len(findings)} "
        f"({severity_counts['CRITICAL']} Critical, {severity_counts['HIGH']} High, {severity_counts['MEDIUM']} Medium)",
        "",
        "## Executive Summary",
        "",
        executive_summary,
        "",
        "## Findings",
        "",
    ]

    for i, finding in enumerate(sorted_findings, start=1):
        print(f"Generating remediation for finding {i}/{len(sorted_findings)}: {finding.get('resource_name')}...")
        remediation_text = generate_remediation(finding)
        report_lines.append(format_finding_section(finding, remediation_text))

    if errors:
        report_lines.append("## Scan Errors")
        report_lines.append("")
        report_lines.append("The following detectors failed to run during this scan and their results are not reflected above:")
        report_lines.append("")
        for err in errors:
            report_lines.append(f"- **{err.get('detector')}**: {err.get('error')}")
        report_lines.append("")

    return "\n".join(report_lines)


def main():
    if not os.path.exists(FINDINGS_FILE):
        print(f"{FINDINGS_FILE} not found — run scan.py first.")
        return

    with open(FINDINGS_FILE) as f:
        scan_output = json.load(f)

    report_markdown = generate_report(scan_output)

    os.makedirs(REPORTS_DIR, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    output_path = os.path.join(REPORTS_DIR, f"report-{timestamp}.md")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report_markdown)

    print(f"\nReport written to {output_path}")


if __name__ == "__main__":
    main()