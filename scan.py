"""
scan.py — CLI entry point for the Cloud Misconfiguration Scanner.

Runs all five detectors against the currently configured AWS account
and writes the combined findings to findings.json.

Usage:
    python scan.py
"""

import json
import sys
from datetime import datetime, timezone

from detectors import (
    detect_public_s3_buckets,
    detect_open_security_groups,
    detect_iam_wildcard_policies,
    detect_unencrypted_ebs_volumes,
    detect_missing_mfa,
)

OUTPUT_FILE = "findings.json"

# Each entry: (human-readable label for terminal output, detector function)
DETECTORS = [
    ("Public S3 buckets", detect_public_s3_buckets),
    ("Open security groups", detect_open_security_groups),
    ("IAM wildcard policies", detect_iam_wildcard_policies),
    ("Unencrypted EBS volumes", detect_unencrypted_ebs_volumes),
    ("Missing MFA", detect_missing_mfa),
]


def run_all_detectors():
    """
    Runs each detector in turn. If one detector fails (e.g. a missing
    IAM permission), the scan continues with the rest rather than
    crashing the whole run — a single permissions gap shouldn't hide
    findings from four other checks that succeeded.
    """
    all_findings = []
    errors = []

    for label, detector_fn in DETECTORS:
        try:
            findings = detector_fn()
            all_findings.extend(findings)
            print(f"  [ok]    {label}: {len(findings)} finding(s)")
        except Exception as e:
            errors.append({"detector": label, "error": str(e)})
            print(f"  [error] {label}: {e}")

    return all_findings, errors


def main():
    print("Running Cloud Misconfiguration Scanner...\n")

    all_findings, errors = run_all_detectors()

    output = {
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "total_findings": len(all_findings),
        "findings": all_findings,
        "errors": errors,
    }

    with open(OUTPUT_FILE, "w") as f:
        json.dump(output, f, indent=2)

    print(f"\n{len(all_findings)} finding(s) written to {OUTPUT_FILE}")

    if errors:
        print(f"{len(errors)} detector(s) failed to run — see '{OUTPUT_FILE}' errors section for details")
        sys.exit(1)  # non-zero exit code signals partial failure to any calling script/CI


if __name__ == "__main__":
    main()