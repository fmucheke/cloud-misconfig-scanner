"""
severity.py

Assigns a severity level (CRITICAL / HIGH / MEDIUM) to each finding, based
on a simple, documented rubric.

## The rubric

CRITICAL — equivalent to full account takeover with no further steps
required: missing root MFA, or an IAM policy granting unrestricted
Action:*/Resource:* admin access.

HIGH — a real, exploitable exposure, but short of full account
compromise: a public S3 bucket, an open security group on a sensitive
port, an unencrypted EBS volume actively attached to a running instance,
a console IAM user without MFA, or an IAM wildcard grant that's broad
(full control of one resource, or one service across all resources) but
not fully unrestricted.

MEDIUM — a real gap, but with lower immediate exposure: an unencrypted
EBS volume that's currently unattached, or an IAM wildcard statement
that's narrower on both the action and resource axes.

This mirrors real-world triage logic: could this be exploited right now
with nothing else needing to go wrong (CRITICAL), does it need one more
condition to matter (MEDIUM), or does it sit in between (HIGH).

Two finding types (iam_wildcard_policy, unencrypted_ebs_volume) don't
have a single fixed severity — they vary based on the specifics of the
finding, so this module reads the machine-readable severity_hint and
attached_instances fields detectors.py attaches to those findings, rather
than parsing the human-readable issue/details text.
"""

# Severity for finding types that are always the same regardless of the
# specific instance of the finding.
FIXED_SEVERITY = {
    "s3_public_bucket": "HIGH",
    "open_security_group": "HIGH",
    "missing_mfa_root": "CRITICAL",
    "missing_mfa_console_user": "HIGH",
}

# Severity for each IAM wildcard severity_hint — see the rubric table in
# notes/session-09-severity-scoring.md for the reasoning behind each level.
IAM_WILDCARD_SEVERITY = {
    "full_admin": "CRITICAL",
    "action_wildcard_scoped_resource": "HIGH",
    "service_wildcard_all_resources": "HIGH",
    "notaction_resource_wildcard": "MEDIUM",
    "partial_wildcard_scoped": "MEDIUM",
}


def assign_severity(finding):
    """
    Takes a single raw finding dict (as produced by detectors.py) and
    returns a severity string: "CRITICAL", "HIGH", "MEDIUM", or "UNKNOWN"
    if the finding_type isn't recognized at all.
    """
    finding_type = finding.get("finding_type")

    if finding_type == "iam_wildcard_policy":
        severity_hint = finding.get("severity_hint")
        return IAM_WILDCARD_SEVERITY.get(severity_hint, "UNKNOWN")

    if finding_type == "unencrypted_ebs_volume":
        attached_instances = finding.get("attached_instances", [])
        return "HIGH" if attached_instances else "MEDIUM"

    return FIXED_SEVERITY.get(finding_type, "UNKNOWN")


def attach_severity(findings):
    """
    Takes a list of raw findings and returns a new list with a "severity"
    key attached to each one. Does not mutate the original findings.
    """
    enriched = []
    for finding in findings:
        f = dict(finding)
        f["severity"] = assign_severity(finding)
        enriched.append(f)
    return enriched


if __name__ == "__main__":
    # Quick manual test covering all 5 IAM wildcard hints, both EBS
    # attachment states, and the 4 fixed-severity finding types — no AWS
    # calls, just exercises the scoring logic itself.
    import json

    sample_findings = [
        {"finding_type": "s3_public_bucket"},
        {"finding_type": "open_security_group"},
        {"finding_type": "missing_mfa_root"},
        {"finding_type": "missing_mfa_console_user"},
        {"finding_type": "iam_wildcard_policy", "severity_hint": "full_admin"},
        {"finding_type": "iam_wildcard_policy", "severity_hint": "action_wildcard_scoped_resource"},
        {"finding_type": "iam_wildcard_policy", "severity_hint": "service_wildcard_all_resources"},
        {"finding_type": "iam_wildcard_policy", "severity_hint": "notaction_resource_wildcard"},
        {"finding_type": "iam_wildcard_policy", "severity_hint": "partial_wildcard_scoped"},
        {"finding_type": "unencrypted_ebs_volume", "attached_instances": ["i-0123456789abcdef0"]},
        {"finding_type": "unencrypted_ebs_volume", "attached_instances": []},
        {"finding_type": "not_a_real_type"},
    ]

    for f, enriched in zip(sample_findings, attach_severity(sample_findings)):
        label = f.get("severity_hint") or f.get("finding_type")
        print(f"{label}: {enriched['severity']}")