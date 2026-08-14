"""
policy_mapper.py

Takes raw findings (as returned by the detector functions in detectors.py)
and attaches their control references, using the lookup table in
control_mappings.py.

This is deliberately a thin layer: it does not decide *what* the controls
are, it just does the lookup and attaches the result to each finding.
"""

from control_mappings import CONTROL_MAPPINGS

# Attached to a finding if its finding_type has no entry in CONTROL_MAPPINGS.
# This should only happen if a detector was added without a corresponding
# mapping table entry — surfacing it loudly is better than silently
# producing an unmapped finding.
UNMAPPED_PLACEHOLDER = {
    "security_hub_control": None,
    "security_hub_title": None,
    "cis_control": None,
    "cis_version": None,
    "nist_csf": None,
    "nist_csf_title": None,
    "nist_csf_legacy": None,
}


def attach_control_mapping(finding):
    """
    Takes a single raw finding dict and returns a new dict with a
    "control_mapping" key attached, containing its Security Hub control ID,
    CIS Benchmark reference (where verified), and NIST CSF subcategory.

    Does not mutate the original finding dict.
    """
    finding_type = finding.get("finding_type")

    if finding_type is None:
        # A finding with no finding_type key can't be looked up at all —
        # this indicates a detector wasn't updated to include one.
        mapping = dict(UNMAPPED_PLACEHOLDER)
        mapping["lookup_error"] = "Finding has no 'finding_type' key"
    elif finding_type not in CONTROL_MAPPINGS:
        # A finding_type that doesn't exist in the table — likely a new
        # detector added without a corresponding mapping entry.
        mapping = dict(UNMAPPED_PLACEHOLDER)
        mapping["lookup_error"] = f"No control mapping found for finding_type '{finding_type}'"
    else:
        mapping = dict(CONTROL_MAPPINGS[finding_type])
        mapping["lookup_error"] = None

    enriched = dict(finding)
    enriched["control_mapping"] = mapping
    return enriched


def attach_control_mappings(findings):
    """
    Takes a list of raw findings and returns a new list with control
    mappings attached to each one.
    """
    return [attach_control_mapping(f) for f in findings]


if __name__ == "__main__":
    # Quick manual test against one example of each of the 6 finding_type
    # values currently produced by detectors.py — doesn't touch AWS at all,
    # just exercises the lookup logic itself.
    import json

    sample_findings = [
        {"finding_type": "s3_public_bucket", "resource_type": "S3 Bucket", "resource_name": "example-bucket"},
        {"finding_type": "open_security_group", "resource_type": "Security Group", "resource_name": "example-sg"},
        {"finding_type": "iam_wildcard_policy", "resource_type": "IAM Managed Policy", "resource_name": "example-policy"},
        {"finding_type": "unencrypted_ebs_volume", "resource_type": "EBS Volume", "resource_name": "example-vol"},
        {"finding_type": "missing_mfa_root", "resource_type": "Root Account", "resource_name": "root"},
        {"finding_type": "missing_mfa_console_user", "resource_type": "IAM User", "resource_name": "example-user"},
        # Deliberately broken cases, to confirm the error path works too:
        {"resource_type": "Unknown", "resource_name": "no-finding-type-key"},
        {"finding_type": "not_a_real_type", "resource_type": "Unknown", "resource_name": "bad-finding-type"},
    ]

    enriched = attach_control_mappings(sample_findings)
    print(json.dumps(enriched, indent=2))