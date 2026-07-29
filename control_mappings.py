"""
control_mappings.py

Hardcoded lookup table mapping each detector's finding type to its
relevant control references. This is deliberately hardcoded rather than
inferred by an LLM at runtime — knowing these mappings is the actual GRC
skill being demonstrated, and a hardcoded table is auditable and
defensible in a way "the AI decided this" is not.

Citation approach:
  - "security_hub_control" is the PRIMARY citation. It's AWS's own stable
    control ID and does not change between CIS Benchmark versions — AWS
    updates the underlying CIS crosswalk as new CIS versions are released,
    but the control ID itself stays fixed.
  - "cis_control" is included only where independently verified against
    AWS's own Security Hub documentation for CIS AWS Foundations Benchmark
    v5.0.0. Where a v5.0.0 mapping could not be confirmed, this field says
    so explicitly rather than asserting an unverified number.
  - "nist_csf" uses NIST CSF 2.0 subcategories (current as of Feb 2024),
    with the legacy CSF 1.1 equivalent noted.

See notes/session-07-control-mapping-research.md for the full research
process, including numbers that were checked and rejected.
"""

CONTROL_MAPPINGS = {
    "s3_public_bucket": {
        "security_hub_control": "S3.1",
        "security_hub_title": "S3 general purpose buckets should have block public access settings enabled",
        "cis_control": "2.1.4",
        "cis_version": "v5.0.0",
        "nist_csf": "PR.AA-05",
        "nist_csf_title": "Access permissions and authorizations are managed, incorporating the principles of least privilege",
        "nist_csf_legacy": "PR.AC-4",
    },
    "open_security_group": {
        "security_hub_control": "EC2.19",
        "security_hub_title": "Security groups should not allow unrestricted access to ports with high risk",
        "cis_control": None,
        "cis_version": "unconfirmed — AWS's Security Hub documentation lists no CIS crosswalk entry (any version) for EC2.13/EC2.14/EC2.19 as of this research pass",
        "nist_csf": "PR.AA-05",
        "nist_csf_title": "Access permissions and authorizations are managed, incorporating the principles of least privilege",
        "nist_csf_legacy": "PR.AC-4",
    },
    "iam_wildcard_policy": {
        "security_hub_control": "IAM.1",
        "security_hub_title": 'IAM policies should not allow full "*" administrative privileges',
        "cis_control": "1.16",
        "cis_version": "v1.4.0 — confirmed. AWS's crosswalk for IAM.1 lists v1.2.0 and v1.4.0 only; no v3.0.0 or v5.0.0 entry exists, suggesting this control may have been restructured in later CIS versions.",
        "nist_csf": "PR.AA-05",
        "nist_csf_title": "Access permissions and authorizations are managed, incorporating the principles of least privilege",
        "nist_csf_legacy": "PR.AC-4",
    },
    "unencrypted_ebs_volume": {
        "security_hub_control": "EC2.7",
        "security_hub_title": "EBS default encryption should be enabled",
        "cis_control": None,
        "cis_version": "unconfirmed — a primary-source AWS sample finding referenced a v5.0.0 number for this control, but the digits were structurally inconsistent with CIS's section numbering pattern, so it was not trusted for this table",
        "nist_csf": "PR.DS-01",
        "nist_csf_title": "The confidentiality, integrity, and availability of data-at-rest are protected",
        "nist_csf_legacy": "PR.DS-1",
    },
    "missing_mfa_root": {
        "security_hub_control": "IAM.9",
        "security_hub_title": "MFA should be enabled for the root user",
        "cis_control": "1.4",
        "cis_version": "v5.0.0 — confirmed",
        "nist_csf": "PR.AA-03",
        "nist_csf_title": "Users, services, and hardware are authenticated",
        "nist_csf_legacy": "PR.AC-7",
    },
    "missing_mfa_console_user": {
        "security_hub_control": "IAM.5",
        "security_hub_title": "MFA should be enabled for all IAM users that have a console password",
        "cis_control": "1.9",
        "cis_version": "v5.0.0 — confirmed",
        "nist_csf": "PR.AA-03",
        "nist_csf_title": "Users, services, and hardware are authenticated",
        "nist_csf_legacy": "PR.AC-7",
    },
}