# Cloud Misconfiguration Scanner with Policy Mapping

## Overview
A cloud security tool that scans an AWS account for common misconfigurations, maps each finding to relevant NIST CSF and CIS AWS Benchmark controls, and generates plain-English remediation reports using an LLM. Built to practice the technical and risk-translation skills used in cloud security and security consulting roles.

## Architecture

## Setup
1. Create a Python virtual environment: `python -m venv venv`
2. Activate it and install dependencies: `pip install boto3`
3. Configure AWS credentials for a least-privilege IAM user (see `/policies` for the exact custom policy used — deliberately scoped to read-only actions, not the AWS-managed ReadOnlyAccess policy)
4. Run `python scan.py`

## Usage
Run a full scan against the currently configured AWS account/region:
```
python scan.py
```
This runs all five detectors, prints a per-detector status line (finding count, or an error if that detector failed), and writes the combined results to `findings.json` in the project root. `findings.json` is regenerated on every run and is not tracked in version control (see `.gitignore`) — it's live output tied to whatever account you're scanning, not a fixture.

If one detector fails (e.g. a missing IAM permission), the others still run; the failure is recorded in the `errors` array in `findings.json` rather than crashing the whole scan.

## Findings Detected
- **Public S3 buckets** — checks Block Public Access configuration and bucket policy for public access grants
- **Open security groups** — checks inbound rules for unrestricted access (0.0.0.0/0) on sensitive ports (SSH, RDP, and common database ports), rather than flagging all open ports indiscriminately
- **IAM wildcard policies** — checks customer-managed policies and role inline policies for statements granting `Action:*` and/or `Resource:*`, including partial wildcards (e.g. `iam:*`) and risky `NotAction` usage. Maps to CIS AWS Foundations Benchmark 1.22 and NIST CSF PR.AC-4.
- **Unencrypted EBS volumes** — checks every volume in the current region for missing encryption at rest, distinguishing volumes actively attached to an instance from unattached ones. Maps to CIS AWS Foundations Benchmark 2.2.1 and NIST CSF PR.DS-1.
- **Missing MFA** — checks the root account and every IAM user with console access for a registered MFA device. Users with programmatic-only (access key) access are correctly excluded, since MFA protects console login events and doesn't apply to them. Maps to CIS AWS Foundations Benchmark 1.5 and 1.10, and NIST CSF PR.AC-7.

## Design Decisions
- **Custom least-privilege IAM policy instead of AWS-managed ReadOnlyAccess** — scoped to only the specific read/describe/list actions each detector needs, minimizing blast radius if credentials were ever compromised. This policy is expanded incrementally as new detectors are added (e.g. `iam:ListEntitiesForPolicy`, `iam:ListRoles`, `iam:ListRolePolicies`, `iam:GetRolePolicy`, and `iam:GetLoginProfile` were each added specifically to support a new detector) rather than granted broadly up front.
- **Explicit error-code handling rather than blanket exception catching** — the S3 detector distinguishes a genuinely missing Block Public Access configuration from other failures (e.g., an IAM permissions gap), so a scan failure is reported as "unverified" rather than silently mislabeled as a security finding.
- **Severity implied through finding language, not a separate field (for now)** — e.g. the EBS detector explicitly notes whether an unencrypted volume is attached to a live instance vs. unattached, since an in-use unencrypted volume is a more urgent finding than an orphaned one, even though both are flagged. A formal severity field is planned once the policy-mapping layer is in place.
- **`detectors.py` and `scan.py` are deliberately separate files** — `detectors.py` is a pure library (defines detector functions, has no execution logic or side effects on import). `scan.py` is the single CLI entry point that imports those functions, runs them, and handles output. This keeps the detectors importable by future pipeline stages (policy mapping, LLM reporting) without triggering a full scan as a side effect of importing them.

## Testing
Findings are validated against a deliberately misconfigured sandbox environment, not assumed to work from code review alone:
- An IAM policy granting `Action:*`/`Resource:*`, attached to a test role
- An unencrypted, unattached EBS volume
- An IAM user with console access and no MFA device registered

Each was confirmed live in AWS and independently verified to be caught by its respective detector — individually, and again together via a full `python scan.py` run — before being considered complete.