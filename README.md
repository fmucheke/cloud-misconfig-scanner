# Cloud Misconfiguration Scanner with Policy Mapping

## Overview
A cloud security tool that scans an AWS account for common misconfigurations, maps each finding to relevant NIST CSF and CIS AWS Benchmark controls, and generates plain-English remediation reports using an LLM. Built to practice the technical and risk-translation skills used in cloud security and security consulting roles.

## Architecture

## Setup
1. Create a Python virtual environment: `python -m venv venv`
2. Activate it and install dependencies: `pip install boto3 anthropic python-dotenv`
3. Configure AWS credentials for a least-privilege IAM user (see `/policies` for the exact custom policy used — deliberately scoped to read-only actions, not the AWS-managed ReadOnlyAccess policy)
4. Create a `.env` file in the project root with `ANTHROPIC_API_KEY=your-key-here` (get a key at console.anthropic.com — never commit this file; it's already excluded in `.gitignore`)
5. Run `python scan.py`

## Usage
Run a full scan against the currently configured AWS account/region:
```
python scan.py
```
This runs all five detectors, prints a per-detector status line (finding count, or an error if that detector failed), and writes the combined results to `findings.json` in the project root. `findings.json` is regenerated on every run and is not tracked in version control (see `.gitignore`) — it's live output tied to whatever account you're scanning, not a fixture.

If one detector fails (e.g. a missing IAM permission), the others still run; the failure is recorded in the `errors` array in `findings.json` rather than crashing the whole scan.

## Findings Detected
- **Public S3 buckets** — checks Block Public Access configuration and bucket policy for public access grants. Maps to Security Hub `[S3.1]` / CIS AWS Foundations Benchmark v5.0.0 control 2.1.4, NIST CSF 2.0 PR.AA-05.
- **Open security groups** — checks inbound rules for unrestricted access (0.0.0.0/0) on sensitive ports (SSH, RDP, and common database ports), rather than flagging all open ports indiscriminately. Maps to Security Hub `[EC2.19]`, NIST CSF 2.0 PR.AA-05. (No CIS version-specific number confirmed — see `control_mappings.py`.)
- **IAM wildcard policies** — checks customer-managed policies and role inline policies for statements granting `Action:*` and/or `Resource:*`, including partial wildcards (e.g. `iam:*`) and risky `NotAction` usage. Maps to Security Hub `[IAM.1]` / CIS AWS Foundations Benchmark v1.4.0 control 1.16, NIST CSF 2.0 PR.AA-05.
- **Unencrypted EBS volumes** — checks every volume in the current region for missing encryption at rest, distinguishing volumes actively attached to an instance from unattached ones. Maps to Security Hub `[EC2.7]`, NIST CSF 2.0 PR.DS-01. (No CIS version-specific number confirmed — see `control_mappings.py`.)
- **Missing MFA** — checks the root account and every IAM user with console access for a registered MFA device. Users with programmatic-only (access key) access are correctly excluded, since MFA protects console login events and doesn't apply to them. Root maps to Security Hub `[IAM.9]` / CIS v5.0.0 control 1.4; console users map to `[IAM.5]` / CIS v5.0.0 control 1.9. Both map to NIST CSF 2.0 PR.AA-03.

Full mapping details, including the reasoning for which citation is treated as authoritative, live in `control_mappings.py`.

## Severity Scoring
Every finding is assigned a severity level — CRITICAL, HIGH, or MEDIUM — based on a documented rubric in `severity.py`:
- **CRITICAL** — equivalent to full account takeover with no further steps required (missing root MFA, or an IAM policy granting unrestricted `Action:*`/`Resource:*` admin access)
- **HIGH** — a real, exploitable exposure short of full compromise (public S3 bucket, open security group on a sensitive port, an unencrypted EBS volume attached to a running instance, a console IAM user without MFA, or a broad-but-bounded IAM wildcard grant)
- **MEDIUM** — a real gap with lower immediate exposure (an unencrypted EBS volume that's currently unattached, or an IAM wildcard statement scoped narrowly on both action and resource)

Two finding types (IAM wildcard policies, EBS volumes) don't have one fixed severity — the specific statement shape or attachment state changes the score. Rather than infer this from the human-readable `details` text, `detectors.py` attaches small machine-readable fields (`severity_hint` on IAM findings, `attached_instances` on EBS findings) specifically so severity scoring doesn't depend on parsing prose.

## LLM Remediation Reporting
`remediation_writer.py` is the only place in the pipeline where an LLM is involved, and its role is deliberately narrow: every fact it's given (the finding, its control mapping, its severity) was already determined by the deterministic layers above it. The LLM's job is to turn those verified facts into one plain-English remediation paragraph — not to decide what's true.

Design principles:
- **Filtered input, not the raw enriched finding** — the prompt is built from only the fields relevant to a report reader (resource, issue, severity, control mapping). Internal bookkeeping fields (`finding_type`, `severity_hint`, `lookup_error`) are excluded, both to reduce token cost and to avoid the model echoing internal field names/vocabulary into report prose.
- **Explicit anti-hallucination instructions** — the system prompt directly forbids inventing timelines, tool names, or details not present in the input.
- **Explicit, non-negotiable citation requirement** — an early version of the prompt allowed the model to reference controls vaguely ("the CIS Benchmark," no code attached). The prompt was tightened to require the literal control codes (e.g. "Security Hub control IAM.1," "CIS AWS Foundations Benchmark v1.4.0 control 1.16") every time, and to say plainly when a CIS number isn't confirmed rather than omit or soften it.
- **Low temperature (0.3)** — favors consistent, accurate phrasing over creative variation, appropriate for a compliance-facing report rather than open-ended writing.

## Design Decisions
- **Custom least-privilege IAM policy instead of AWS-managed ReadOnlyAccess** — scoped to only the specific read/describe/list actions each detector needs, minimizing blast radius if credentials were ever compromised. This policy is expanded incrementally as new detectors are added rather than granted broadly up front.
- **Explicit error-code handling rather than blanket exception catching** — the S3 detector distinguishes a genuinely missing Block Public Access configuration from other failures (e.g., an IAM permissions gap), so a scan failure is reported as "unverified" rather than silently mislabeled as a security finding.
- **`detectors.py` and `scan.py` are deliberately separate files** — `detectors.py` is a pure library (defines detector functions, has no execution logic or side effects on import). `scan.py` is the single CLI entry point that imports those functions, runs them, and handles output.
- **AWS Security Hub control ID as the primary citation, not the raw CIS Benchmark number** — CIS AWS Foundations Benchmark control numbers are renumbered, merged, or dropped between versions, so a bare CIS number is ambiguous without stating which version it's from. Security Hub control IDs are stable across CIS versions. Every finding still cites a CIS control where one has been independently verified against AWS's own documentation; where it couldn't be verified, `control_mappings.py` says so explicitly rather than asserting an unconfirmed number.
- **Small machine-readable fields alongside human-readable text, rather than parsing prose** — `finding_type` (added when the policy mapping layer was built), `severity_hint`, and `attached_instances` all exist so downstream code (the mapping lookup, severity scoring) can branch on an explicit value instead of string-matching sentences meant for a human reader. The `details` field stays as the readable explanation; these fields are the queryable counterpart.

## Testing
Findings are validated against a deliberately misconfigured sandbox environment, not assumed to work from code review alone:
- An IAM policy granting `Action:*`/`Resource:*`, attached to a test role
- An unencrypted, unattached EBS volume
- An IAM user with console access and no MFA device registered

Each was confirmed live in AWS and independently verified to be caught by its respective detector — individually, and again together via a full `python scan.py` run — before being considered complete.