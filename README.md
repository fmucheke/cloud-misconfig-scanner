# Cloud Misconfiguration Scanner with Policy Mapping

## Overview
A cloud security tool that scans an AWS account for common misconfigurations, maps each finding to relevant NIST CSF and CIS AWS Benchmark controls, and generates plain-English remediation reports using an LLM. Built to practice the technical and risk-translation skills used in cloud security and security consulting roles.

## Architecture

## Setup
1. Create a Python virtual environment: `python -m venv venv`
2. Activate it and install dependencies: `pip install boto3 anthropic python-dotenv markdown2 xhtml2pdf`
3. Configure AWS credentials for a least-privilege IAM user (see `/policies` for the exact custom policy used — deliberately scoped to read-only actions, not the AWS-managed ReadOnlyAccess policy)
4. Create a `.env` file in the project root with `ANTHROPIC_API_KEY=your-key-here` (get a key at console.anthropic.com — never commit this file; it's already excluded in `.gitignore`)
5. Run the full pipeline (see Usage below)

## Usage
Run the full pipeline, in order:
```
python scan.py
python report_generator.py
python pdf_converter.py
```
- **`scan.py`** runs all five detectors against the currently configured AWS account/region, prints a per-detector status line, and writes the combined, enriched results to `findings.json`.
- **`report_generator.py`** reads `findings.json`, generates a remediation paragraph for each finding plus one executive summary (via the Anthropic API), and writes a formatted Markdown report to `reports/report-<timestamp>.md`.
- **`pdf_converter.py`** converts the most recently generated Markdown report (or a specific path passed as an argument) into a PDF at the same location.

`findings.json` and everything under `reports/` are regenerated on every run and are not tracked in version control — they're live output tied to whatever account was scanned and when, not fixtures.

If one detector fails during `scan.py` (e.g. a missing IAM permission), the others still run; the failure is recorded in the `errors` array rather than crashing the whole scan, and is also called out in the generated report.

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
`remediation_writer.py` is the only place in the pipeline where an LLM is involved, and its role is deliberately narrow: every fact it's given (the finding, its control mapping, its severity) was already determined by the deterministic layers above it. The LLM's job is to turn those verified facts into readable prose — one plain-English remediation paragraph per finding, plus one executive summary across all findings — not to decide what's true.

Design principles:
- **Filtered input, not the raw enriched finding** — the prompt is built from only the fields relevant to a report reader. Internal bookkeeping fields (`finding_type`, `severity_hint`, `lookup_error`) are excluded, both to reduce token cost and to avoid the model echoing internal field names/vocabulary into report prose.
- **Explicit anti-hallucination instructions** — the system prompt directly forbids inventing timelines, tool names, or details not present in the input.
- **Explicit, non-negotiable citation requirement** — an early version of the prompt allowed the model to reference controls vaguely ("the CIS Benchmark," no code attached). The prompt was tightened to require the literal control codes every time, and to say plainly when a CIS number isn't confirmed rather than omit or soften it.
- **The executive summary computes its own facts in Python, not in the prompt** — severity counts are computed with a plain dict and handed to the model as already-established numbers, with an explicit instruction not to estimate or restate them differently. An earlier version let the model describe "the number of severity levels" in its own words and it miscounted; the fix was to require the literal numbers rather than a paraphrased description of them.
- **Low temperature (0.3)** — favors consistent, accurate phrasing over creative variation, appropriate for a compliance-facing report rather than open-ended writing.

## Report Generation
`report_generator.py` assembles everything into one document — it performs no analysis of its own, only orchestration and formatting:
- Findings are sorted **CRITICAL → HIGH → MEDIUM** so the most urgent item always appears first, regardless of the order detectors happened to run in.
- The scan timestamp is reformatted for human readability (e.g. "September 06, 2026 at 11:32 PM UTC") in the report, while `findings.json` keeps the raw ISO 8601 format for machine use.
- Each finding section repeats the same "state it plainly if a CIS number isn't confirmed" honesty rule used in the LLM prompt, so the compliance mapping line and the remediation paragraph beneath it never contradict each other.

`pdf_converter.py` converts the generated Markdown into a PDF using `markdown2` + `xhtml2pdf` — chosen over `weasyprint` specifically to avoid a difficult Windows-only GTK dependency unrelated to the project's actual scope. One rendering limitation was found and fixed: the default font used by this PDF stack lacks glyphs for some Unicode characters an LLM is likely to produce (arrows especially render as garbled text), so risky characters are sanitized to safe ASCII equivalents immediately before PDF conversion — the source Markdown file is left untouched, since Markdown itself renders those characters correctly everywhere else (GitHub, editors, etc.).

## Design Decisions
- **Custom least-privilege IAM policy instead of AWS-managed ReadOnlyAccess** — scoped to only the specific read/describe/list actions each detector needs, minimizing blast radius if credentials were ever compromised. This policy is expanded incrementally as new detectors are added rather than granted broadly up front.
- **Explicit error-code handling rather than blanket exception catching** — the S3 detector distinguishes a genuinely missing Block Public Access configuration from other failures (e.g., an IAM permissions gap), so a scan failure is reported as "unverified" rather than silently mislabeled as a security finding.
- **`detectors.py` and `scan.py` are deliberately separate files** — `detectors.py` is a pure library (defines detector functions, has no execution logic or side effects on import). `scan.py` is the single CLI entry point that imports those functions, runs them, and handles output.
- **AWS Security Hub control ID as the primary citation, not the raw CIS Benchmark number** — CIS AWS Foundations Benchmark control numbers are renumbered, merged, or dropped between versions, so a bare CIS number is ambiguous without stating which version it's from. Security Hub control IDs are stable across CIS versions. Every finding still cites a CIS control where one has been independently verified against AWS's own documentation; where it couldn't be verified, `control_mappings.py` says so explicitly rather than asserting an unconfirmed number.
- **Small machine-readable fields alongside human-readable text, rather than parsing prose** — `finding_type`, `severity_hint`, and `attached_instances` all exist so downstream code can branch on an explicit value instead of string-matching sentences meant for a human reader.

## Testing
Findings are validated against a deliberately misconfigured sandbox environment, not assumed to work from code review alone:
- An IAM policy granting `Action:*`/`Resource:*`, attached to a test role
- An unencrypted, unattached EBS volume
- An IAM user with console access and no MFA device registered

Each was confirmed live in AWS and independently verified to be caught by its respective detector — individually, together via `python scan.py`, and end-to-end through a full generated PDF report — before being considered complete.