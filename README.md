# AWS Cloud Hygiene Scanner (LocalStack + Boto3)

A lightweight Python CLI tool that audits S3 and IAM configurations for basic security and cost-hygiene issues, designed to run locally against **LocalStack** with zero real AWS account or cloud spend required.

## What It Checks
- **S3 Default Encryption:** Flags buckets without default server-side encryption enabled.
- **S3 Lifecycle Policies:** Flags buckets without an enabled lifecycle rule to prevent unbounded object retention costs.
- **IAM Least Privilege:** Flags customer-managed IAM policies (`Scope="Local"`) that allow wildcard `"Action": "*"`.

## Quick Start (LocalStack)
1. Install dependencies:
   ```bash
   pip install -r requirements.txt

   ## Sample Output
```text
[PASS] S3 Encryption (compliant-logs-bucket): Configured
[PASS] S3 Lifecycle (compliant-logs-bucket): Configured
[FAIL] S3 Encryption (unmanaged-uploads-bucket): Missing default encryption
[FAIL] S3 Lifecycle (unmanaged-uploads-bucket): Missing lifecycle policy
[FAIL] IAM Least Privilege (overly-permissive-dev-policy): Allows wildcard action '*'
[PASS] IAM Least Privilege (scoped-log-writer-policy): Scoped actions

Audit complete. Total findings: 3