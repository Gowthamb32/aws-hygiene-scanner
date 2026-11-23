import json
import sys
import boto3
from botocore.exceptions import ClientError
from moto import mock_aws


def create_bucket_for_region(s3, bucket_name: str, region: str) -> None:
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": region},
        )


def seed_resources(s3, iam, region: str) -> None:
    # Compliant bucket: encryption + lifecycle policy
    good_bucket = "compliant-logs-bucket"
    create_bucket_for_region(s3, good_bucket, region)
    s3.put_bucket_encryption(
        Bucket=good_bucket,
        ServerSideEncryptionConfiguration={
            "Rules": [
                {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
            ]
        },
    )
    s3.put_bucket_lifecycle_configuration(
        Bucket=good_bucket,
        LifecycleConfiguration={
            "Rules": [
                {
                    "ID": "expire-old-logs",
                    "Filter": {"Prefix": "logs/"},
                    "Status": "Enabled",
                    "Expiration": {"Days": 90},
                }
            ]
        },
    )

    # Non-compliant bucket: missing lifecycle policy (and remove encryption if present)
    bad_bucket = "unmanaged-uploads-bucket"
    create_bucket_for_region(s3, bad_bucket, region)
    try:
        s3.delete_bucket_encryption(Bucket=bad_bucket)
    except ClientError:
        pass

    # Over-permissive IAM policy
    iam.create_policy(
        PolicyName="overly-permissive-dev-policy",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
            }
        ),
    )

    # Least-privilege IAM policy
    iam.create_policy(
        PolicyName="scoped-log-writer-policy",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject", "s3:PutObject"],
                        "Resource": "arn:aws:s3:::compliant-logs-bucket/logs/*",
                    }
                ],
            }
        ),
    )


def check_s3_buckets(s3) -> int:
    findings = 0
    for bucket in s3.list_buckets().get("Buckets", []):
        name = bucket["Name"]

        try:
            s3.get_bucket_encryption(Bucket=name)
            print(f"[PASS] S3 Encryption ({name}): Configured")
        except ClientError:
            print(f"[FAIL] S3 Encryption ({name}): Missing default encryption")
            findings += 1

        try:
            s3.get_bucket_lifecycle_configuration(Bucket=name)
            print(f"[PASS] S3 Lifecycle ({name}): Configured")
        except ClientError:
            print(f"[FAIL] S3 Lifecycle ({name}): Missing lifecycle policy")
            findings += 1

    return findings


def check_iam_policies(iam) -> int:
    findings = 0
    for policy in iam.list_policies(Scope="Local").get("Policies", []):
        name = policy["PolicyName"]
        version_id = policy["DefaultVersionId"]
        doc = iam.get_policy_version(
            PolicyArn=policy["Arn"], VersionId=version_id
        )["PolicyVersion"]["Document"]
        if isinstance(doc, str):
            doc = json.loads(doc)

        statements = doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        has_wildcard = any(
            stmt.get("Effect") == "Allow"
            and (
                "*"
                in (
                    [stmt.get("Action")]
                    if isinstance(stmt.get("Action"), str)
                    else stmt.get("Action", [])
                )
            )
            for stmt in statements
        )

        if has_wildcard:
            print(f"[FAIL] IAM Least Privilege ({name}): Allows wildcard action '*'")
            findings += 1
        else:
            print(f"[PASS] IAM Least Privilege ({name}): Scoped actions")

    return findings


@mock_aws
def main() -> int:
    region = "eu-west-2"
    s3 = boto3.client("s3", region_name=region)
    iam = boto3.client("iam", region_name=region)

    seed_resources(s3, iam, region=region)

    findings = 0
    findings += check_s3_buckets(s3)
    findings += check_iam_policies(iam)

    print(f"\nAudit complete. Total findings: {findings}")
    return 1 if findings > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
    