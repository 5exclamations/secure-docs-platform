"""Creates the dev bucket (idempotent) and enables versioning. Used by the compose `minio-init` job."""

import os

import boto3
from botocore.exceptions import ClientError

s3 = boto3.client(
    "s3",
    endpoint_url=os.environ["S3_ENDPOINT_URL"],
    region_name=os.environ.get("S3_REGION", "us-east-1"),
    aws_access_key_id=os.environ["S3_ACCESS_KEY_ID"],
    aws_secret_access_key=os.environ["S3_SECRET_ACCESS_KEY"],
)
bucket = os.environ["S3_BUCKET"]
try:
    s3.create_bucket(Bucket=bucket)
except ClientError as exc:
    if exc.response["Error"]["Code"] not in {"BucketAlreadyOwnedByYou", "BucketAlreadyExists"}:
        raise
s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
print(f"bucket {bucket} ready")
