import boto3

REGION = "eu-west-3"
SECURE_BUCKET = "patient-records"
OPEN_BUCKET = "marketing-assets"
TRAIL_BUCKET = "audit-trail-logs"
TRAIL = "org-trail"
FULL_PUBLIC_ACCESS_BLOCK = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}


def harden_bucket(s3, name: str) -> None:
    s3.put_public_access_block(Bucket=name, PublicAccessBlockConfiguration=FULL_PUBLIC_ACCESS_BLOCK)
    s3.put_bucket_encryption(
        Bucket=name,
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]
        },
    )
    s3.put_bucket_versioning(Bucket=name, VersioningConfiguration={"Status": "Enabled"})


def main() -> None:
    session = boto3.Session(region_name=REGION)
    s3 = session.client("s3")
    for bucket in (SECURE_BUCKET, OPEN_BUCKET, TRAIL_BUCKET):
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": REGION})
    harden_bucket(s3, SECURE_BUCKET)
    harden_bucket(s3, TRAIL_BUCKET)

    iam = session.client("iam")
    iam.update_account_password_policy(
        MinimumPasswordLength=16,
        RequireSymbols=True,
        RequireNumbers=True,
        RequireUppercaseCharacters=True,
        RequireLowercaseCharacters=True,
        PasswordReusePrevention=24,
    )
    iam.create_user(UserName="ci-deployer")
    iam.create_access_key(UserName="ci-deployer")

    cloudtrail = session.client("cloudtrail")
    cloudtrail.create_trail(
        Name=TRAIL, S3BucketName=TRAIL_BUCKET, IsMultiRegionTrail=True, EnableLogFileValidation=True
    )
    cloudtrail.start_logging(Name=TRAIL)

    kms = session.client("kms")
    key_id = kms.create_key(Description=SECURE_BUCKET)["KeyMetadata"]["KeyId"]
    kms.enable_key_rotation(KeyId=key_id)


if __name__ == "__main__":
    main()
