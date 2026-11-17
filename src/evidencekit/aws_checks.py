from dataclasses import dataclass
from datetime import datetime
from typing import Any

import boto3
from botocore.exceptions import ClientError

from evidencekit.model import Check, Outcome, Provider, Status, outcome_for

MIN_PASSWORD_LENGTH = 14
MIN_PASSWORD_REUSE_PREVENTION = 24
REQUIRED_PASSWORD_FLAGS = (
    "RequireUppercaseCharacters",
    "RequireLowercaseCharacters",
    "RequireNumbers",
    "RequireSymbols",
)
MAX_ACCESS_KEY_IDLE_DAYS = 90
MAX_USER_IDLE_DAYS = 90
MIN_LOG_RETENTION_DAYS = 365
VISIBLE_KEY_ID_CHARS = 4
PUBLIC_ACCESS_BLOCK_FLAGS = (
    "BlockPublicAcls",
    "IgnorePublicAcls",
    "BlockPublicPolicy",
    "RestrictPublicBuckets",
)
NO_PUBLIC_ACCESS_BLOCK = "NoSuchPublicAccessBlockConfiguration"
NO_BUCKET_ENCRYPTION = "ServerSideEncryptionConfigurationNotFoundError"
NO_LIFECYCLE = "NoSuchLifecycleConfiguration"


@dataclass(frozen=True)
class AwsContext:
    session: boto3.Session
    now: datetime


def root_mfa(ctx: AwsContext) -> Outcome:
    summary = ctx.session.client("iam").get_account_summary()["SummaryMap"]
    enabled = summary["AccountMFAEnabled"] == 1
    evidence = {"AccountMFAEnabled": summary["AccountMFAEnabled"]}
    if not enabled:
        return Outcome(Status.FAIL, "root user has no MFA device", evidence)
    return Outcome(Status.PASS, "root user has MFA enabled", evidence)


def password_policy(ctx: AwsContext) -> Outcome:
    iam = ctx.session.client("iam")
    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]
    except iam.exceptions.NoSuchEntityException:
        return Outcome(Status.FAIL, "no account password policy is set", {"password_policy": None})
    gaps = password_policy_gaps(policy)
    evidence = {"password_policy": policy, "gaps": gaps}
    if gaps:
        return Outcome(Status.FAIL, f"{len(gaps)} password policy gaps", evidence)
    return Outcome(Status.PASS, "password policy meets the baseline", evidence)


def password_policy_gaps(policy: dict[str, Any]) -> list[str]:
    gaps = [f"{flag} is not enabled" for flag in REQUIRED_PASSWORD_FLAGS if not policy.get(flag)]
    if policy.get("MinimumPasswordLength", 0) < MIN_PASSWORD_LENGTH:
        gaps.append(f"MinimumPasswordLength is below {MIN_PASSWORD_LENGTH}")
    if policy.get("PasswordReusePrevention", 0) < MIN_PASSWORD_REUSE_PREVENTION:
        gaps.append(f"PasswordReusePrevention is below {MIN_PASSWORD_REUSE_PREVENTION}")
    return gaps


def unused_access_keys(ctx: AwsContext) -> Outcome:
    iam = ctx.session.client("iam")
    keys = []
    for page in iam.get_paginator("list_users").paginate():
        for user in page["Users"]:
            keys.extend(_active_keys(iam, user["UserName"], ctx.now))
    for key in keys:
        key["recently_used"] = key["idle_days"] <= MAX_ACCESS_KEY_IDLE_DAYS
    return outcome_for(keys, "recently_used", f"active access keys idle for more than {MAX_ACCESS_KEY_IDLE_DAYS} days")


def _active_keys(iam: Any, user_name: str, now: datetime) -> list[dict[str, Any]]:
    keys = []
    for page in iam.get_paginator("list_access_keys").paginate(UserName=user_name):
        for key in page["AccessKeyMetadata"]:
            if key["Status"] != "Active":
                continue
            last_used = iam.get_access_key_last_used(AccessKeyId=key["AccessKeyId"])["AccessKeyLastUsed"]
            keys.append(key_record(user_name, key, last_used.get("LastUsedDate"), now))
    return keys


def key_record(user_name: str, key: dict[str, Any], last_used: datetime | None, now: datetime) -> dict[str, Any]:
    created = key["CreateDate"]
    return {
        "user": user_name,
        "access_key_id": mask_key_id(key["AccessKeyId"]),
        "created": created.isoformat(),
        "last_used": last_used.isoformat() if last_used else None,
        "idle_days": (now - (last_used or created)).days,
    }


def mask_key_id(key_id: str) -> str:
    return "*" * (len(key_id) - VISIBLE_KEY_ID_CHARS) + key_id[-VISIBLE_KEY_ID_CHARS:]


def inactive_users(ctx: AwsContext) -> Outcome:
    iam = ctx.session.client("iam")
    users = [
        user_activity(user, _last_key_use(iam, user["UserName"]), ctx.now)
        for page in iam.get_paginator("list_users").paginate()
        for user in page["Users"]
    ]
    for user in users:
        user["active"] = user["idle_days"] <= MAX_USER_IDLE_DAYS
    return outcome_for(users, "active", f"IAM users with no activity for more than {MAX_USER_IDLE_DAYS} days")


def _last_key_use(iam: Any, user_name: str) -> datetime | None:
    uses = [
        iam.get_access_key_last_used(AccessKeyId=key["AccessKeyId"])["AccessKeyLastUsed"].get("LastUsedDate")
        for page in iam.get_paginator("list_access_keys").paginate(UserName=user_name)
        for key in page["AccessKeyMetadata"]
    ]
    return max((use for use in uses if use), default=None)


def user_activity(user: dict[str, Any], last_key_use: datetime | None, now: datetime) -> dict[str, Any]:
    activity = [moment for moment in (user.get("PasswordLastUsed"), last_key_use) if moment]
    last_active = max(activity, default=None)
    return {
        "user": user["UserName"],
        "created": user["CreateDate"].isoformat(),
        "console_last_used": user["PasswordLastUsed"].isoformat() if user.get("PasswordLastUsed") else None,
        "access_key_last_used": last_key_use.isoformat() if last_key_use else None,
        "idle_days": (now - (last_active or user["CreateDate"])).days,
    }


def s3_public_access_block(ctx: AwsContext) -> Outcome:
    s3 = ctx.session.client("s3")
    buckets = [_public_access_record(s3, name) for name in _bucket_names(s3)]
    return outcome_for(buckets, "fully_blocked", "buckets without a full public access block")


def _public_access_record(s3: Any, bucket: str) -> dict[str, Any]:
    try:
        config = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
    except ClientError as error:
        if _error_code(error) != NO_PUBLIC_ACCESS_BLOCK:
            raise
        config = {}
    flags = {flag: config.get(flag, False) for flag in PUBLIC_ACCESS_BLOCK_FLAGS}
    return {"bucket": bucket, "public_access_block": flags, "fully_blocked": all(flags.values())}


def s3_default_encryption(ctx: AwsContext) -> Outcome:
    s3 = ctx.session.client("s3")
    buckets = [_encryption_record(s3, name) for name in _bucket_names(s3)]
    return outcome_for(buckets, "encrypted", "buckets without default encryption")


def _encryption_record(s3: Any, bucket: str) -> dict[str, Any]:
    try:
        rules = s3.get_bucket_encryption(Bucket=bucket)["ServerSideEncryptionConfiguration"]["Rules"]
    except ClientError as error:
        if _error_code(error) != NO_BUCKET_ENCRYPTION:
            raise
        rules = []
    algorithms = [
        rule["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
        for rule in rules
        if "ApplyServerSideEncryptionByDefault" in rule
    ]
    return {"bucket": bucket, "algorithms": algorithms, "encrypted": bool(algorithms)}


def s3_versioning(ctx: AwsContext) -> Outcome:
    s3 = ctx.session.client("s3")
    buckets = [_versioning_record(s3, name) for name in _bucket_names(s3)]
    return outcome_for(buckets, "versioned", "buckets without versioning enabled")


def _versioning_record(s3: Any, bucket: str) -> dict[str, Any]:
    status = s3.get_bucket_versioning(Bucket=bucket).get("Status")
    return {"bucket": bucket, "versioning_status": status, "versioned": status == "Enabled"}


def _bucket_names(s3: Any) -> list[str]:
    return [bucket["Name"] for page in s3.get_paginator("list_buckets").paginate() for bucket in page["Buckets"]]


def _error_code(error: ClientError) -> str:
    return error.response.get("Error", {}).get("Code", "")


def cloudtrail_multi_region(ctx: AwsContext) -> Outcome:
    cloudtrail = ctx.session.client("cloudtrail")
    trails = [
        {
            "name": trail["Name"],
            "arn": trail["TrailARN"],
            "home_region": trail.get("HomeRegion"),
            "multi_region": trail.get("IsMultiRegionTrail", False),
            "logging": cloudtrail.get_trail_status(Name=trail["TrailARN"])["IsLogging"],
        }
        for trail in _trails(cloudtrail)
    ]
    evidence = {"trails": trails}
    covering = [trail["name"] for trail in trails if trail["multi_region"] and trail["logging"]]
    if not covering:
        return Outcome(Status.FAIL, "no multi-region trail is logging", evidence)
    return Outcome(Status.PASS, f"multi-region trails logging: {', '.join(covering)}", evidence)


def cloudtrail_log_validation(ctx: AwsContext) -> Outcome:
    trails = [
        {
            "name": trail["Name"],
            "arn": trail["TrailARN"],
            "log_file_validation": trail.get("LogFileValidationEnabled", False),
        }
        for trail in _trails(ctx.session.client("cloudtrail"))
    ]
    if not trails:
        return Outcome(Status.FAIL, "no CloudTrail trail is configured", {"resources": []})
    return outcome_for(trails, "log_file_validation", "trails without log file validation")


def cloudtrail_log_retention(ctx: AwsContext) -> Outcome:
    s3 = ctx.session.client("s3")
    trails = [_retention_record(s3, trail) for trail in _trails(ctx.session.client("cloudtrail"))]
    if not trails:
        return Outcome(Status.FAIL, "no CloudTrail trail is configured", {"resources": []})
    return outcome_for(trails, "retained", f"trails whose logs expire before {MIN_LOG_RETENTION_DAYS} days")


def _retention_record(s3: Any, trail: dict[str, Any]) -> dict[str, Any]:
    bucket = trail["S3BucketName"]
    days = log_expiration_days(_lifecycle_rules(s3, bucket))
    return {
        "name": trail["Name"],
        "bucket": bucket,
        "expires_after_days": days,
        "retained": days is None or days >= MIN_LOG_RETENTION_DAYS,
    }


def _lifecycle_rules(s3: Any, bucket: str) -> list[dict[str, Any]]:
    try:
        return s3.get_bucket_lifecycle_configuration(Bucket=bucket)["Rules"]
    except ClientError as error:
        if _error_code(error) == NO_LIFECYCLE:
            return []
        raise


def log_expiration_days(rules: list[dict[str, Any]]) -> int | None:
    days = [
        rule["Expiration"]["Days"]
        for rule in rules
        if rule["Status"] == "Enabled" and "Days" in rule.get("Expiration", {})
    ]
    return min(days, default=None)


def _trails(cloudtrail: Any) -> list[dict[str, Any]]:
    return cloudtrail.describe_trails(includeShadowTrails=True)["trailList"]


def kms_key_rotation(ctx: AwsContext) -> Outcome:
    kms = ctx.session.client("kms")
    described = [
        kms.describe_key(KeyId=key["KeyId"])["KeyMetadata"]
        for page in kms.get_paginator("list_keys").paginate()
        for key in page["Keys"]
    ]
    keys = [_rotation_record(kms, metadata) for metadata in described if _is_rotatable_customer_key(metadata)]
    return outcome_for(keys, "rotation_enabled", "customer managed keys without automatic rotation")


def _is_rotatable_customer_key(metadata: dict[str, Any]) -> bool:
    return (
        metadata["KeyManager"] == "CUSTOMER"
        and metadata["KeyState"] == "Enabled"
        and metadata.get("KeySpec") == "SYMMETRIC_DEFAULT"
        and metadata.get("Origin") == "AWS_KMS"
    )


def _rotation_record(kms: Any, metadata: dict[str, Any]) -> dict[str, Any]:
    rotation = kms.get_key_rotation_status(KeyId=metadata["KeyId"])
    return {
        "key_id": metadata["KeyId"],
        "description": metadata.get("Description", ""),
        "rotation_enabled": rotation["KeyRotationEnabled"],
    }


AWS_CHECKS = (
    Check("aws.iam.root_mfa", "Root user has MFA enabled", Provider.AWS, root_mfa),
    Check("aws.iam.password_policy", "IAM password policy meets the baseline", Provider.AWS, password_policy),
    Check("aws.iam.unused_access_keys", "No active access key is left unused", Provider.AWS, unused_access_keys),
    Check("aws.iam.inactive_users", "No IAM user is left inactive", Provider.AWS, inactive_users),
    Check("aws.s3.public_access_block", "S3 buckets block public access", Provider.AWS, s3_public_access_block),
    Check("aws.s3.default_encryption", "S3 buckets encrypt objects by default", Provider.AWS, s3_default_encryption),
    Check("aws.s3.versioning", "S3 buckets keep object versions", Provider.AWS, s3_versioning),
    Check(
        "aws.cloudtrail.multi_region",
        "A multi-region CloudTrail trail is logging",
        Provider.AWS,
        cloudtrail_multi_region,
    ),
    Check(
        "aws.cloudtrail.log_validation",
        "CloudTrail log file validation is enabled",
        Provider.AWS,
        cloudtrail_log_validation,
    ),
    Check(
        "aws.cloudtrail.log_retention",
        f"CloudTrail logs are kept for at least {MIN_LOG_RETENTION_DAYS} days",
        Provider.AWS,
        cloudtrail_log_retention,
    ),
    Check("aws.kms.key_rotation", "Customer managed KMS keys rotate automatically", Provider.AWS, kms_key_rotation),
)
