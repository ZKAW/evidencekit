from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from conftest import DATA_BUCKET, REGION, TRAIL, TRAIL_BUCKET

from evidencekit.aws_checks import (
    MAX_ACCESS_KEY_IDLE_DAYS,
    MAX_USER_IDLE_DAYS,
    MIN_LOG_RETENTION_DAYS,
    AwsContext,
    cloudtrail_log_retention,
    cloudtrail_log_validation,
    cloudtrail_multi_region,
    inactive_users,
    key_record,
    kms_key_rotation,
    log_expiration_days,
    mask_key_id,
    password_policy,
    root_mfa,
    s3_default_encryption,
    s3_public_access_block,
    s3_versioning,
    unused_access_keys,
    user_activity,
)
from evidencekit.model import Status

S3_CHECKS = (
    (s3_public_access_block, "fully_blocked"),
    (s3_default_encryption, "encrypted"),
    (s3_versioning, "versioned"),
)
OPEN_BUCKET = "open-bucket"


def test_root_mfa_fails_without_device(aws: AwsContext) -> None:
    assert root_mfa(aws).status is Status.FAIL


def test_root_mfa_passes_with_device(compliant_aws: AwsContext) -> None:
    assert root_mfa(compliant_aws).status is Status.PASS


def test_password_policy_fails_when_missing(aws: AwsContext) -> None:
    outcome = password_policy(aws)
    assert outcome.status is Status.FAIL
    assert outcome.evidence == {"password_policy": None}


def test_password_policy_lists_each_gap(aws: AwsContext) -> None:
    aws.session.client("iam").update_account_password_policy(MinimumPasswordLength=8, RequireNumbers=True)
    outcome = password_policy(aws)
    assert outcome.status is Status.FAIL
    assert "MinimumPasswordLength is below 14" in outcome.evidence["gaps"]
    assert "RequireSymbols is not enabled" in outcome.evidence["gaps"]
    assert "RequireNumbers is not enabled" not in outcome.evidence["gaps"]


def test_password_policy_passes_when_strong(compliant_aws: AwsContext) -> None:
    assert password_policy(compliant_aws).status is Status.PASS


def _create_key(ctx: AwsContext, user: str = "ci-deployer") -> str:
    iam = ctx.session.client("iam")
    iam.create_user(UserName=user)
    return iam.create_access_key(UserName=user)["AccessKey"]["AccessKeyId"]


def _past_idle_limit(ctx: AwsContext) -> AwsContext:
    return replace(ctx, now=datetime.now(UTC) + timedelta(days=MAX_ACCESS_KEY_IDLE_DAYS + 1))


def test_fresh_access_key_passes_and_is_masked(compliant_aws: AwsContext) -> None:
    key_id = _create_key(compliant_aws)
    outcome = unused_access_keys(compliant_aws)
    assert outcome.status is Status.PASS
    [key] = outcome.evidence["resources"]
    assert key["access_key_id"].endswith(key_id[-4:])
    assert key_id not in str(outcome.evidence)


def test_idle_access_key_fails(compliant_aws: AwsContext) -> None:
    _create_key(compliant_aws)
    outcome = unused_access_keys(_past_idle_limit(compliant_aws))
    assert outcome.status is Status.FAIL
    assert outcome.evidence["resources"][0]["user"] == "ci-deployer"


def test_inactive_access_key_is_ignored(compliant_aws: AwsContext) -> None:
    key_id = _create_key(compliant_aws)
    compliant_aws.session.client("iam").update_access_key(UserName="ci-deployer", AccessKeyId=key_id, Status="Inactive")
    outcome = unused_access_keys(_past_idle_limit(compliant_aws))
    assert outcome.status is Status.PASS
    assert outcome.evidence["resources"] == []


def test_key_idle_time_counts_from_last_use() -> None:
    now = datetime(2026, 6, 1, tzinfo=UTC)
    key = {"AccessKeyId": "AKIAEXAMPLEKEY12345", "CreateDate": datetime(2024, 1, 1, tzinfo=UTC)}
    record = key_record("alice", key, now - timedelta(days=3), now)
    assert record["idle_days"] == 3


def test_mask_key_id_keeps_last_four_characters() -> None:
    assert mask_key_id("AKIAEXAMPLE1234") == "***********1234"


@pytest.mark.parametrize("check", [check for check, _ in S3_CHECKS])
def test_s3_checks_pass_on_hardened_buckets(compliant_aws: AwsContext, check) -> None:
    assert check(compliant_aws).status is Status.PASS


@pytest.mark.parametrize(("check", "compliant_key"), S3_CHECKS)
def test_s3_checks_fail_on_bare_bucket(compliant_aws: AwsContext, check, compliant_key: str) -> None:
    s3 = compliant_aws.session.client("s3")
    s3.create_bucket(Bucket=OPEN_BUCKET, CreateBucketConfiguration={"LocationConstraint": REGION})
    outcome = check(compliant_aws)
    assert outcome.status is Status.FAIL
    assert outcome.summary.startswith("1 of 3")
    failing = [resource["bucket"] for resource in outcome.evidence["resources"] if not resource[compliant_key]]
    assert failing == [OPEN_BUCKET]


def test_partial_public_access_block_fails(compliant_aws: AwsContext) -> None:
    compliant_aws.session.client("s3").put_public_access_block(
        Bucket=DATA_BUCKET,
        PublicAccessBlockConfiguration={"BlockPublicAcls": True, "IgnorePublicAcls": True},
    )
    assert s3_public_access_block(compliant_aws).status is Status.FAIL


def test_cloudtrail_checks_pass_with_validated_multi_region_trail(compliant_aws: AwsContext) -> None:
    assert cloudtrail_multi_region(compliant_aws).status is Status.PASS
    assert cloudtrail_log_validation(compliant_aws).status is Status.PASS


def test_cloudtrail_checks_fail_without_trails(aws: AwsContext) -> None:
    assert cloudtrail_multi_region(aws).status is Status.FAIL
    assert cloudtrail_log_validation(aws).status is Status.FAIL


def test_cloudtrail_checks_fail_on_single_region_unvalidated_trail(aws: AwsContext) -> None:
    aws.session.client("s3").create_bucket(
        Bucket="trail-logs", CreateBucketConfiguration={"LocationConstraint": REGION}
    )
    cloudtrail = aws.session.client("cloudtrail")
    cloudtrail.create_trail(Name="regional-trail", S3BucketName="trail-logs")
    cloudtrail.start_logging(Name="regional-trail")
    assert cloudtrail_multi_region(aws).status is Status.FAIL
    assert cloudtrail_log_validation(aws).status is Status.FAIL


def test_stopped_trail_fails_multi_region(compliant_aws: AwsContext) -> None:
    compliant_aws.session.client("cloudtrail").stop_logging(Name=TRAIL)
    outcome = cloudtrail_multi_region(compliant_aws)
    assert outcome.status is Status.FAIL
    assert outcome.evidence["trails"][0]["logging"] is False


def _expire_trail_logs_after(ctx: AwsContext, days: int) -> None:
    ctx.session.client("s3").put_bucket_lifecycle_configuration(
        Bucket=TRAIL_BUCKET,
        LifecycleConfiguration={
            "Rules": [{"ID": "expire", "Status": "Enabled", "Filter": {"Prefix": ""}, "Expiration": {"Days": days}}]
        },
    )


def test_trail_logs_without_expiration_are_retained(compliant_aws: AwsContext) -> None:
    outcome = cloudtrail_log_retention(compliant_aws)
    assert outcome.status is Status.PASS
    assert outcome.evidence["resources"][0]["expires_after_days"] is None


@pytest.mark.parametrize(
    ("days", "expected"), [(MIN_LOG_RETENTION_DAYS - 1, Status.FAIL), (MIN_LOG_RETENTION_DAYS, Status.PASS)]
)
def test_trail_logs_must_live_at_least_the_minimum(compliant_aws: AwsContext, days: int, expected: Status) -> None:
    _expire_trail_logs_after(compliant_aws, days)
    assert cloudtrail_log_retention(compliant_aws).status is expected


def test_log_retention_fails_without_trails(aws: AwsContext) -> None:
    assert cloudtrail_log_retention(aws).status is Status.FAIL


def test_shortest_enabled_expiration_wins() -> None:
    rules = [
        {"Status": "Enabled", "Expiration": {"Days": 400}},
        {"Status": "Enabled", "Expiration": {"Days": 30}},
        {"Status": "Disabled", "Expiration": {"Days": 1}},
        {"Status": "Enabled", "Transitions": [{"Days": 10, "StorageClass": "GLACIER"}]},
    ]
    assert log_expiration_days(rules) == 30


def test_customer_keys_must_rotate_and_aws_managed_keys_are_ignored(aws: AwsContext) -> None:
    kms = aws.session.client("kms")
    rotated = kms.create_key(Description="patient-records")["KeyMetadata"]["KeyId"]
    kms.enable_key_rotation(KeyId=rotated)
    assert kms_key_rotation(aws).status is Status.PASS

    static = kms.create_key(Description="backups")["KeyMetadata"]["KeyId"]
    kms.create_key(KeySpec="RSA_2048", KeyUsage="SIGN_VERIFY")
    outcome = kms_key_rotation(aws)

    assert outcome.status is Status.FAIL
    failing = [key["key_id"] for key in outcome.evidence["resources"] if not key["rotation_enabled"]]
    assert failing == [static]


def test_new_user_is_active_until_the_idle_limit(compliant_aws: AwsContext) -> None:
    compliant_aws.session.client("iam").create_user(UserName="auditor")
    assert inactive_users(compliant_aws).status is Status.PASS
    later = replace(compliant_aws, now=datetime.now(UTC) + timedelta(days=MAX_USER_IDLE_DAYS + 1))
    outcome = inactive_users(later)
    assert outcome.status is Status.FAIL
    assert outcome.evidence["resources"][0]["user"] == "auditor"


def test_user_idle_time_counts_from_latest_console_or_key_use() -> None:
    now = datetime(2026, 6, 1, tzinfo=UTC)
    user = {"UserName": "ops", "CreateDate": now - timedelta(days=400), "PasswordLastUsed": now - timedelta(days=200)}
    assert user_activity(user, now - timedelta(days=5), now)["idle_days"] == 5
    assert user_activity(user, None, now)["idle_days"] == 200
    assert user_activity({**user, "PasswordLastUsed": None}, None, now)["idle_days"] == 400
