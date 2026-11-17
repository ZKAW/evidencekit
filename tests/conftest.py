from datetime import UTC, datetime
from typing import Any

import boto3
import httpx
import pytest
from moto import mock_aws
from moto.core import DEFAULT_ACCOUNT_ID
from moto.iam.models import iam_backends

from evidencekit.aws_checks import AwsContext
from evidencekit.github_checks import GitHubContext
from evidencekit.github_client import GitHubClient

REGION = "eu-west-3"
DATA_BUCKET = "patient-records"
TRAIL_BUCKET = "audit-trail-logs"
TRAIL = "org-trail"
STRONG_PASSWORD_POLICY = {
    "MinimumPasswordLength": 16,
    "RequireSymbols": True,
    "RequireNumbers": True,
    "RequireUppercaseCharacters": True,
    "RequireLowercaseCharacters": True,
    "PasswordReusePrevention": 24,
}
FULL_PUBLIC_ACCESS_BLOCK = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}


@pytest.fixture(autouse=True)
def aws_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    for name in ("AWS_PROFILE", "AWS_ENDPOINT_URL", "AWS_SESSION_TOKEN", "GITHUB_TOKEN"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def session():
    with mock_aws():
        yield boto3.Session(region_name=REGION)


@pytest.fixture
def aws(session: boto3.Session) -> AwsContext:
    return AwsContext(session, datetime.now(UTC))


@pytest.fixture
def compliant_aws(aws: AwsContext) -> AwsContext:
    iam = aws.session.client("iam")
    iam.update_account_password_policy(**STRONG_PASSWORD_POLICY)
    _enable_root_mfa()
    s3 = aws.session.client("s3")
    for bucket in (DATA_BUCKET, TRAIL_BUCKET):
        _create_secure_bucket(s3, bucket)
    cloudtrail = aws.session.client("cloudtrail")
    cloudtrail.create_trail(
        Name=TRAIL, S3BucketName=TRAIL_BUCKET, IsMultiRegionTrail=True, EnableLogFileValidation=True
    )
    cloudtrail.start_logging(Name=TRAIL)
    return aws


def _enable_root_mfa() -> None:
    # NOTE: moto has no API to attach an MFA device to the root user.
    iam_backends[DEFAULT_ACCOUNT_ID]["aws"].account_summary._account_mfa_enabled = 1


def _create_secure_bucket(s3, name: str) -> None:
    s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": REGION})
    s3.put_public_access_block(Bucket=name, PublicAccessBlockConfiguration=FULL_PUBLIC_ACCESS_BLOCK)
    s3.put_bucket_encryption(
        Bucket=name,
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]
        },
    )
    s3.put_bucket_versioning(Bucket=name, VersioningConfiguration={"Status": "Enabled"})


ORG = "acme"
TOKEN = "ghp_fake_token_for_tests"
REPOS_PATH = f"/orgs/{ORG}/repos?per_page=100"

Route = tuple[int, Any, dict[str, str]]


def repo(name: str, secret_scanning_status: str | None = "enabled", archived: bool = False) -> dict[str, Any]:
    analysis = {"secret_scanning": {"status": secret_scanning_status}} if secret_scanning_status else None
    return {
        "name": name,
        "full_name": f"{ORG}/{name}",
        "default_branch": "main",
        "archived": archived,
        "security_and_analysis": analysis,
    }


def ok(body: Any = None, headers: dict[str, str] | None = None) -> Route:
    return (200, body, headers or {})


def status(code: int) -> Route:
    return (code, None, {})


class FakeGitHub:
    def __init__(self, routes: dict[str, Route]) -> None:
        self.routes = routes
        self.requests: list[httpx.Request] = []

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        code, body, headers = self.routes.get(request.url.raw_path.decode(), status(404))
        return httpx.Response(code, json=body, headers=headers)

    def context(self) -> GitHubContext:
        return GitHubContext(GitHubClient(TOKEN, transport=httpx.MockTransport(self.handle)), ORG)


@pytest.fixture
def api() -> FakeGitHub:
    routes = {
        f"/orgs/{ORG}": ok({"login": ORG, "two_factor_requirement_enabled": True}),
        REPOS_PATH: ok([repo("api"), repo("web")]),
    }
    for name in ("api", "web"):
        routes[f"/repos/{ORG}/{name}/branches/main"] = ok({"name": "main", "protected": True})
        routes[f"/repos/{ORG}/{name}/vulnerability-alerts"] = status(204)
    return FakeGitHub(routes)
