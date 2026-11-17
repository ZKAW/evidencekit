import pytest
from conftest import ORG, REPOS_PATH, TOKEN, FakeGitHub, ok, repo, status

from evidencekit.github_checks import (
    GITHUB_CHECKS,
    branch_protection,
    dependabot_alerts,
    org_two_factor_required,
    secret_scanning,
)
from evidencekit.github_client import API_VERSION
from evidencekit.model import Status
from evidencekit.runner import run_check


@pytest.mark.parametrize("check", [check.run for check in GITHUB_CHECKS])
def test_compliant_org_passes(api: FakeGitHub, check) -> None:
    assert check(api.context()).status is Status.PASS


def test_requests_carry_token_and_api_version(api: FakeGitHub) -> None:
    org_two_factor_required(api.context())
    [request] = api.requests
    assert request.headers["Authorization"] == f"Bearer {TOKEN}"
    assert request.headers["X-GitHub-Api-Version"] == API_VERSION


def test_two_factor_not_required_fails(api: FakeGitHub) -> None:
    api.routes[f"/orgs/{ORG}"] = ok({"login": ORG, "two_factor_requirement_enabled": False})
    assert org_two_factor_required(api.context()).status is Status.FAIL


def test_two_factor_hidden_from_non_owner_is_an_error(api: FakeGitHub) -> None:
    api.routes[f"/orgs/{ORG}"] = ok({"login": ORG})
    assert org_two_factor_required(api.context()).status is Status.ERROR


def test_unprotected_default_branch_fails(api: FakeGitHub) -> None:
    api.routes[f"/repos/{ORG}/web/branches/main"] = ok({"name": "main", "protected": False})
    outcome = branch_protection(api.context())
    assert outcome.status is Status.FAIL
    assert outcome.summary == "1 of 2 repositories with an unprotected default branch"


def test_empty_repository_is_skipped(api: FakeGitHub) -> None:
    del api.routes[f"/repos/{ORG}/web/branches/main"]
    outcome = branch_protection(api.context())
    assert outcome.status is Status.PASS
    assert outcome.evidence["skipped_without_default_branch"] == [f"{ORG}/web"]


def test_archived_repositories_are_ignored(api: FakeGitHub) -> None:
    api.routes[REPOS_PATH] = ok([repo("api"), repo("legacy", secret_scanning_status="disabled", archived=True)])
    outcome = secret_scanning(api.context())
    assert outcome.status is Status.PASS
    assert [resource["repo"] for resource in outcome.evidence["resources"]] == [f"{ORG}/api"]


@pytest.mark.parametrize("scanning", ["disabled", None])
def test_secret_scanning_disabled_or_hidden_fails(api: FakeGitHub, scanning: str | None) -> None:
    api.routes[REPOS_PATH] = ok([repo("api"), repo("web", secret_scanning_status=scanning)])
    assert secret_scanning(api.context()).status is Status.FAIL


def test_dependabot_alerts_disabled_fails(api: FakeGitHub) -> None:
    api.routes[f"/repos/{ORG}/web/vulnerability-alerts"] = status(404)
    outcome = dependabot_alerts(api.context())
    assert outcome.status is Status.FAIL
    assert {"repo": f"{ORG}/web", "enabled": False} in outcome.evidence["resources"]


def test_forbidden_response_becomes_an_error_result(api: FakeGitHub) -> None:
    api.routes[f"/repos/{ORG}/web/vulnerability-alerts"] = status(403)
    [check] = [check for check in GITHUB_CHECKS if check.id == "github.repo.dependabot_alerts"]
    result = run_check(check, api.context())
    assert result.status is Status.ERROR
    assert "403" in result.summary


def test_repository_listing_follows_pagination(api: FakeGitHub) -> None:
    next_page = f"https://api.github.com/orgs/{ORG}/repos?per_page=100&page=2"
    api.routes[REPOS_PATH] = ok([repo("api")], {"Link": f'<{next_page}>; rel="next"'})
    api.routes[f"/orgs/{ORG}/repos?per_page=100&page=2"] = ok([repo("web", secret_scanning_status="disabled")])
    outcome = secret_scanning(api.context())
    assert outcome.summary == "1 of 2 repositories without secret scanning enabled"
