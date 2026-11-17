from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

import httpx

from evidencekit.github_client import GitHubClient
from evidencekit.model import Check, Outcome, Provider, Status, outcome_for


@dataclass(frozen=True)
class GitHubContext:
    client: GitHubClient
    org: str


def org_two_factor_required(ctx: GitHubContext) -> Outcome:
    org = ctx.client.get_json(f"/orgs/{ctx.org}")
    required = org.get("two_factor_requirement_enabled")
    evidence = {"org": ctx.org, "two_factor_requirement_enabled": required}
    if required is None:
        return Outcome(Status.ERROR, "2FA requirement is only visible to organization owners", evidence)
    if not required:
        return Outcome(Status.FAIL, "organization does not require 2FA", evidence)
    return Outcome(Status.PASS, "organization requires 2FA for all members", evidence)


def branch_protection(ctx: GitHubContext) -> Outcome:
    records = [_branch_record(ctx.client, repo) for repo in _active_repos(ctx)]
    repos = [record for record in records if record["protected"] is not None]
    outcome = outcome_for(repos, "protected", "repositories with an unprotected default branch")
    empty = [record["repo"] for record in records if record["protected"] is None]
    return Outcome(outcome.status, outcome.summary, outcome.evidence | {"skipped_without_default_branch": empty})


def _branch_record(client: GitHubClient, repo: dict[str, Any]) -> dict[str, Any]:
    branch = repo["default_branch"]
    response = client.get(f"/repos/{repo['full_name']}/branches/{quote(branch, safe='')}")
    if response.status_code == httpx.codes.NOT_FOUND:
        return {"repo": repo["full_name"], "default_branch": branch, "protected": None}
    response.raise_for_status()
    return {"repo": repo["full_name"], "default_branch": branch, "protected": response.json()["protected"]}


def secret_scanning(ctx: GitHubContext) -> Outcome:
    repos = [_secret_scanning_record(repo) for repo in _active_repos(ctx)]
    return outcome_for(repos, "enabled", "repositories without secret scanning enabled")


def _secret_scanning_record(repo: dict[str, Any]) -> dict[str, Any]:
    analysis = repo.get("security_and_analysis") or {}
    status = (analysis.get("secret_scanning") or {}).get("status")
    return {"repo": repo["full_name"], "secret_scanning": status, "enabled": status == "enabled"}


def dependabot_alerts(ctx: GitHubContext) -> Outcome:
    repos = [_dependabot_record(ctx.client, repo) for repo in _active_repos(ctx)]
    return outcome_for(repos, "enabled", "repositories without Dependabot alerts")


def _dependabot_record(client: GitHubClient, repo: dict[str, Any]) -> dict[str, Any]:
    response = client.get(f"/repos/{repo['full_name']}/vulnerability-alerts")
    if response.status_code not in (httpx.codes.NO_CONTENT, httpx.codes.NOT_FOUND):
        response.raise_for_status()
    return {"repo": repo["full_name"], "enabled": response.status_code == httpx.codes.NO_CONTENT}


def _active_repos(ctx: GitHubContext) -> list[dict[str, Any]]:
    return [repo for repo in ctx.client.paginate(f"/orgs/{ctx.org}/repos") if not repo["archived"]]


GITHUB_CHECKS = (
    Check("github.org.two_factor_required", "Organization requires 2FA", Provider.GITHUB, org_two_factor_required),
    Check("github.repo.branch_protection", "Default branches are protected", Provider.GITHUB, branch_protection),
    Check("github.repo.secret_scanning", "Secret scanning is enabled", Provider.GITHUB, secret_scanning),
    Check("github.repo.dependabot_alerts", "Dependabot alerts are enabled", Provider.GITHUB, dependabot_alerts),
)
