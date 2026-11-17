import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, NoReturn

import boto3
import typer
from botocore.exceptions import BotoCoreError, ClientError

from evidencekit.aws_checks import AWS_CHECKS, AwsContext
from evidencekit.catalogue import CHECKS, load_catalogue
from evidencekit.github_checks import GITHUB_CHECKS, GitHubContext
from evidencekit.github_client import GitHubClient
from evidencekit.model import CheckResult
from evidencekit.pack import verify_pack, write_pack
from evidencekit.runner import run_checks

TOKEN_ENV = "GITHUB_TOKEN"

app = typer.Typer(no_args_is_help=True, add_completion=False)


@app.command()
def controls() -> None:
    """List the controls in the catalogue and the checks mapped to them."""
    for control in load_catalogue():
        typer.echo(f"{control.id}  {control.title}")
        for check_id in control.checks:
            typer.echo(f"    {check_id}  {CHECKS[check_id].title}")


@app.command()
def collect(
    aws: Annotated[bool, typer.Option("--aws", help="Run the AWS checks with the default boto3 credentials.")] = False,
    github_org: Annotated[str | None, typer.Option(help=f"Run the GitHub checks on this org ({TOKEN_ENV}).")] = None,
    out: Annotated[Path, typer.Option(help="Directory that receives the timestamped pack.")] = Path("evidence"),
) -> None:
    """Run the checks and write a timestamped, hashed evidence pack."""
    if not aws and not github_org:
        raise typer.BadParameter("choose at least one of --aws and --github-org")
    collected_at = datetime.now(UTC).replace(microsecond=0)
    results: list[CheckResult] = []
    scope: dict[str, str] = {}
    if aws:
        session = boto3.Session()
        scope["aws_account"] = _aws_account(session)
        results += run_checks(AWS_CHECKS, AwsContext(session, collected_at))
    if github_org:
        scope["github_org"] = github_org
        with GitHubClient(_github_token()) as client:
            results += run_checks(GITHUB_CHECKS, GitHubContext(client, github_org))
    for result in results:
        typer.echo(f"{result.status:<5}  {result.check_id}  {result.summary}")
    pack = write_pack(out, load_catalogue(), results, collected_at, scope)
    typer.echo(f"\nevidence pack: {pack.path}")
    typer.echo(f"manifest sha256: {pack.manifest_sha256}")


@app.command()
def verify(
    pack_dir: Annotated[Path, typer.Argument(help="Evidence pack directory to check.")],
    expected_manifest_sha256: Annotated[
        str | None, typer.Option(help="Manifest hash recorded outside the pack at collection time.")
    ] = None,
) -> None:
    """Recompute every hash in a pack and report tampering."""
    problems = verify_pack(pack_dir, expected_manifest_sha256)
    for problem in problems:
        typer.echo(f"TAMPERED  {problem}")
    if problems:
        raise typer.Exit(1)
    typer.echo(f"OK  {pack_dir}: every file matches the manifest")


def _aws_account(session: boto3.Session) -> str:
    if session.region_name is None:
        _abort("no AWS region configured: set AWS_DEFAULT_REGION or a region in your AWS profile")
    try:
        return session.client("sts").get_caller_identity()["Account"]
    except (BotoCoreError, ClientError) as error:
        _abort(f"cannot reach AWS: {error}")


def _github_token() -> str:
    token = os.environ.get(TOKEN_ENV)
    if not token:
        _abort(f"{TOKEN_ENV} is not set")
    return token


def _abort(message: str) -> NoReturn:
    typer.echo(f"error: {message}", err=True)
    raise typer.Exit(1)
