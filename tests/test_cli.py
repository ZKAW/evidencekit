import functools
from pathlib import Path

import httpx
import pytest
from conftest import ORG, TOKEN, FakeGitHub
from typer.testing import CliRunner

from evidencekit import cli
from evidencekit.aws_checks import AwsContext
from evidencekit.github_client import GitHubClient

runner = CliRunner()


def _pack_dir(out: Path) -> Path:
    [pack] = list(out.iterdir())
    return pack


def test_controls_lists_catalogue() -> None:
    result = runner.invoke(cli.app, ["controls"])
    assert result.exit_code == 0
    assert "A.8.15  Logging" in result.output
    assert "aws.cloudtrail.log_validation" in result.output


def test_collect_needs_a_provider(tmp_path: Path) -> None:
    result = runner.invoke(cli.app, ["collect", "--out", str(tmp_path)])
    assert result.exit_code == 2


def test_aws_collect_then_verify_then_tamper(compliant_aws: AwsContext, tmp_path: Path) -> None:
    collected = runner.invoke(cli.app, ["collect", "--aws", "--out", str(tmp_path)])
    assert collected.exit_code == 0, collected.output
    assert "pass   aws.iam.root_mfa" in collected.output
    pack = _pack_dir(tmp_path)
    assert len(list((pack / "checks").iterdir())) == len(cli.AWS_CHECKS)

    assert runner.invoke(cli.app, ["verify", str(pack)]).exit_code == 0

    evidence = pack / "checks" / "aws.iam.root_mfa.json"
    evidence.write_text(evidence.read_text().replace('"pass"', '"fail"'))
    tampered = runner.invoke(cli.app, ["verify", str(pack)])
    assert tampered.exit_code == 1
    assert "TAMPERED  checks/aws.iam.root_mfa.json: modified" in tampered.output


def test_github_collect_requires_token(tmp_path: Path) -> None:
    result = runner.invoke(cli.app, ["collect", "--github-org", ORG, "--out", str(tmp_path)])
    assert result.exit_code == 1
    assert "GITHUB_TOKEN is not set" in result.output


def test_github_token_never_reaches_the_pack(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, api: FakeGitHub) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", TOKEN)
    monkeypatch.setattr(cli, "GitHubClient", functools.partial(GitHubClient, transport=httpx.MockTransport(api.handle)))
    result = runner.invoke(cli.app, ["collect", "--github-org", ORG, "--out", str(tmp_path)])
    assert result.exit_code == 0, result.output
    pack = _pack_dir(tmp_path)
    assert all(TOKEN not in path.read_text() for path in pack.rglob("*") if path.is_file())
