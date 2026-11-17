import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from evidencekit.catalogue import load_catalogue
from evidencekit.model import CheckResult, Provider, Status
from evidencekit.pack import MANIFEST_FILE, Pack, sha256_file, verify_pack, write_pack
from evidencekit.report import control_status, table_cell

COLLECTED_AT = datetime(2026, 11, 16, 9, 30, tzinfo=UTC)
ROOT_MFA_FILE = "checks/aws.iam.root_mfa.json"


def result(check_id: str, status: Status) -> CheckResult:
    return CheckResult(
        check_id=check_id,
        title=check_id,
        provider=Provider.AWS,
        status=status,
        summary=f"{check_id} is {status}",
        evidence={"detail": "value | with pipe"},
        collected_at=COLLECTED_AT.isoformat(),
    )


@pytest.fixture
def pack(tmp_path: Path) -> Pack:
    results = [result("aws.iam.root_mfa", Status.PASS), result("aws.iam.password_policy", Status.FAIL)]
    return write_pack(tmp_path, load_catalogue(), results, COLLECTED_AT, {"aws_account": "123456789012"})


def test_pack_layout(pack: Pack) -> None:
    assert pack.path.name == "20261116T093000Z"
    names = sorted(path.relative_to(pack.path).as_posix() for path in pack.path.rglob("*") if path.is_file())
    assert names == [
        "checks/aws.iam.password_policy.json",
        ROOT_MFA_FILE,
        MANIFEST_FILE,
        "manifest.sha256",
        "report.md",
    ]


def test_manifest_hashes_every_file(pack: Pack) -> None:
    manifest = json.loads((pack.path / MANIFEST_FILE).read_text())
    assert manifest["aws_account"] == "123456789012"
    for relative, digest in manifest["files"].items():
        assert sha256_file(pack.path / relative) == digest
    assert sha256_file(pack.path / MANIFEST_FILE) == pack.manifest_sha256


def test_report_embeds_evidence_hashes_and_statuses(pack: Pack) -> None:
    report = (pack.path / "report.md").read_text()
    assert sha256_file(pack.path / ROOT_MFA_FILE) in report
    assert "| A.8.2 | Privileged access rights | pass |" in report
    assert "| A.8.5 | Secure authentication | fail |" in report
    assert "| A.8.28 | Secure coding | not collected |" in report


def test_untouched_pack_verifies(pack: Pack) -> None:
    assert verify_pack(pack.path, pack.manifest_sha256) == []


def test_modified_evidence_is_detected(pack: Pack) -> None:
    evidence = pack.path / ROOT_MFA_FILE
    evidence.write_text(evidence.read_text().replace('"pass"', '"fail"'))
    assert verify_pack(pack.path) == [f"{ROOT_MFA_FILE}: modified (SHA-256 mismatch)"]


def test_deleted_evidence_is_detected(pack: Pack) -> None:
    (pack.path / ROOT_MFA_FILE).unlink()
    assert verify_pack(pack.path) == [f"{ROOT_MFA_FILE}: missing"]


def test_added_file_is_detected(pack: Pack) -> None:
    (pack.path / "checks" / "extra.json").write_text("{}")
    assert verify_pack(pack.path) == ["checks/extra.json: not listed in the manifest"]


def test_rewritten_manifest_is_detected(pack: Pack) -> None:
    evidence = pack.path / ROOT_MFA_FILE
    evidence.write_text("{}\n")
    manifest_path = pack.path / MANIFEST_FILE
    manifest = json.loads(manifest_path.read_text())
    manifest["files"][ROOT_MFA_FILE] = sha256_file(evidence)
    manifest_path.write_text(json.dumps(manifest))
    problems = verify_pack(pack.path, pack.manifest_sha256)
    assert "manifest.json does not match manifest.sha256" in problems
    assert f"manifest.json does not match the expected SHA-256 {pack.manifest_sha256}" in problems


def test_manifest_path_outside_pack_is_rejected(pack: Pack) -> None:
    manifest_path = pack.path / MANIFEST_FILE
    manifest = json.loads(manifest_path.read_text())
    manifest["files"]["../outside.json"] = "0" * 64
    manifest_path.write_text(json.dumps(manifest))
    assert "../outside.json: path points outside the pack" in verify_pack(pack.path)


def test_corrupt_manifest_is_reported(pack: Pack) -> None:
    (pack.path / MANIFEST_FILE).write_text("[]")
    assert "manifest.json is not a valid manifest" in verify_pack(pack.path)


def test_missing_manifest_is_reported(tmp_path: Path) -> None:
    assert verify_pack(tmp_path) == ["manifest.json is missing"]


def test_control_status_reports_the_worst_check() -> None:
    [control] = [control for control in load_catalogue() if control.id == "A.8.5"]
    passing = {check_id: result(check_id, Status.PASS) for check_id in control.checks}
    assert control_status(control, passing) is Status.PASS
    errored = passing | {"aws.iam.root_mfa": result("aws.iam.root_mfa", Status.ERROR)}
    assert control_status(control, errored) is Status.ERROR
    failed = errored | {"aws.iam.password_policy": result("aws.iam.password_policy", Status.FAIL)}
    assert control_status(control, failed) is Status.FAIL


def test_table_cell_escapes_markdown() -> None:
    assert table_cell("a | b\nc") == "a \\| b c"
