from pathlib import Path

import pytest

from evidencekit.catalogue import CHECKS, CatalogueError, load_catalogue

EXPECTED_CONTROL_COUNT = 10


def test_catalogue_has_ten_controls_with_rationale() -> None:
    controls = load_catalogue()
    assert len(controls) == EXPECTED_CONTROL_COUNT
    assert all(control.rationale for control in controls)


def test_every_referenced_check_exists() -> None:
    referenced = {check_id for control in load_catalogue() for check_id in control.checks}
    assert referenced <= CHECKS.keys()


def test_every_check_backs_at_least_one_control() -> None:
    referenced = {check_id for control in load_catalogue() for check_id in control.checks}
    assert referenced == CHECKS.keys()


def test_unknown_check_is_rejected(tmp_path: Path) -> None:
    catalogue = tmp_path / "catalogue.yaml"
    catalogue.write_text("controls:\n  - {id: A.5.15, title: Access control, rationale: r, checks: [aws.nope]}\n")
    with pytest.raises(CatalogueError, match=r"aws\.nope"):
        load_catalogue(catalogue)


def test_duplicate_control_is_rejected(tmp_path: Path) -> None:
    entry = "  - {id: A.8.2, title: Privileged access rights, rationale: r, checks: [aws.iam.root_mfa]}\n"
    catalogue = tmp_path / "catalogue.yaml"
    catalogue.write_text("controls:\n" + entry + entry)
    with pytest.raises(CatalogueError, match="duplicate"):
        load_catalogue(catalogue)
