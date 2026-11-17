from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path

import yaml

from evidencekit.aws_checks import AWS_CHECKS
from evidencekit.github_checks import GITHUB_CHECKS
from evidencekit.model import Check

CHECKS: dict[str, Check] = {check.id: check for check in (*AWS_CHECKS, *GITHUB_CHECKS)}
DEFAULT_CATALOGUE = files("evidencekit") / "catalogue.yaml"


class CatalogueError(ValueError):
    pass


@dataclass(frozen=True)
class Control:
    id: str
    title: str
    rationale: str
    hds: tuple[str, ...]
    checks: tuple[str, ...]


def load_catalogue(path: Path | None = None) -> list[Control]:
    text = path.read_text() if path else DEFAULT_CATALOGUE.read_text()
    controls = [_parse_control(entry) for entry in yaml.safe_load(text)["controls"]]
    _validate(controls)
    return controls


def _parse_control(entry: dict) -> Control:
    return Control(
        id=entry["id"],
        title=entry["title"],
        rationale=entry["rationale"].strip(),
        hds=tuple(entry.get("hds", ())),
        checks=tuple(entry["checks"]),
    )


def _validate(controls: list[Control]) -> None:
    ids = [control.id for control in controls]
    if len(ids) != len(set(ids)):
        raise CatalogueError("duplicate control id in catalogue")
    for control in controls:
        if not control.checks:
            raise CatalogueError(f"{control.id} has no checks")
        unknown = [check_id for check_id in control.checks if check_id not in CHECKS]
        if unknown:
            raise CatalogueError(f"{control.id} references unknown checks: {', '.join(unknown)}")
