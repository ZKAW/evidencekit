from typing import Any

from jinja2 import Environment, PackageLoader, StrictUndefined

from evidencekit.catalogue import Control
from evidencekit.model import CheckResult, Status

STATUS_SEVERITY = (Status.FAIL, Status.ERROR, Status.NOT_COLLECTED, Status.PASS)
TEMPLATE = "report.md.j2"


def control_status(control: Control, results: dict[str, CheckResult]) -> Status:
    statuses = {
        results[check_id].status if check_id in results else Status.NOT_COLLECTED for check_id in control.checks
    }
    return next(status for status in STATUS_SEVERITY if status in statuses)


def table_cell(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def render_report(
    pack_id: str,
    controls: list[Control],
    results: list[CheckResult],
    evidence_files: dict[str, str],
    hashes: dict[str, str],
    metadata: dict[str, str],
) -> str:
    env = Environment(
        loader=PackageLoader("evidencekit"),
        undefined=StrictUndefined,
        keep_trailing_newline=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["cell"] = table_cell
    by_id = {result.check_id: result for result in results}
    return env.get_template(TEMPLATE).render(
        pack_id=pack_id,
        metadata=metadata,
        controls=controls,
        statuses={control.id: control_status(control, by_id) for control in controls},
        results=by_id,
        evidence_files=evidence_files,
        hashes=hashes,
    )
