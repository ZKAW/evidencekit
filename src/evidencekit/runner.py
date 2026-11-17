from collections.abc import Iterable
from datetime import UTC, datetime

from evidencekit.model import Check, CheckResult, Outcome, Status


def run_checks(checks: Iterable[Check], context: object) -> list[CheckResult]:
    return [run_check(check, context) for check in checks]


def run_check(check: Check, context: object) -> CheckResult:
    try:
        outcome = check.run(context)
    except Exception as error:
        outcome = Outcome(Status.ERROR, f"{type(error).__name__}: {error}", {})
    return CheckResult(
        check_id=check.id,
        title=check.title,
        provider=check.provider,
        status=outcome.status,
        summary=outcome.summary,
        evidence=outcome.evidence,
        collected_at=datetime.now(UTC).isoformat(timespec="seconds"),
    )
