from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class Status(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"
    NOT_COLLECTED = "not collected"


class Provider(StrEnum):
    AWS = "aws"
    GITHUB = "github"


@dataclass(frozen=True)
class Outcome:
    status: Status
    summary: str
    evidence: dict[str, Any]


@dataclass(frozen=True)
class Check:
    id: str
    title: str
    provider: Provider
    run: Callable[[Any], Outcome]


@dataclass(frozen=True)
class CheckResult:
    check_id: str
    title: str
    provider: Provider
    status: Status
    summary: str
    evidence: dict[str, Any]
    collected_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "provider": self.provider.value,
            "status": self.status.value,
            "summary": self.summary,
            "collected_at": self.collected_at,
            "evidence": self.evidence,
        }


def outcome_for(resources: list[dict[str, Any]], compliant_key: str, subject: str) -> Outcome:
    failing = [resource for resource in resources if not resource[compliant_key]]
    status = Status.FAIL if failing else Status.PASS
    return Outcome(status, f"{len(failing)} of {len(resources)} {subject}", {"resources": resources})
