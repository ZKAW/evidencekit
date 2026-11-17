import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from importlib.metadata import version
from pathlib import Path
from typing import Any

from evidencekit.catalogue import Control
from evidencekit.model import CheckResult
from evidencekit.report import render_report

TIMESTAMP_FORMAT = "%Y%m%dT%H%M%SZ"
CHECKS_DIR = "checks"
REPORT_FILE = "report.md"
MANIFEST_FILE = "manifest.json"
MANIFEST_DIGEST_FILE = "manifest.sha256"
MANIFEST_SCHEMA = 1
HASH_CHUNK_BYTES = 64 * 1024


@dataclass(frozen=True)
class Pack:
    path: Path
    manifest_sha256: str


def write_pack(
    out_dir: Path,
    controls: list[Control],
    results: list[CheckResult],
    collected_at: datetime,
    scope: dict[str, str],
) -> Pack:
    pack_id = collected_at.strftime(TIMESTAMP_FORMAT)
    pack_dir = out_dir / pack_id
    (pack_dir / CHECKS_DIR).mkdir(parents=True)
    metadata = {
        "collected_at": collected_at.isoformat(),
        "tool": f"evidencekit {version('evidencekit')}",
        **scope,
    }
    evidence_files = {result.check_id: f"{CHECKS_DIR}/{result.check_id}.json" for result in results}
    hashes = {}
    for result in results:
        path = evidence_files[result.check_id]
        hashes[path] = _write(pack_dir / path, to_json(result.to_dict()))
    report = render_report(pack_id, controls, results, evidence_files, hashes, metadata)
    hashes[REPORT_FILE] = _write(pack_dir / REPORT_FILE, report)
    manifest = {"schema": MANIFEST_SCHEMA, **metadata, "files": hashes}
    manifest_sha256 = _write(pack_dir / MANIFEST_FILE, to_json(manifest))
    (pack_dir / MANIFEST_DIGEST_FILE).write_text(f"{manifest_sha256}  {MANIFEST_FILE}\n")
    return Pack(pack_dir, manifest_sha256)


def to_json(data: dict[str, Any]) -> str:
    return json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _write(path: Path, text: str) -> str:
    data = text.encode()
    path.write_bytes(data)
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        while chunk := file.read(HASH_CHUNK_BYTES):
            digest.update(chunk)
    return digest.hexdigest()


def verify_pack(pack_dir: Path, expected_manifest_sha256: str | None = None) -> list[str]:
    manifest_path = pack_dir / MANIFEST_FILE
    if not manifest_path.is_file():
        return [f"{MANIFEST_FILE} is missing"]
    problems = _manifest_problems(pack_dir, sha256_file(manifest_path), expected_manifest_sha256)
    listed = _listed_files(manifest_path)
    if listed is None:
        return [*problems, f"{MANIFEST_FILE} is not a valid manifest"]
    return problems + _listed_file_problems(pack_dir, listed) + _unlisted_files(pack_dir, listed)


def _manifest_problems(pack_dir: Path, manifest_sha256: str, expected: str | None) -> list[str]:
    problems = []
    digest_path = pack_dir / MANIFEST_DIGEST_FILE
    if not digest_path.is_file():
        problems.append(f"{MANIFEST_DIGEST_FILE} is missing")
    elif digest_path.read_text().split()[:1] != [manifest_sha256]:
        problems.append(f"{MANIFEST_FILE} does not match {MANIFEST_DIGEST_FILE}")
    if expected and expected.lower() != manifest_sha256:
        problems.append(f"{MANIFEST_FILE} does not match the expected SHA-256 {expected}")
    return problems


def _listed_files(manifest_path: Path) -> dict[str, str] | None:
    try:
        files = json.loads(manifest_path.read_bytes()).get("files")
    except (json.JSONDecodeError, AttributeError):
        return None
    return files if isinstance(files, dict) else None


def _listed_file_problems(pack_dir: Path, listed: dict[str, str]) -> list[str]:
    root = pack_dir.resolve()
    problems = []
    for relative, digest in sorted(listed.items()):
        path = (pack_dir / relative).resolve()
        if not path.is_relative_to(root):
            problems.append(f"{relative}: path points outside the pack")
        elif not path.is_file():
            problems.append(f"{relative}: missing")
        elif sha256_file(path) != digest:
            problems.append(f"{relative}: modified (SHA-256 mismatch)")
    return problems


def _unlisted_files(pack_dir: Path, listed: dict[str, str]) -> list[str]:
    expected = {*listed, MANIFEST_FILE, MANIFEST_DIGEST_FILE}
    return [
        f"{relative}: not listed in the manifest"
        for relative in sorted(path.relative_to(pack_dir).as_posix() for path in pack_dir.rglob("*") if path.is_file())
        if relative not in expected
    ]
