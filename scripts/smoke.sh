#!/usr/bin/env bash
set -euo pipefail

port="${MOTO_PORT:-5055}"
export AWS_ENDPOINT_URL="http://127.0.0.1:${port}"
export AWS_ACCESS_KEY_ID=testing AWS_SECRET_ACCESS_KEY=testing AWS_DEFAULT_REGION=eu-west-3
out="$(mktemp -d)"

uv run moto_server -p "${port}" >/dev/null 2>&1 &
server=$!
trap 'kill "${server}"' EXIT
until curl -s -o /dev/null "${AWS_ENDPOINT_URL}"; do sleep 0.2; done

uv run python scripts/seed_fake_aws.py
uv run evidencekit collect --aws --out "${out}"
pack="$(find "${out}" -mindepth 1 -maxdepth 1 -type d)"

echo "--- verify untouched pack"
uv run evidencekit verify "${pack}"

echo "--- flip root_mfa from fail to pass, then verify again"
sed -i 's/"status": "fail"/"status": "pass"/' "${pack}/checks/aws.iam.root_mfa.json"
if uv run evidencekit verify "${pack}"; then
    echo "tampering went undetected" >&2
    exit 1
fi
echo "--- tampering detected"
