# evidencekit

## Description

Collects audit evidence for ISO 27001 Annex A and HDS controls from AWS (IAM, S3, CloudTrail, KMS) and GitHub (2FA, branch protection, secret scanning, Dependabot).

Each check stores the raw API data it relied on. A run produces a timestamped evidence pack where every file is hashed with SHA-256, and `verify` reports any file changed, added or removed afterwards.

The control-to-check mapping is in `src/evidencekit/catalogue.yaml`.

## Setup

Requires Python 3.13 and [uv](https://docs.astral.sh/uv/).

```bash
uv sync
```

AWS credentials come from the standard boto3 chain and need read-only access to IAM, S3, CloudTrail and KMS. GitHub checks use `GITHUB_TOKEN`; the 2FA and security settings are only visible to an organization owner or repository admin.

## Run

```bash
uv run evidencekit controls
uv run evidencekit collect --aws --github-org acme --out evidence/
uv run evidencekit verify evidence/<timestamp>/ --expected-manifest-sha256 <hash>
```

Keep the manifest hash printed by `collect` outside the pack (a ticket, an email to the auditor): anyone who can write to the pack can also recompute its hashes.

With Docker:

```bash
docker build -t evidencekit .
docker run --rm -e AWS_PROFILE -e AWS_DEFAULT_REGION -v ~/.aws:/home/evidencekit/.aws:ro \
  -v "$PWD/evidence:/home/evidencekit/evidence" evidencekit collect --aws
```

Tests:

```bash
uv run pytest
./scripts/smoke.sh
```
