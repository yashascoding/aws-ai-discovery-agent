# AWS AI Discovery Agent & AI System Registry (POC)

A read-only AWS agent that discovers AI-related resources and **evidenced AI
activity**, classifies each finding by *strength of evidence*, produces a stable
AI-system registry, and reports the governance documentation gaps an
ISO/IEC 42001-oriented AI management system needs to close.

It is built to be **honest**: catalogue availability is never reported as usage;
absent CloudTrail evidence is never reported as proof of non-use; denied
permissions are surfaced, not hidden.

> This tool supports AI inventory/governance activities relevant to ISO/IEC
> 42001. It **does not** assert compliance or certification. ISO/IEC 42001 does
> not prescribe a registry schema.

## Highlights

- **Evidence-tiered classification** — `CONFIRMED_AI_ACTIVITY` >
  `CONFIGURED_AI_RESOURCE` > `POTENTIAL_AI_USAGE` > `INACTIVE_OR_STALE` >
  `UNKNOWN`, each with explicit reasons and limitations.
- **Catalogue vs account resources** — Bedrock foundation models and AWS-managed
  (system-defined) inference profiles are catalogue entries (`UNKNOWN`); only
  real account resources enter the organizational inventory.
- **Activity evidence** — windowed, deduplicated, metadata-only CloudTrail
  `LookupEvents`; invocation vs management events; prompt/output bodies never
  stored.
- **Stable registry** — deterministic record ids (`air-<hash>`) so governance
  metadata survives rescans; merge lets the fresh classification win without
  losing historically-evidenced activity.
- **ISO 42001-oriented gap mapping** — per-record missing documented-information
  fields with clause references.
- **Read-only by construction** — no create/modify/tag/delete code paths; the
  only mutating-capable action (model invocation) is gated behind a cost flag.
- **Fully testable offline** — 8 fixture scenarios + 44 unit tests with no AWS
  account, plus an opt-in live read-only suite.

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# No AWS needed:
python -m src.cli test-fixtures      # offline scenario suite (8)
python -m pytest tests/ -q           # unit tests (44)

# Read-only against your account:
python -m src.cli --profile <name> identity
python -m src.cli --profile <name> scan --regions ap-south-1 --activity-days 30
python -m src.cli validate --report-dir reports
python -m src.cli report   --report-dir reports
```

## Commands

| Command | Purpose |
|---|---|
| `identity` | Verify AWS identity via STS `GetCallerIdentity`. |
| `scan` | Read-only AI resource discovery (`--regions`, `--activity-days`, `--services`, `--no-merge`, `--skip-activity`). |
| `validate` | Validate `inventory.json` against the JSON schema. |
| `report` | Generate the Markdown report from an existing inventory. |
| `test-fixtures` | Deterministic offline scenario suite (no AWS). |
| `test-live` | Opt-in live read-only tests (`--enable-live-tests`; model invocation further gated). |

## What it discovers

| Adapter | Services / operations |
|---|---|
| `bedrock` | Foundation-model catalogue, inference profiles, provisioned throughputs, custom models, guardrails, agents, agent aliases, knowledge bases, prompts, flows |
| `sagemaker` | Models, endpoints, endpoint configs, training/processing jobs, pipelines, model packages, inference components, experiments |
| `glue` | ML transforms (list ids + bounded detail) |
| `application` | Lambda functions with static AI-association indicators |
| `tags` | `AI-System`-tagged non-AI-native resources (via Resource Groups Tagging API) |
| `evidence` | CloudTrail `LookupEvents` (windowed, sanitised) |

## Output artifacts

Written to `--report-dir` (default `reports/`, git-ignored):

`inventory.json` · `inventory.csv` · `summary.json` · `scan_errors.json` ·
`governance_gaps.json` · `evidence/cloudtrail-events.json` · `report.md` ·
`test_results.json`

## Documentation

- [`docs/architecture.md`](docs/architecture.md) — data flow, module map, classification model, safety.
- [`docs/iso42001.md`](docs/iso42001.md) — field → AIMS documented-information mapping.
- [`docs/iam.md`](docs/iam.md) — least-privilege policy and required actions.
- [`docs/limitations.md`](docs/limitations.md) — what a read-only scan cannot prove.
- [`docs/test-evidence.md`](docs/test-evidence.md) — offline + live test matrix.
- [`docs/demo.md`](docs/demo.md) — 5-minute walkthrough.
- [`examples/iam/ai-discovery-readonly-policy.json`](examples/iam/ai-discovery-readonly-policy.json) — ready-to-use read-only policy.

## Safety

- Read-only default; no resource creation, mutation or deletion.
- No secrets, prompt bodies, model outputs or request payloads are ever printed
  or stored; CloudTrail events are reduced to an allow-list of metadata.
- Lambda AI association records matching environment-variable **names**, never
  values.
- Live tests that would require writes (create endpoint/resource, mutate tag) are
  documented and skipped; their logic is validated offline.

## Requirements

- Python 3.11+ (developed on 3.12), `boto3`/`botocore`, `jsonschema`, `pytest`,
  `botocore[crt]` for SSO/login credential providers. See `requirements.txt`.
