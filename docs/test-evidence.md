# Test evidence

Two independent test layers back this project:

* **Offline suite** — deterministic, no AWS calls, runs anywhere.
* **Live suite** — read-only against a real AWS account, opt-in.

Both write machine-readable results to `reports/test_results.json`.

## How to reproduce

```bash
# Offline: fixtures + unit tests (no AWS credentials needed)
python -m src.cli test-fixtures          # 8 scenarios
python -m pytest tests/ -v               # 49 unit tests

# Live: read-only against your account (opt-in)
python -m src.cli --profile <name> identity
python -m src.cli --profile <name> test-live --enable-live-tests --regions ap-south-1,us-east-1
```

## Offline scenarios (fixtures)

Synthetic AWS responses live in `examples/fixtures/`. Each scenario asserts the
*interpretation*, not just that code runs.

| ID | Scenario | What it proves |
|---|---|---|
| A | AI model catalogue | Catalogue entries (incl. system-defined inference profiles) are `UNKNOWN`, never organizational usage; application-created profiles remain account resources |
| D | Application-level AI association | Lambda with AI-looking config → `POTENTIAL_AI_USAGE` via `static_configuration_association`, never confirmed; plain Lambda absent |
| E | Ownership & governance metadata | Tags populate purpose/owner fields; 7 documented-info fields flagged missing |
| F | Negative control | Not `CONFIRMED` without invocation evidence |
| G | Missing permissions | `access_denied` recorded per operation, scan continues, coverage reflects the block (Bedrock blocked, SageMaker still returned) |
| H | Duplicate/failed/historical events | Duplicate CloudTrail deliveries deduped; failed-only invoke → `CONFIRMED_AI_ACTIVITY` + `configured_but_unverified`; >90-day-old event dropped; creator captured from management event |
| I | Multi-Region & pagination | Two Regions scanned; all pages collected; 32 unique ids, no collisions |
| J | Empty environment | Zero records, zero errors, schema valid |

Result: **8 passed, 0 failed, 0 skipped**.

## Unit tests (`tests/`)

| File | Focus |
|---|---|
| `test_registry.py` | Stable IDs, provenance, merge semantics (fresh wins; evidenced activity never demoted), missing fields, counter refresh after merge |
| `test_classification.py` | Category selection, event matching, staleness, dedupe |
| `test_adapters.py` | Catalogue/account split, pagination, Lambda association key-names-only, tag adapter dedup, access-denied partial results |
| `test_cloudtrail.py` | Parsing, metadata-only sanitisation, window filter, dedupe, summaries |
| `test_pipeline.py` | End-to-end offline scan, schema validity, activity-vs-existence, governance gaps, report artifacts, CLI commands, merged-scan artifact consistency |

Result: **49 passed**.

## Live test cases (read-only)

Run against account `393849326645` (profile `truvan-poc`), Regions
`ap-south-1` + `us-east-1`:

| ID | Case | Result |
|---|---|---|
| LIVE-IDENT | STS `GetCallerIdentity` | **pass** — account `393849326645`, caller ARN returned |
| LIVE-A | Real Bedrock catalogue | **pass** — 131 catalogue records, 0 wrongly active, 0 errors |
| LIVE-D | Lambda AI association | **pass** — read-only; no false confirmations |
| LIVE-F | Negative control | **pass** — 0 confirmed of 351 records with no invocation data events |
| LIVE-G | Permission/error visibility | **pass** — errors surfaced, not hidden |
| LIVE-I | Multi-Region coverage | **pass** — 351 records, all unique ids, both Regions scanned |
| LIVE-B | Actual Bedrock inference | **skipped** — `--enable-model-invocation` not passed (cost/consent gate) |
| LIVE-C | SageMaker test resource | **skipped** — automatic resource creation prohibited by safety rules; covered offline |
| LIVE-E | Tag mutation on a resource | **skipped** — write operation; offline scenario E validates read-only tag ingestion |

Result: **6 passed, 0 failed, 3 skipped**.

## What is *not* claimed

* Live results depend on the account/Region at scan time and are not reproducible
  from fixtures (documented per live scenario).
* Skipped cases are skipped for cost/safety reasons; their logic is validated
  offline, but no live write was performed.
* `CONFIRMED_AI_ACTIVITY` requires operator-enabled CloudTrail data events;
  without them, the live suite correctly reports zero confirmations and the
  negative control passes.

## Artifacts produced by a full run

```
reports/
├── inventory.json            # schema-validated registry
├── inventory.csv             # flat triage view
├── summary.json              # counts, coverage
├── scan_errors.json          # denied/unsupported ops
├── governance_gaps.json      # missing documented-information
├── evidence/cloudtrail-events.json   # sanitised, metadata-only
├── report.md                 # human-readable report
├── schema_validation.json
└── test_results.json         # offline + live results
```
