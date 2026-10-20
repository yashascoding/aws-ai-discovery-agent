# Demo walkthrough

A 5-minute tour that shows the tool doing something honest and non-trivial:
discovering AI resources, deciding what is *actually* AI usage, and reporting the
governance gaps a human must close.

## 0. Setup

```bash
cd ~/aws-governance-poc
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## 1. Prove nothing is hidden: run the whole suite offline

```bash
python -m src.cli test-fixtures     # 8/8 scenarios, no AWS needed
python -m pytest tests/ -q          # 44 unit tests
```

This is the credibility move: the interesting logic (classification, dedupe,
staleness, denied-permission handling) is tested **without** touching AWS.

## 2. Verify identity (read-only)

```bash
python -m src.cli --profile <your-profile> identity
```

```
Account ID    : 393849326645
Caller ARN    : arn:aws:iam::…
Region        : ap-south-1
Creds source  : login
```

## 3. Run a read-only scan

```bash
python -m src.cli --profile <your-profile> scan \
    --regions ap-south-1 --activity-days 30
```

```
Records: 131  Resources: 131  Errors: 0
Classifications: {"UNKNOWN": 131}
Schema valid: yes
```

### What just happened (the interesting part)

The account has **131 catalogue entries** (Bedrock foundation models and
AWS-managed inference profiles) and **zero account-owned AI resources, zero
evidenced AI activity** in the window. The tool refuses to dress availability up
as usage:

* foundation models → `catalog` / `UNKNOWN`
* AWS-managed inference profiles → `catalog` / `UNKNOWN` (detected via
  `SYSTEM_DEFINED` / `apac.`·`global.`·`us.`… prefixes)
* no `CONFIRMED_AI_ACTIVITY` because no invocation data events exist

This is the answer a governance tool *should* give here: "you are using AWS AI
services, but I see no deployed, evidenced AI systems — here is what I could and
could not see."

## 4. Show the classification is evidence-driven, not naive

Inspect `reports/inventory.json`:

```json
{
  "resource_kind": "catalog",
  "classification": "UNKNOWN",
  "usage_status": "unknown",
  "classification_reasons": ["Catalogue entry … availability, not … usage"],
  "evidence_limitations": ["Catalogue presence must not be read as … usage"]
}
```

Every record carries its reasons and its limitations. Flip to the offline
scenario H artifact (`reports/offline/scenario_H_inventory.json`) to see a
*genuine* confirmation:

```json
{
  "classification": "CONFIRMED_AI_ACTIVITY",
  "usage_status": "confirmed",
  "cloudtrail_event_ids": ["ev-synth-…"],
  "evidence_limitations": ["Absence of CloudTrail events does not prove non-use …"]
}
```

The same code produces "catalogue, unknown" for availability and "confirmed" for
a matched, successful invocation.

## 5. Validate + report

```bash
python -m src.cli validate --report-dir reports
python -m src.cli report   --report-dir reports
```

`reports/report.md` opens with the discovery summary, the classification table,
the governance gap table and — always — the scope/limitations section:

> This report supports AI inventory/governance activities relevant to ISO/IEC
> 42001 but does not assert compliance or certification.

## 6. Live test suite (read-only)

```bash
python -m src.cli --profile <your-profile> test-live \
    --enable-live-tests --regions ap-south-1,us-east-1
```

```
Live suite: 6 passed, 0 failed, 3 skipped
  [PASS] Live STS identity verification
  [PASS] Live AI model catalogue: catalog_records=131, wrongly_active=0
  [PASS] Live negative control: confirmed=0 of 351 records
  [SKIP] Actual Bedrock inference: --enable-model-invocation not passed (cost/consent gate)
  [SKIP] SageMaker test resource: resource creation prohibited
  [SKIP] Ownership tags on a test resource (mutation): write operation
```

The skips are a feature: the tool refuses to spend money or mutate the account
without explicit, separate consent.

## 7. The one-slide pitch

> "An AI governance inventory is only as good as its honesty. This agent finds
> AI resources across Bedrock, SageMaker, Glue and lambda/tags; it separates
> *availability* from *configuration* from *evidenced activity*; it never claims
> usage it cannot prove; it degrades gracefully on denied permissions; it is
> read-only by construction; and it maps the result to the documented-information
> gaps an ISO/IEC 42001 AIMS needs — without claiming compliance."

## Where to look next

* `docs/architecture.md` — data flow, module boundaries, classification model.
* `docs/iso42001.md` — field → AIMS documented-information mapping.
* `docs/iam.md` — exact least-privilege policy.
* `docs/limitations.md` — everything this tool cannot see.
* `docs/test-evidence.md` — offline + live test matrix.
