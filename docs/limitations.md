# Limitations

This tool is honest about what a read-only scan can and cannot establish. These
limitations are also embedded in machine-readable output
(`evidence_limitations` per record, `report.md` scope section).

## 1. Availability ≠ usage

Bedrock foundation models and AWS-managed (system-defined) inference profiles are
returned by list APIs for *every* account in a Region. They are recorded as
catalogue entries (`resource_kind="catalog"`) and classified `UNKNOWN`. They are
**never** reported as organizational AI usage.

## 2. CloudTrail coverage is not complete

* `cloudtrail:LookupEvents` returns **management events** (and data events only
  if already delivered to Event History). Bedrock model **invocation** and
  SageMaker data-plane events are **data events** and must be enabled by the
  operator, per event type / resource, before this tool can see them.
* Event History is retained for **90 days**. `--activity-days` cannot exceed what
  CloudTrail retains.
* Therefore **absence of invocation events is not proof of non-use.** Every
  non-confirmed record carries this limitation explicitly.

## 3. Classification is evidence-tiered, not ground truth

* `CONFIRMED_AI_ACTIVITY` means a retained invocation event was observed and
  matched — it does not mean the workload is in production or business-critical.
* `CONFIGURED_AI_RESOURCE` means the resource exists — the workload may be under
  development, retired, or unused.
* `POTENTIAL_AI_USAGE` from tags / static configuration is a **human-asserted or
  heuristic claim**, not verified behaviour.
* Matching relies on identifiers (model id, endpoint name, ARN, agent/KB id,
  pipeline/training-job name). Events whose target identifiers are absent or
  opaque may be unmatched; unmatched invocation events are surfaced separately.

## 4. Service and Region coverage

* Discovery covers the 27 adapters in `src/discovery/`. Services that expose no
  listable account resources (for example some runtime-only AI features) remain
  invisible unless they publish CloudWatch metrics or CloudTrail events.
* AI-capable infrastructure is **not** treated as AI by default. EC2/ECS/EKS/
  S3/OpenSearch/Redshift/Aurora/Neptune resources enter the registry only with
  evidence (accelerated instance family, AI name/tag, AI container image, or
  explicit AI association). Ordinary infrastructure stays `UNKNOWN`.
* Container contents, notebook contents, object data, database rows, and
  application payloads are never inspected, so workload purpose cannot be
  inferred from data.
* Not every service is available in every Region; endpoint/opt-in/subscription
  failures are recorded as `not_configured` or `unsupported`, not as
  "no resources".
* Only Regions explicitly passed via `--regions` (or discovered and enabled) are
  scanned.

## 5. Usage telemetry is not a usage census

* CloudWatch collection is intentionally bounded
  (`max_metrics_per_namespace`, `max_datapoints_per_metric`, lookback window).
* `no_datapoints` means no datapoints were returned. It is **not** evidence of
  zero usage; telemetry may be disabled, delayed, not published for that
  resource, or outside the lookback window.
* `partial` means CloudWatch returned `PartialData` or some namespaces failed;
  totals may be incomplete.
* Service-scoped measurements are never attributed to a specific resource.
  Resource attribution requires a matching CloudWatch dimension.
* Metric names and units vary by service; no cross-service unit conversion or
  charge estimation is performed.
* GPU utilization often requires the CloudWatch agent and is not equivalent to
  CPU utilization.

## 6. Reported cost is not an AI allocation

* Cost Explorer cost is reported at service/Region/day granularity and is
  filtered to `RECORD_TYPE=Usage`.
* Totals cover **AI-capable services**, not necessarily AI workloads. For
  example, EC2 spend appears when EC2 is in scope even if no AI EC2 instance was
  discovered.
* Cost is allocated to a resource only when a Cost Explorer grouping or CUR row
  contains a matching billing identifier. Otherwise it stays service-level and
  is surfaced as unattributed.
* Billing data can be delayed or estimated; `estimated` and `data_through` are
  recorded explicitly.
* CUR ingestion is optional and bounded; missing CUR access falls back to Cost
  Explorer and is reported as `partial`, not silently ignored.
* No cost is estimated from names, instance counts, catalogue entries, or
  metric volumes.

## 7. Granularity and identity

* Record IDs are stable across scans but are **derived** (`air-<hash>`); they are
  not AWS resource ids. They are intended to anchor governance metadata, not to
  replace ARNs.
* Some list APIs return summaries without ARNs or timestamps (e.g. Bedrock agents
  and knowledge bases). Where a field is unavailable, the record marks it missing
  rather than inventing it.

## 8. Staleness is a policy, not a fact

`INACTIVE_OR_STALE` uses a 90-day modification-age heuristic
(`STALE_AFTER_DAYS`) combined with the absence of activity evidence. It is a
prioritisation signal for human follow-up, not a determination that a resource
is unused.

## 9. Safety boundaries (by design)

* Model invocation is **not** performed automatically; it requires
  `--enable-model-invocation` and has cost implications.
* No resource is created, modified, tagged or deleted by any command.
* Live tests that would require writes (create endpoint / create resource /
  mutate tag) are **documented and skipped**, not automated.

## 10. Governance mapping is not a compliance claim

`docs/iso42001.md` maps registry fields to the kind of documented information an
AIMS typically needs. ISO/IEC 42001 does not prescribe a schema and this tool
does not assert conformity or certification. Gap output shows **what is
missing**, never that a control is satisfied.

## 11. Not a substitute for organisational process

The tool cannot know which resources are in scope for your AIMS, what an AI
system's intended purpose is, who its accountable owner should be, or what its
risk classification is. It surfaces candidates and gaps for humans to resolve.
