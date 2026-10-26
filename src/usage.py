"""CloudWatch usage measurement for discovered AI resources.

Design rules
------------
* Only read CloudWatch metadata and datapoints; no log bodies or payloads.
* A missing metric/datapoint is recorded as ``no_datapoints`` or an explicit
  collection failure, never as a measured zero.
* Measurements can be resource-scoped (when a dimension matches a registry
  record) or service-scoped. Service-scoped data is never attributed to a
  specific resource.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from botocore.exceptions import BotoCoreError, ClientError

from .capabilities import ServiceCapability
from .config import ScanConfig, utcnow
from .errors import OperationError, classify_exception, error_message, get_logger, with_retry
from .registry import RegistryRecord

logger = get_logger(__name__)

COUNT_METRICS = {
    "invocations", "invocationcount", "requests", "requestcount", "errors", "throttles",
    "count", "calls", "documentsprocessed", "pagesprocessed", "charactersprocessed",
    "audio", "video", "transactions", "units", "messages", "tokens", "inputtokens",
    "outputtokens", "usage", "processedbytes", "bytes", "records",
}
PAID_RUNTIME_RESOURCE_TYPES = {
    "sagemaker_endpoint", "bedrock_provisioned_throughput", "bedrock_inference_profile",
    "ec2_instance", "eks_cluster", "ecs_service",
}
MAX_NAMESPACES = 30
MAX_METRICS_PER_NAMESPACE = 25
MAX_DIMENSION_CANDIDATES = 5000


@dataclass
class UsageMeasurement:
    measurement_id: str
    source: str
    service: str
    capability_keys: list[str] = field(default_factory=list)
    namespace: str | None = None
    metric_name: str | None = None
    statistic: str | None = None
    period_seconds: int | None = None
    unit: str | None = None
    dimensions: dict[str, str] = field(default_factory=dict)
    scope: str = "service"
    resource_record_id: str | None = None
    resource_id: str | None = None
    start_time: str | None = None
    end_time: str | None = None
    datapoint_count: int = 0
    total: float | None = None
    average: float | None = None
    minimum: float | None = None
    maximum: float | None = None
    latest_value: float | None = None
    latest_timestamp: str | None = None
    points: list[dict[str, Any]] = field(default_factory=list)
    attribution_confidence: str = "service_level"
    collection_status: str = "collected"
    limitation: str | None = None
    observed_at: str = field(default_factory=lambda: utcnow().isoformat())

    def as_dict(self) -> dict[str, Any]:
        return {
            "measurement_id": self.measurement_id,
            "source": self.source,
            "service": self.service,
            "capability_keys": self.capability_keys,
            "namespace": self.namespace,
            "metric_name": self.metric_name,
            "statistic": self.statistic,
            "period_seconds": self.period_seconds,
            "unit": self.unit,
            "dimensions": self.dimensions,
            "scope": self.scope,
            "resource_record_id": self.resource_record_id,
            "resource_id": self.resource_id,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "datapoint_count": self.datapoint_count,
            "total": self.total,
            "average": self.average,
            "minimum": self.minimum,
            "maximum": self.maximum,
            "latest_value": self.latest_value,
            "latest_timestamp": self.latest_timestamp,
            "points": self.points,
            "attribution_confidence": self.attribution_confidence,
            "collection_status": self.collection_status,
            "limitation": self.limitation,
            "observed_at": self.observed_at,
        }


@dataclass
class UsageCollectionResult:
    measurements: list[UsageMeasurement] = field(default_factory=list)
    status: str = "not_configured"
    reason: str | None = None
    namespaces_attempted: list[str] = field(default_factory=list)
    namespaces_succeeded: list[str] = field(default_factory=list)
    metrics_examined: int = 0
    observed_at: str = field(default_factory=lambda: utcnow().isoformat())


def _mid(*parts: Any) -> str:
    raw = "|".join("" if p is None else str(p) for p in parts)
    return "um-" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _iso(dt: Any) -> str | None:
    return None if dt is None else str(dt)


def _is_count_metric(name: str) -> bool:
    return name.replace("_", "").replace("-", "").lower() in COUNT_METRICS


def _statistic(name: str) -> str:
    return "Sum" if _is_count_metric(name) else "Average"


def _period(config: ScanConfig) -> int:
    days = max(1, config.usage_lookback_days)
    if days <= 2:
        return 300
    if days <= 14:
        return 3600
    if days <= 60:
        return 21600
    return 86400


def _namespace_capabilities(capabilities: Iterable[ServiceCapability]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for cap in capabilities:
        if not cap.collect_usage:
            continue
        for ns in cap.usage_namespaces:
            out.setdefault(ns, [])
            if cap.key not in out[ns]:
                out[ns].append(cap.key)
    return out


def _record_candidates(record: RegistryRecord) -> set[str]:
    values = {
        record.resource_id, record.resource_name, record.resource_arn,
        record.foundation_model_id, record.inference_profile_id,
        record.sagemaker_endpoint_name, record.sagemaker_model_arn,
        record.bedrock_agent_id, record.bedrock_knowledge_base_id,
    }
    values.update(str(v) for v in (record.ai_association or {}).get("indicators", []) if isinstance(v, str))
    return {str(v).strip().lower() for v in values if v}


def _namespace_for_record(record: RegistryRecord, capabilities: list[ServiceCapability]) -> list[str]:
    out = []
    for cap in capabilities:
        if not cap.collect_usage or not cap.usage_namespaces:
            continue
        adapter = cap.adapter or ""
        service = record.aws_service or ""
        if adapter == service or (adapter == "application" and service == "lambda"):
            out.extend(cap.usage_namespaces)
    return list(dict.fromkeys(out))


def _match_records(
    metric: dict[str, Any], records: list[RegistryRecord], capabilities: list[ServiceCapability]
) -> tuple[RegistryRecord | None, dict[str, str], str | None]:
    dims = {d.get("Name"): d.get("Value") for d in metric.get("Dimensions", []) if d.get("Name")}
    candidates: dict[str, RegistryRecord] = {}
    for rec in records:
        if len(candidates) >= MAX_DIMENSION_CANDIDATES:
            break
        for value in _record_candidates(rec):
            candidates.setdefault(value, rec)
    matches = []
    for value in dims.values():
        rec = candidates.get(str(value or "").lower())
        if rec is not None:
            matches.append(rec)
    unique = {r.record_id: r for r in matches}
    if len(unique) == 1:
        rec = next(iter(unique.values()))
        return rec, dims, rec.aws_region
    if len(unique) > 1:
        return None, dims, None
    for rec in records:
        ns = _namespace_for_record(rec, capabilities)
        if metric.get("Namespace") in ns:
            return None, dims, rec.aws_region
    return None, dims, None


def _capability_keys(
    namespace: str,
    record: RegistryRecord | None,
    ns_caps: dict[str, list[str]],
    capabilities: list[ServiceCapability],
) -> list[str]:
    keys = list(ns_caps.get(namespace, []))
    if record is None:
        return keys
    by_key = {c.key: c for c in capabilities}
    preferred = []
    for key in keys:
        cap = by_key.get(key)
        if cap and (cap.adapter == record.aws_service or (cap.adapter == "application" and record.aws_service == "lambda")):
            preferred.append(key)
    return preferred or keys


def _metric_priority(metric: dict[str, Any], candidate_values: set[str]) -> int:
    dims = {str(d.get("Value", "")).lower() for d in metric.get("Dimensions", [])}
    if dims & candidate_values:
        return 0
    if dims:
        return 1
    return 2


def _collect_namespace(
    session,
    region: str,
    namespace: str,
    records: list[RegistryRecord],
    capabilities: list[ServiceCapability],
    ns_caps: dict[str, list[str]],
    config: ScanConfig,
    errors: list[OperationError],
) -> tuple[list[UsageMeasurement], bool]:
    client = session.client("cloudwatch", region_name=region)
    try:
        metrics = with_retry(
            lambda: _list_metrics(client, namespace, config.max_metrics_per_namespace * 2),
            max_retries=config.max_retries,
            base_delay=config.retry_base_delay,
            logger=logger,
            context=f"cloudwatch.ListMetrics:{namespace}",
        )
    except (ClientError, BotoCoreError) as exc:
        errors.append(OperationError(
            service="cloudwatch", operation="ListMetrics", region=region,
            error_type=classify_exception(exc), message=f"{namespace}: {error_message(exc)}",
            scan_id=config.scan_id,
        ))
        return [], False

    candidate_values: set[str] = set()
    for rec in records[:500]:
        candidate_values.update(_record_candidates(rec))
    metrics = sorted(metrics, key=lambda m: _metric_priority(m, candidate_values))[: config.max_metrics_per_namespace]
    if not metrics:
        return [], True

    period = _period(config)
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=max(1, config.usage_lookback_days))
    queries = []
    for idx, metric in enumerate(metrics[:500]):
        queries.append({
            "Id": f"m{idx}",
            "MetricStat": {
                "Metric": {
                    "Namespace": namespace,
                    "MetricName": metric.get("MetricName"),
                    "Dimensions": metric.get("Dimensions", []),
                },
                "Period": period,
                "Stat": _statistic(metric.get("MetricName") or ""),
            },
            "ReturnData": True,
        })
    measurements: list[UsageMeasurement] = []
    for start_idx in range(0, len(queries), 100):
        batch = queries[start_idx:start_idx + 100]
        try:
            response = with_retry(
                lambda: client.get_metric_data(
                    MetricDataQueries=batch,
                    StartTime=start,
                    EndTime=end,
                    ScanBy="TimestampDescending",
                    MaxDatapoints=max(60, config.max_datapoints_per_metric),
                ),
                max_retries=config.max_retries,
                base_delay=config.retry_base_delay,
                logger=logger,
                context=f"cloudwatch.GetMetricData:{namespace}",
            )
        except (ClientError, BotoCoreError) as exc:
            errors.append(OperationError(
                service="cloudwatch", operation="GetMetricData", region=region,
                error_type=classify_exception(exc), message=f"{namespace}: {error_message(exc)}",
                scan_id=config.scan_id,
            ))
            return measurements, False
        by_id = {r.get("Id"): r for r in response.get("MetricDataResults", [])}
        for idx, metric in enumerate(metrics[start_idx:start_idx + len(batch)]):
            raw = by_id.get(f"m{idx}") or {}
            values = [float(v) for v in (raw.get("Values") or []) if v is not None]
            timestamps = [str(t) for t in (raw.get("Timestamps") or [])]
            record, dims, _region_hint = _match_records(metric, records, capabilities)
            status_code = raw.get("StatusCode") or "Complete"
            points = [
                {"timestamp": ts, "value": val}
                for ts, val in zip(timestamps, values)
            ][: config.max_datapoints_per_metric]
            if record is not None:
                scope = "resource"
                confidence = "resource_dimension_match"
            else:
                scope = "service"
                confidence = "service_level"
            status = "collected"
            limitation = None
            if status_code != "Complete":
                status = "partial"
                limitation = f"CloudWatch returned status {status_code}; datapoints may be incomplete."
            if not points:
                status = "no_datapoints"
                limitation = (
                    "CloudWatch returned no datapoints for this metric in the lookback window. "
                    "This is not evidence of zero usage; telemetry may be disabled, delayed, or not published."
                )
            cap_keys = _capability_keys(namespace, record, ns_caps, capabilities)
            measurements.append(UsageMeasurement(
                measurement_id=_mid(region, namespace, metric.get("MetricName"), *sorted(dims.items())),
                source="cloudwatch",
                service=(record.aws_service if record else _service_for_namespace(namespace, capabilities)),
                capability_keys=cap_keys,
                namespace=namespace,
                metric_name=metric.get("MetricName"),
                statistic=_statistic(metric.get("MetricName") or ""),
                period_seconds=period,
                unit=None,
                dimensions=dims,
                scope=scope,
                resource_record_id=(record.record_id if record else None),
                resource_id=(record.resource_id if record else None),
                start_time=_iso(start),
                end_time=_iso(end),
                datapoint_count=len(values),
                total=(round(sum(values), 6) if values else None),
                average=(round(sum(values) / len(values), 6) if values else None),
                minimum=(round(min(values), 6) if values else None),
                maximum=(round(max(values), 6) if values else None),
                latest_value=(values[0] if values else None),
                latest_timestamp=(timestamps[0] if timestamps else None),
                points=points,
                attribution_confidence=confidence,
                collection_status=status,
                limitation=limitation,
            ))
    return measurements, True


def _list_metrics(client, namespace: str, limit: int) -> list[dict[str, Any]]:
    out = []
    kwargs = {"Namespace": namespace}
    for _ in range(10):
        response = client.list_metrics(**kwargs)
        out.extend(response.get("Metrics", []))
        token = response.get("NextToken")
        if not token or len(out) >= limit:
            break
        kwargs["NextToken"] = token
    return out[:limit]


def _service_for_namespace(namespace: str, capabilities: list[ServiceCapability]) -> str:
    for cap in capabilities:
        if namespace in cap.usage_namespaces and cap.adapter:
            return cap.adapter
    return namespace.split("/")[-1].lower()


def collect_usage(
    session,
    region: str,
    records: list[RegistryRecord],
    capabilities: list[ServiceCapability],
    config: ScanConfig,
    errors: list[OperationError],
) -> UsageCollectionResult:
    result = UsageCollectionResult()
    if not config.enable_usage_collection:
        result.reason = "Usage collection disabled by configuration (ENABLE_USAGE_COLLECTION=false)."
        return result
    ns_caps = _namespace_capabilities(capabilities)
    namespaces = [ns for ns in sorted(ns_caps) if ns_caps[ns]][:MAX_NAMESPACES]
    result.namespaces_attempted = namespaces
    if not namespaces:
        result.status = "unsupported"
        result.reason = "No CloudWatch namespaces are mapped to the selected capabilities."
        return result
    attempted_records = records
    for namespace in namespaces:
        measurements, ok = _collect_namespace(
            session, region, namespace, attempted_records, capabilities,
            ns_caps, config, errors,
        )
        result.measurements.extend(measurements)
        result.metrics_examined += len(measurements)
        if ok:
            result.namespaces_succeeded.append(namespace)
    if result.namespaces_succeeded:
        result.status = "collected"
        if len(result.namespaces_succeeded) < len(namespaces):
            result.status = "partial"
            result.reason = "Some CloudWatch namespaces could not be queried; see scan errors."
    else:
        error_types = {e.error_type for e in errors if e.service == "cloudwatch"}
        if error_types & {"access_denied", "permission_denied"}:
            result.status = "permission_denied"
        elif error_types & {"not_configured", "not_available", "unsupported"}:
            result.status = "unsupported"
        else:
            result.status = "collection_failed"
        result.reason = "No CloudWatch namespace query succeeded; see scan errors."
    return result
