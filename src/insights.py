"""Post-discovery enrichment: capability status, usage, cost, and findings."""
from __future__ import annotations

from typing import Any

from .capabilities import (
    ServiceCapability,
    build_capability_registry,
    finalize_capabilities,
)
from .config import ScanConfig, utcnow
from .costs import CostRecord, CostCollectionResult, collect_costs
from .errors import get_logger
from .findings import Finding, generate_findings
from .registry import RegistryRecord
from .usage import UsageCollectionResult, UsageMeasurement, collect_usage

logger = get_logger(__name__)


def enrich_scan(result, session, config: ScanConfig) -> None:
    """Mutate a ScanResult with capability, usage, cost, and finding evidence."""
    capabilities = build_capability_registry()
    _apply_discovery_outcomes(capabilities, result)
    _apply_collection_toggles(capabilities, config)

    records: list[RegistryRecord] = result.registry.records
    usage_result = UsageCollectionResult(
        status="not_configured" if not config.enable_usage_collection else "collection_failed",
        reason="Usage collection was not attempted." if config.enable_usage_collection else
        "Usage collection disabled by configuration (ENABLE_USAGE_COLLECTION=false).",
    )
    if config.enable_usage_collection:
        merged: dict[str, UsageMeasurement] = {}
        statuses = []
        for region in result.regions_scanned:
            partial = collect_usage(session, region, records, capabilities, config, result.errors)
            for measurement in partial.measurements:
                merged.setdefault(measurement.measurement_id, measurement)
            statuses.append((partial.status, partial.reason))
            usage_result.namespaces_attempted.extend(
                ns for ns in partial.namespaces_attempted if ns not in usage_result.namespaces_attempted
            )
            usage_result.namespaces_succeeded.extend(
                ns for ns in partial.namespaces_succeeded if ns not in usage_result.namespaces_succeeded
            )
            usage_result.metrics_examined += partial.metrics_examined
        usage_result.measurements = list(merged.values())
        if statuses:
            usage_result.status = _combine_status([s[0] for s in statuses])
            reasons = [r for s, r in statuses if r]
            usage_result.reason = "; ".join(dict.fromkeys(reasons)) or None
        _mark_usage_capabilities(capabilities, usage_result)
    result.usage_collection = usage_result
    result.usage_measurements = usage_result.measurements

    cost_result = collect_costs(session, config, capabilities, records, result.errors)
    if not config.enable_cost_collection:
        for cap in capabilities:
            if cap.cost_service_names:
                cap.billing_status = "not_configured"
                cap.status_reason = cost_result.reason
    else:
        _mark_cost_capabilities(capabilities, cost_result)
    result.cost_collection = cost_result
    result.cost_records = cost_result.records

    capability_dicts = finalize_capabilities(
        capabilities,
        records=records,
        usage_measurements=result.usage_measurements,
        cost_records=result.cost_records,
        observed_at=utcnow().isoformat(),
    )
    result.capabilities = capability_dicts

    _attach_measurements(records, result.usage_measurements, result.cost_records)
    findings: list[Finding] = generate_findings(
        records=records,
        usage_measurements=result.usage_measurements,
        cost_records=result.cost_records,
        capabilities=capabilities,
        config=config,
    )
    result.findings = findings


def _combine_status(statuses: list[str]) -> str:
    if not statuses:
        return "not_configured"
    if all(s == "collected" for s in statuses):
        return "collected"
    if any(s == "collected" for s in statuses):
        return "partial"
    for preferred in ("permission_denied", "collection_failed", "unsupported", "not_configured"):
        if preferred in statuses:
            return preferred
    return "partial"


def _apply_discovery_outcomes(capabilities: list[ServiceCapability], result) -> None:
    outcomes = getattr(result, "adapter_outcomes", {}) or {}
    for cap in capabilities:
        if not cap.adapter:
            continue
        outcome = outcomes.get(cap.adapter) or {}
        if not outcome.get("attempted"):
            cap.discovery_status = "not_configured"
            cap.status_reason = "Adapter was not selected for this scan."
            continue
        succeeded = bool(outcome.get("succeeded"))
        errors = outcome.get("errors") or []
        error_types = {e.get("error_type") for e in errors if isinstance(e, dict)}
        if succeeded and errors:
            if cap.discovery_status not in {"partial", "unsupported"}:
                cap.discovery_status = "partial"
            cap.status_reason = (
                "Discovery succeeded in at least one Region but some operations failed: "
                + ", ".join(sorted({str(e.get('operation')) for e in errors if isinstance(e, dict)}))
            )
        elif succeeded:
            if cap.discovery_status not in {"partial", "unsupported"}:
                cap.discovery_status = "supported"
            cap.status_reason = "Discovery operations succeeded."
        elif error_types & {"access_denied", "permission_denied"}:
            cap.discovery_status = "permission_denied"
            cap.status_reason = "Discovery was denied by IAM."
        elif error_types & {"not_configured"}:
            cap.discovery_status = "not_configured"
            cap.status_reason = "The service is not enabled/subscribed for this account."
        elif error_types & {"not_available"}:
            cap.discovery_status = "not_configured"
            cap.status_reason = "The service endpoint is not available in the scanned Region."
        elif cap.discovery_status != "unsupported":
            cap.discovery_status = "collection_failed"
            cap.status_reason = "Discovery failed; see scan errors."


def _apply_collection_toggles(capabilities: list[ServiceCapability], config: ScanConfig) -> None:
    if not config.enable_usage_collection:
        for cap in capabilities:
            if cap.collect_usage and cap.usage_namespaces:
                cap.usage_status = "not_configured"
                cap.status_reason = "Usage collection disabled by configuration."
    if not config.enable_cost_collection:
        for cap in capabilities:
            if cap.cost_service_names:
                cap.billing_status = "not_configured"


def _mark_usage_capabilities(capabilities: list[ServiceCapability], usage: UsageCollectionResult) -> None:
    if usage.status in {"collected", "partial"}:
        return
    for cap in capabilities:
        if not cap.collect_usage or not cap.usage_namespaces:
            continue
        if usage.status == "permission_denied":
            cap.usage_status = "permission_denied"
        elif usage.status == "collection_failed":
            cap.usage_status = "collection_failed"
        elif usage.status in {"unsupported", "not_configured"}:
            cap.usage_status = usage.status
        if usage.reason:
            cap.status_reason = usage.reason


def _mark_cost_capabilities(capabilities: list[ServiceCapability], cost: CostCollectionResult) -> None:
    if cost.status == "collected":
        return
    for cap in capabilities:
        if not cap.cost_service_names:
            continue
        if cost.status == "partial":
            # Some source succeeded; finalize still reports mapped amounts.
            continue
        if cost.status == "permission_denied":
            cap.billing_status = "permission_denied"
        elif cost.status == "collection_failed":
            cap.billing_status = "collection_failed"
        elif cost.status in {"unsupported", "not_configured"}:
            cap.billing_status = cost.status
        if cost.reason:
            cap.status_reason = cost.reason


def _attach_measurements(
    records: list[RegistryRecord],
    measurements: list[UsageMeasurement],
    costs: list[CostRecord],
) -> None:
    by_id = {r.record_id: r for r in records}
    for measurement in measurements:
        if measurement.resource_record_id and measurement.resource_record_id in by_id:
            record = by_id[measurement.resource_record_id]
            record.usage_measurements.append(measurement.as_dict())
    for cost in costs:
        if cost.resource_record_id and cost.resource_record_id in by_id:
            record = by_id[cost.resource_record_id]
            record.cost_records.append(cost.as_dict())
