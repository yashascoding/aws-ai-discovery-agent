"""Scan orchestration: adapters -> records -> evidence -> classification.

Ordering per Region:
1. Run discovery adapters (read-only, paginated, error-isolated).
2. Batch-fetch tags for discovered ARNs and merge into resources.
3. Collect CloudTrail activity evidence for the observation window.
4. Build/merge RegistryRecords, then classify with evidence attached.

The scanner never creates, modifies, or deletes AWS resources.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from .aws_identity import IdentityResult, create_session, get_identity
from .classification import classify_all
from .config import ScanConfig, utcnow
from .discovery import ADAPTERS, AdapterResult, DiscoveredResource
from .errors import OperationError, get_logger
from .evidence.cloudtrail import (
    ActivityEvent,
    collect_activity_events,
    filter_window,
    summarize_events,
)
from .region_discovery import RegionCoverage, resolve_scan_regions
from .registry import Registry, RegistryRecord, make_record_id
from .discovery.tagging import collect_tags
from .costs import CostCollectionResult, CostRecord
from .findings import Finding
from .usage import UsageCollectionResult, UsageMeasurement

logger = get_logger(__name__)


@dataclass
class ScanResult:
    config: ScanConfig
    identity: IdentityResult | None = None
    registry: Registry = field(default_factory=Registry)
    errors: list[OperationError] = field(default_factory=list)
    coverage: list[RegionCoverage] = field(default_factory=list)
    events: list[ActivityEvent] = field(default_factory=list)
    services_attempted: list[str] = field(default_factory=list)
    adapter_outcomes: dict[str, dict[str, Any]] = field(default_factory=dict)
    usage_collection: UsageCollectionResult | None = None
    usage_measurements: list[UsageMeasurement] = field(default_factory=list)
    cost_collection: CostCollectionResult | None = None
    cost_records: list[CostRecord] = field(default_factory=list)
    capabilities: list[dict[str, Any]] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    resources_discovered: int = 0
    started_at: str = ""
    finished_at: str = ""
    duration_seconds: float = 0.0
    notes: list[str] = field(default_factory=list)

    @property
    def regions_scanned(self) -> list[str]:
        return [c.region for c in self.coverage if c.status == "scanned"]


# --------------------------------------------------------------------------- #
# DiscoveredResource -> RegistryRecord
# --------------------------------------------------------------------------- #
def build_record(
    resource: DiscoveredResource,
    account_id: str | None,
    scan_id: str,
    region: str,
) -> RegistryRecord:
    record_id = make_record_id(
        account_id, resource.region or region, resource.service,
        resource.resource_type, resource.resource_id,
    )
    now_iso = utcnow().isoformat()
    kind = resource.metadata.get("resource_kind", "account_resource")
    if resource.ai_association:
        kind = "application_association"

    record = RegistryRecord(
        record_id=record_id,
        aws_service=resource.service,
        resource_type=resource.resource_type,
        resource_kind=kind if kind in {"catalog", "account_resource", "application_association"} else "account_resource",
        first_seen_scan=scan_id,
        last_seen_scan=scan_id,
        first_observed=now_iso,
        last_observed=now_iso,
        last_inventory_scan=now_iso,
    )

    source = resource.source_operation or "aws_api_listing"
    record.set_field("resource_name", resource.name, source)
    record.set_field("description", resource.description, source)
    record.set_field("resource_arn", resource.arn, source)
    record.set_field("resource_id", resource.resource_id, source)
    record.set_field("system_status", resource.status, source)
    record.set_field("creation_time", resource.created_time, source)
    record.set_field("last_modified_time", resource.modified_time, source)
    record.set_field("aws_account_id", account_id, "sts.GetCallerIdentity")
    record.set_field("aws_region", resource.region or region, source)
    record.provenance.setdefault(
        "resource_type", {"source": source, "observed_at": now_iso}
    )

    md = resource.metadata
    record.set_field("foundation_model_id", md.get("foundation_model_id"), source)
    record.set_field("model_provider", md.get("model_provider"), source)
    record.set_field("technology_category", _technology_category(resource), source)
    record.set_field("bedrock_agent_id", md.get("bedrock_agent_id"), source)
    record.set_field("bedrock_knowledge_base_id", md.get("bedrock_knowledge_base_id"), source)
    record.set_field("bedrock_guardrail_id", md.get("bedrock_guardrail_id"), source)
    record.set_field("bedrock_flow_id", md.get("flow_id") or md.get("id"), source)
    record.set_field("sagemaker_model_arn", md.get("sagemaker_model_arn"), source)
    record.set_field("sagemaker_endpoint_name", md.get("sagemaker_endpoint_name"), source)
    record.set_field("sagemaker_training_job_name", md.get("sagemaker_training_job_name"), source)
    record.set_field("sagemaker_pipeline_arn", md.get("sagemaker_pipeline_arn"), source)

    # Model naming for catalogue entries.
    if resource.resource_type == "bedrock_foundation_model_catalog_entry":
        record.set_field("model_name_version", resource.name, source)
        record.set_field(
            "lifecycle_stage",
            md.get("model_lifecycle_status"),
            source,
        )

    if resource.ai_association:
        record.ai_association = resource.ai_association

    if resource.tags:
        record.tags = dict(resource.tags)
        _apply_governance_tags(record, resource.tags)

    # Concrete AI resources always have a name-like identifier for the registry.
    if record.resource_name is None:
        record.set_field("resource_name", resource.resource_id, source)
    return record


def _technology_category(resource: DiscoveredResource) -> str:
    mapping = {
        "bedrock_foundation_model_catalog_entry": "foundation_model_catalogue",
        "bedrock_inference_profile": "foundation_model_inference_profile",
        "bedrock_provisioned_throughput": "provisioned_inference",
        "bedrock_custom_model": "custom_model",
        "bedrock_agent": "agentic_system",
        "bedrock_agent_alias": "agentic_system_alias",
        "bedrock_knowledge_base": "retrieval_augmented_generation",
        "bedrock_guardrail": "ai_safety_control",
        "bedrock_prompt": "prompt_asset",
        "bedrock_flow": "orchestration_flow",
        "sagemaker_model": "ml_model",
        "sagemaker_endpoint": "ml_inference_endpoint",
        "sagemaker_endpoint_config": "ml_endpoint_configuration",
        "sagemaker_training_job": "ml_training_job",
        "sagemaker_processing_job": "ml_processing_job",
        "sagemaker_pipeline": "ml_pipeline",
        "sagemaker_model_package": "ml_model_package",
        "sagemaker_inference_component": "ml_inference_component",
        "sagemaker_experiment": "ml_experiment",
        "glue_ml_transform": "ml_transform",
        "lambda_function": "application_integration",
    }
    return mapping.get(resource.resource_type, "ai_ml_resource")


def _apply_governance_tags(record: RegistryRecord, tags: dict[str, str]) -> None:
    """Map governance tags onto registry fields (human-asserted, tagged source)."""
    src = "resource_groups_tagging_api"
    record.set_field("ai_system_name", tags.get("AI-System"), src)
    record.set_field("system_owner", tags.get("AI-System-Owner") or tags.get("Owner"), src)
    record.set_field("technical_owner", tags.get("Owner") if tags.get("AI-System-Owner") else None, src)
    record.set_field("intended_purpose", tags.get("BusinessPurpose"), src)
    record.set_field("data_classification", tags.get("DataClassification"), src)
    record.set_field("human_oversight", tags.get("HumanOversight"), src)
    record.set_field("risk_assessment_status", tags.get("RiskAssessment"), src)
    record.set_field("deployment_environment", tags.get("Environment"), src)
    if tags.get("Owner") and not record.business_owner:
        record.business_owner = tags["Owner"]
        record.provenance["business_owner"] = {"source": src, "observed_at": utcnow().isoformat()}
    record.owner_source = "tag:Owner" if tags.get("Owner") else record.owner_source
    if tags.get("AI-System-Owner"):
        record.owner_source = "tag:AI-System-Owner"


# --------------------------------------------------------------------------- #
# Activity-only records for unmatched invocations
# --------------------------------------------------------------------------- #
def synthesize_activity_records(
    unmatched: list[ActivityEvent], account_id: str | None, scan_id: str
) -> list[RegistryRecord]:
    """Create CONFIRMED records for invocation events with no discovered resource.

    This keeps direct usage evidence even when the underlying resource cannot
    be listed (permission gap, region gap, or data-event-only visibility).
    """
    records: list[RegistryRecord] = []
    grouped: dict[tuple[str, str], list[ActivityEvent]] = {}
    for event in unmatched:
        if not event.is_invocation:
            continue
        target_key = (
            event.target.get("modelId")
            or event.target.get("endpointName")
            or event.target.get("agentId")
            or event.target.get("knowledgeBaseId")
            or "unknown-target"
        )
        grouped.setdefault((event.event_source, target_key), []).append(event)

    for (event_source, target_key), events in grouped.items():
        service = event_source.split(".")[0]
        region = events[0].region
        resource_type = f"{service}_invocation_activity"
        record_id = make_record_id(account_id, region, service, resource_type, target_key)
        record = RegistryRecord(
            record_id=record_id,
            aws_service=service,
            resource_type=resource_type,
            resource_kind="account_resource",
            first_seen_scan=scan_id,
            last_seen_scan=scan_id,
            aws_account_id=account_id,
            aws_region=region,
            resource_id=target_key,
            resource_name=target_key,
        )
        src = "cloudtrail.lookup_events"
        record.set_field("foundation_model_id", target_key if "bedrock" in service else None, src)
        record.set_field("sagemaker_endpoint_name", target_key if "sagemaker" in service else None, src)
        record.provenance["resource_type"] = {"source": src, "observed_at": utcnow().isoformat()}
        records.append(record)
    return records


# --------------------------------------------------------------------------- #
# Main entry
# --------------------------------------------------------------------------- #
def run_scan(
    config: ScanConfig,
    progress: Callable[[str], None] | None = None,
    session_factory: Callable[[ScanConfig], Any] | None = None,
) -> ScanResult:
    """Execute a scan. ``session_factory`` is only used by unit tests."""

    def say(message: str) -> None:
        logger.info(message)
        if progress:
            progress(message)

    result = ScanResult(config=config, started_at=utcnow().isoformat())
    started = time.monotonic()

    session = session_factory(config) if session_factory else create_session(config)
    identity = get_identity(config, session)
    result.identity = identity
    if not identity.success:
        result.errors.append(
            OperationError(
                service="sts",
                operation="GetCallerIdentity",
                region=config.regions[0],
                error_type=identity.error_type or "other",
                message=identity.error or "unknown identity error",
                scan_id=config.scan_id,
            )
        )
        result.finished_at = utcnow().isoformat()
        result.duration_seconds = round(time.monotonic() - started, 3)
        say("Identity verification failed; aborting scan.")
        return result
    say(f"Identity OK: account {identity.account_id} ({identity.caller_arn})")

    regions, region_errors, not_enabled = resolve_scan_regions(session, config)
    result.errors.extend(region_errors)
    result.errors.extend(not_enabled)
    say(f"Regions to scan: {', '.join(regions)}")

    adapters = ADAPTERS.build(config, config.services)
    for adapter in adapters:
        result.services_attempted.extend(
            f"{client}.{op}" for client, op in adapter.api_operations()
        )
    say(f"Adapters: {', '.join(a.name for a in adapters)}")

    for region in regions:
        coverage = RegionCoverage(region=region, status="scanned")
        say(f"Scanning region {region} ...")
        region_resources: list[DiscoveredResource] = []
        any_success = False

        for adapter in adapters:
            if not adapter.supports_region(region):
                coverage.notes.append(
                    f"{adapter.name}: not supported in {region} (skipped)"
                )
                continue
            coverage.services_attempted.append(adapter.name)
            outcome = result.adapter_outcomes.setdefault(
                adapter.name,
                {"service": adapter.service, "attempted": True, "succeeded": False,
                 "regions": [], "operations_succeeded": [], "errors": []},
            )
            outcome["regions"].append(region)
            try:
                adapter_result: AdapterResult = adapter.discover(session, region)
            except Exception as exc:  # noqa: BLE001 - adapter must not kill the scan
                result.errors.append(
                    OperationError(
                        service=adapter.service,
                        operation="discover",
                        region=region,
                        error_type="adapter_crash",
                        message=f"{type(exc).__name__}: {exc}",
                        scan_id=config.scan_id,
                    )
                )
                coverage.services_failed.append(adapter.name)
                outcome["errors"].append({
                    "service": adapter.service, "operation": "discover", "region": region,
                    "error_type": "adapter_crash", "message": f"{type(exc).__name__}: {exc}",
                })
                continue
            region_resources.extend(adapter_result.resources)
            result.errors.extend(adapter_result.errors)
            result.notes.extend(adapter_result.notes)
            for op in adapter_result.operations_attempted:
                if op not in result.services_attempted:
                    result.services_attempted.append(op)
            for op in adapter_result.operations_succeeded:
                if op not in outcome["operations_succeeded"]:
                    outcome["operations_succeeded"].append(op)
            for err in adapter_result.errors:
                outcome["errors"].append(err.as_dict())
            if adapter_result.operations_succeeded:
                any_success = True
                outcome["succeeded"] = True
                coverage.services_succeeded.append(adapter.name)
            if adapter_result.errors:
                failed_ops = {e.operation for e in adapter_result.errors}
                if failed_ops and not adapter_result.operations_succeeded:
                    coverage.services_failed.append(adapter.name)
                elif failed_ops:
                    coverage.notes.append(
                        f"{adapter.name}: partial failures in {', '.join(sorted(failed_ops))}"
                    )
            say(
                f"  {adapter.name}: {len(adapter_result.resources)} resources, "
                f"{len(adapter_result.errors)} errors"
            )

        # Tag enrichment for everything discovered in this region.
        arns = [r.arn for r in region_resources if r.arn]
        tag_errors: list[OperationError] = []
        tags_by_arn = collect_tags(session, region, arns, config, tag_errors)
        result.errors.extend(tag_errors)
        for resource in region_resources:
            if resource.arn and resource.arn in tags_by_arn and not resource.tags:
                resource.tags = tags_by_arn[resource.arn]

        # Convert to records (dedup within region by record id).
        for resource in region_resources:
            record = build_record(resource, identity.account_id, config.scan_id, region)
            result.registry.upsert(record)
            result.resources_discovered += 1

        # Activity evidence (if requested).
        if config.activity_days > 0:
            events = collect_activity_events(session, region, config, result.errors)
            events = filter_window(events, config.observation_start)
            result.events.extend(events)
            say(f"  activity events: {len(events)} (window {config.activity_days}d)")
        else:
            result.notes.append(
                "activity evidence collection disabled for this scan "
                "(--skip-activity or activity_days=0)"
            )

        if any_success:
            coverage.status = "scanned"
        else:
            coverage.status = "permission_error"
            coverage.notes.append("no discovery operation succeeded in this region")
        result.coverage.append(coverage)

    # De-duplicate events across regions (same event id).
    deduped: dict[str, ActivityEvent] = {}
    for event in result.events:
        deduped.setdefault(event.event_id, event)
    result.events = sorted(deduped.values(), key=lambda e: e.event_time, reverse=True)

    # Unmatched invocation synthesis BEFORE classification so synthesized
    # records are classified too.
    existing_ids = {r.record_id for r in result.registry.records}
    from .classification import match_events_to_records

    matches, unmatched = match_events_to_records(result.registry.records, result.events)
    synth = synthesize_activity_records(unmatched, identity.account_id, config.scan_id)
    for record in synth:
        if record.record_id not in existing_ids:
            result.registry.upsert(record)
    say(f"Activity evidence: {summarize_events(result.events)}")

    # Classification across all records.
    classify_all(result.registry.records, result.events, window_days=config.activity_days)

    # Usage, billing, capability coverage, and findings. Enrichment failures are
    # isolated so the inventory remains usable and the failure stays visible.
    try:
        from .insights import enrich_scan
        say("Collecting usage, cost, and coverage evidence ...")
        enrich_scan(result, session, config)
        usage_status = result.usage_collection.status if result.usage_collection else "not_configured"
        cost_status = result.cost_collection.status if result.cost_collection else "not_configured"
        say(
            f"Usage: {usage_status} ({len(result.usage_measurements)} measurements); "
            f"Cost: {cost_status} ({len(result.cost_records)} records); "
            f"Findings: {len(result.findings)}"
        )
    except Exception as exc:  # noqa: BLE001 - enrichment must not lose inventory
        logger.exception("enrichment failed")
        result.errors.append(OperationError(
            service="insights", operation="enrich_scan", region=None,
            error_type="collection_failed",
            message=f"{type(exc).__name__}: {exc}", scan_id=config.scan_id,
        ))
        result.notes.append("Insights enrichment failed; inventory and activity evidence are still valid.")

    result.finished_at = utcnow().isoformat()
    result.duration_seconds = round(time.monotonic() - started, 3)
    say(
        f"Scan complete: {len(result.registry)} records, "
        f"{len(result.errors)} errors, {result.duration_seconds}s"
    )
    return result


def build_scan_metadata(result: ScanResult) -> dict[str, Any]:
    config = result.config
    identity = result.identity
    records = result.registry.records
    classification_counts: dict[str, int] = {}
    usage_counts: dict[str, int] = {}
    for rec in records:
        classification_counts[rec.classification] = classification_counts.get(rec.classification, 0) + 1
        usage_counts[rec.usage_status] = usage_counts.get(rec.usage_status, 0) + 1

    findings_by_severity: dict[str, int] = {}
    for finding in result.findings:
        findings_by_severity[finding.severity] = findings_by_severity.get(finding.severity, 0) + 1
    capabilities_by_status: dict[str, int] = {}
    for cap in result.capabilities:
        status = cap.get("discovery_status")
        capabilities_by_status[status] = capabilities_by_status.get(status, 0) + 1

    return {
        "scan_id": config.scan_id,
        "started_at": result.started_at,
        "finished_at": result.finished_at,
        "duration_seconds": result.duration_seconds,
        "account_id": identity.account_id if identity else None,
        "caller_arn": identity.caller_arn if identity else None,
        "profile": config.profile,
        "regions_requested": list(config.regions),
        "regions_scanned": result.regions_scanned,
        "regions_not_scanned": [
            r for r in config.regions if r not in result.regions_scanned
        ],
        "services_attempted": sorted(set(result.services_attempted)),
        "resources_discovered": result.resources_discovered,
        "records_total": len(records),
        "classification_counts": classification_counts,
        "usage_status_counts": usage_counts,
        "activity_evidence_events": len(result.events),
        "activity_summary": summarize_events(result.events),
        "error_count": len(result.errors),
        "observation_window": {
            "activity_days": config.activity_days,
            "start": config.observation_start.isoformat(),
            "end": utcnow().isoformat(),
        },
        "usage_collection": {
            "enabled": config.enable_usage_collection,
            "lookback_days": config.usage_lookback_days,
            "status": result.usage_collection.status if result.usage_collection else "not_configured",
            "reason": result.usage_collection.reason if result.usage_collection else None,
            "measurement_count": len(result.usage_measurements),
            "namespaces_succeeded": result.usage_collection.namespaces_succeeded if result.usage_collection else [],
        },
        "cost_collection": {
            "enabled": config.enable_cost_collection,
            "lookback_days": config.cost_lookback_days,
            "status": result.cost_collection.status if result.cost_collection else "not_configured",
            "reason": result.cost_collection.reason if result.cost_collection else None,
            "record_count": len(result.cost_records),
            "mapped_reported_amount": result.cost_collection.mapped_amount if result.cost_collection else None,
            "unattributed_reported_amount": result.cost_collection.unattributed_amount if result.cost_collection else None,
            "currency": result.cost_collection.currency if result.cost_collection else None,
            "data_through": result.cost_collection.data_through if result.cost_collection else None,
        },
        "findings_summary": {
            "total": len(result.findings),
            "by_severity": findings_by_severity,
        },
        "capabilities_total": len(result.capabilities),
        "capabilities_by_discovery_status": capabilities_by_status,
        "read_only": True,
        "notes": result.notes[:50],
    }
