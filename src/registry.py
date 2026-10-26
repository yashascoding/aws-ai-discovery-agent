"""Registry record model, stable identifiers, provenance, and scan merging."""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import utcnow

SCHEMA_VERSION = "1.0.0"

CLASSIFICATIONS = (
    "CONFIRMED_AI_ACTIVITY",
    "CONFIGURED_AI_RESOURCE",
    "POTENTIAL_AI_USAGE",
    "INACTIVE_OR_STALE",
    "UNKNOWN",
)

USAGE_STATUSES = ("confirmed", "configured_but_unverified", "potential", "inactive", "unknown")

REVIEW_STATUSES = ("not_required", "pending", "in_review", "reviewed", "escalated")

# Governance fields checked for the ISO/IEC 42001-oriented gap report.
GOVERNANCE_FIELDS = (
    ("ai_system_name", "AI system name"),
    ("intended_purpose", "Intended purpose"),
    ("system_owner", "System owner"),
    ("business_owner", "Business owner"),
    ("technical_owner", "Technical owner"),
    ("intended_users", "Intended users / affected parties"),
    ("data_categories", "Data categories processed"),
    ("data_classification", "Data classification"),
    ("personal_data_involved", "Personal or sensitive data involvement"),
    ("human_oversight", "Human oversight arrangements"),
    ("risk_assessment_status", "Risk assessment status"),
    ("known_risks_and_mitigations", "Known risks and mitigations"),
    ("guardrails_or_safety_controls", "Guardrails / safety controls"),
    ("monitoring_arrangements", "Monitoring arrangements"),
    ("deployment_environment", "Deployment environment"),
    ("lifecycle_stage", "Lifecycle stage"),
)


def make_record_id(
    account_id: str | None,
    region: str | None,
    service: str,
    resource_type: str,
    resource_id: str | None,
) -> str:
    """Stable, non-reversible record identifier for merge across scans."""
    key = "|".join(
        [
            account_id or "unknown-account",
            region or "unknown-region",
            service,
            resource_type,
            resource_id or "unknown-id",
        ]
    )
    return "air-" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def _iso(dt: datetime | str | None) -> str | None:
    if dt is None:
        return None
    if isinstance(dt, str):
        return dt
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


@dataclass
class RegistryRecord:
    """One discovered resource as an auditable registry entry.

    Optional governance fields default to None (explicitly unknown) and are
    never invented. Evidence and provenance are kept per field.
    """

    record_id: str
    aws_service: str
    resource_type: str
    #: catalog = global model-catalogue entry; account_resource = concrete
    #: account/Region resource; application_association = inferred AI linkage
    #: from application configuration (not direct invocation evidence).
    resource_kind: str = "account_resource"
    classification: str = "UNKNOWN"
    classification_reasons: list[str] = field(default_factory=list)
    detection_method: list[str] = field(default_factory=list)
    usage_status: str = "unknown"
    missing_metadata_fields: list[str] = field(default_factory=list)
    human_review_status: str = "pending"
    provenance: dict[str, dict[str, Any]] = field(default_factory=dict)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    first_observed: str = field(default_factory=lambda: _iso(utcnow()))
    last_observed: str = field(default_factory=lambda: _iso(utcnow()))
    last_inventory_scan: str = field(default_factory=lambda: _iso(utcnow()))
    first_seen_scan: str | None = None
    last_seen_scan: str | None = None
    record_version: int = 1

    # Identification and ownership
    ai_system_name: str | None = None
    resource_name: str | None = None
    description: str | None = None
    intended_purpose: str | None = None
    system_owner: str | None = None
    business_owner: str | None = None
    technical_owner: str | None = None
    owner_source: str | None = None
    aws_account_id: str | None = None
    aws_region: str | None = None
    resource_arn: str | None = None
    resource_id: str | None = None
    creation_time: str | None = None
    last_modified_time: str | None = None
    last_observed_activity_time: str | None = None
    creator_or_last_actor: str | None = None
    creator_or_last_actor_kind: str | None = None

    # AI technology and lifecycle
    technology_category: str | None = None
    model_provider: str | None = None
    model_name_version: str | None = None
    foundation_model_id: str | None = None
    inference_profile_id: str | None = None
    sagemaker_model_arn: str | None = None
    sagemaker_endpoint_name: str | None = None
    sagemaker_training_job_name: str | None = None
    sagemaker_pipeline_arn: str | None = None
    bedrock_agent_id: str | None = None
    bedrock_knowledge_base_id: str | None = None
    bedrock_guardrail_id: str | None = None
    bedrock_flow_id: str | None = None
    lifecycle_stage: str | None = None
    deployment_environment: str | None = None
    system_status: str | None = None
    classification_confidence: str | None = None

    # Usage and operational evidence
    last_invocation_time: str | None = None
    last_successful_invocation_time: str | None = None
    invocation_count_in_window: int | None = None
    invocation_window_days: int | None = None
    calling_principal: str | None = None
    evidence_source: str | None = None
    evidence_event_time: str | None = None
    cloudtrail_event_ids: list[str] = field(default_factory=list)
    evidence_limitations: list[str] = field(default_factory=list)
    usage_measurements: list[dict[str, Any]] = field(default_factory=list)
    cost_records: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)

    # Governance and risk
    tags: dict[str, str] = field(default_factory=dict)
    #: Inferred AI association evidence for application resources (e.g. Lambda
    #: configuration hints). Never treated as direct invocation proof.
    ai_association: dict[str, Any] | None = None
    data_categories: str | None = None
    data_classification: str | None = None
    personal_data_involved: str | None = None
    intended_users: str | None = None
    human_oversight: str | None = None
    policy_references: list[str] = field(default_factory=list)
    risk_assessment_status: str | None = None
    known_risks_and_mitigations: str | None = None
    guardrails_or_safety_controls: str | None = None
    monitoring_arrangements: str | None = None
    incident_or_change_references: list[str] = field(default_factory=list)
    follow_up_actions: list[str] = field(default_factory=list)

    def set_field(self, name: str, value: Any, source: str, observed_at: datetime | None = None) -> None:
        """Assign a value and record its provenance. Never overwrites with None."""
        if value is None or value == "" or value == []:
            return
        current = getattr(self, name, None)
        if current is None or current == "" or current == []:
            setattr(self, name, value)
            self.provenance[name] = {
                "source": source,
                "observed_at": _iso(observed_at or utcnow()),
            }

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def compute_missing_fields(record: RegistryRecord) -> list[str]:
    """Return governance field keys that are unknown for this record."""
    missing = []
    for key, _label in GOVERNANCE_FIELDS:
        value = getattr(record, key, None)
        if value is None or value == "" or value == "unknown":
            missing.append(key)
    return missing


class Registry:
    """In-memory registry with stable IDs, merge semantics, and history."""

    def __init__(self) -> None:
        self._records: dict[str, RegistryRecord] = {}

    def upsert(self, record: RegistryRecord) -> RegistryRecord:
        existing = self._records.get(record.record_id)
        if existing is None:
            if record.first_seen_scan is None:
                record.first_seen_scan = record.last_seen_scan
            self._records[record.record_id] = record
            return record
        return merge_records(existing, record)

    @property
    def records(self) -> list[RegistryRecord]:
        return list(self._records.values())

    def __len__(self) -> int:
        return len(self._records)

    def to_document(
        self,
        scan_meta: dict[str, Any],
        errors: list[dict[str, Any]],
        coverage: list[dict[str, Any]],
        *,
        capabilities: list[dict[str, Any]] | None = None,
        findings: list[dict[str, Any]] | None = None,
        usage_measurements: list[dict[str, Any]] | None = None,
        cost_records: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        records = []
        for rec in sorted(self._records.values(), key=lambda r: r.record_id):
            rec.missing_metadata_fields = compute_missing_fields(rec)
            records.append(rec.to_dict())
        document = {
            "schema_version": SCHEMA_VERSION,
            "scan": scan_meta,
            "records": records,
            "errors": errors,
            "coverage": coverage,
        }
        if capabilities is not None:
            document["capabilities"] = capabilities
        if findings is not None:
            document["findings"] = findings
        if usage_measurements is not None:
            document["usage_measurements"] = usage_measurements
        if cost_records is not None:
            document["cost_records"] = cost_records
        return document


def merge_records(existing: RegistryRecord, incoming: RegistryRecord) -> RegistryRecord:
    """Merge a newly observed version of a record into the existing one.

    Rules: keep earliest first_observed, take latest last_observed, prefer
    non-null incoming values, union list/set fields, keep the stronger
    classification, and retain provenance from both sides.
    """
    existing.last_observed = max(
        filter(None, [existing.last_observed, incoming.last_observed]),
        default=existing.last_observed,
    ) or existing.last_observed
    if incoming.last_seen_scan:
        existing.last_seen_scan = incoming.last_seen_scan
    existing.last_inventory_scan = incoming.last_inventory_scan or existing.last_inventory_scan
    existing.record_version += 1

    # Classification is *derived* state: the freshest scan reflects the current
    # evidence and current classification logic/code version, so it must win.
    # We only fall back to the historical value when the fresh record carries a
    # weaker/unknown classification AND the previous one had direct evidence
    # (e.g. a resource temporarily not listed). This prevents a stale, once-
    # stronger classification from masking a corrected reclassification.
    existing_had_direct_evidence = "cloudtrail_activity" in (existing.detection_method or [])
    incoming_is_unknown = incoming.classification in {"UNKNOWN", None}
    if incoming_is_unknown and existing_had_direct_evidence:
        pass  # keep the previously-evidenced classification
    else:
        existing.classification = incoming.classification
        existing.classification_confidence = incoming.classification_confidence
    # Always union reasons so the audit trail keeps both sides.
    for reason in incoming.classification_reasons:
        if reason not in existing.classification_reasons:
            existing.classification_reasons.append(reason)

    usage_rank = {"confirmed": 0, "inactive": 1, "configured_but_unverified": 2, "potential": 3, "unknown": 4}
    if not (incoming_is_unknown and existing_had_direct_evidence):
        existing.usage_status = incoming.usage_status
    else:
        if usage_rank.get(incoming.usage_status, 9) < usage_rank.get(existing.usage_status, 9):
            existing.usage_status = incoming.usage_status

    for f in fields(incoming):
        name = f.name
        if name in {
            "record_id",
            "first_observed",
            "last_observed",
            "last_seen_scan",
            "first_seen_scan",
            "record_version",
            "last_inventory_scan",
            "classification",
            "classification_reasons",
            "classification_confidence",
            "usage_status",
        }:
            continue
        value = getattr(incoming, name)
        current = getattr(existing, name)
        if isinstance(value, list) or isinstance(current, list):
            merged = list(current or [])
            for item in value or []:
                if item not in merged:
                    merged.append(item)
            if merged:
                setattr(existing, name, merged)
        elif isinstance(value, dict) or isinstance(current, dict):
            merged_dict = dict(current or {})
            for k, v in (value or {}).items():
                merged_dict.setdefault(k, v)
            if merged_dict:
                setattr(existing, name, merged_dict)
        elif value not in (None, "", []):
            setattr(existing, name, value)
            src = incoming.provenance.get(name)
            if src and name not in existing.provenance:
                existing.provenance[name] = src
    for key, src in incoming.provenance.items():
        existing.provenance.setdefault(key, src)
    return existing


def load_previous_inventory(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return None


def _record_from_dict(raw: dict[str, Any]) -> RegistryRecord | None:
    """Rehydrate one record, ignoring keys this schema version does not know."""
    known = {f.name for f in fields(RegistryRecord)}
    payload = {k: v for k, v in raw.items() if k in known}
    try:
        return RegistryRecord(**payload)
    except TypeError:
        return None


def records_from_document(document: dict[str, Any]) -> list[RegistryRecord]:
    """Rehydrate the registry records held in an inventory document."""
    out: list[RegistryRecord] = []
    for raw in document.get("records", []):
        record = _record_from_dict(raw)
        if record is not None:
            out.append(record)
    return out


def refresh_scan_counts(document: dict[str, Any]) -> dict[str, Any]:
    """Recompute inventory-scoped counters from the document's records.

    ``records_total``, ``classification_counts`` and ``usage_status_counts``
    describe the *inventory*, so they must be recomputed whenever records are
    merged in; otherwise the summary contradicts the inventory it describes.
    """
    records = document.get("records", [])
    scan = document.setdefault("scan", {})
    classification_counts: dict[str, int] = {}
    usage_counts: dict[str, int] = {}
    for raw in records:
        classification = raw.get("classification") or "UNKNOWN"
        classification_counts[classification] = classification_counts.get(classification, 0) + 1
        usage = raw.get("usage_status") or "unknown"
        usage_counts[usage] = usage_counts.get(usage, 0) + 1
    scan["records_total"] = len(records)
    scan["classification_counts"] = classification_counts
    scan["usage_status_counts"] = usage_counts
    return document


def merge_with_previous(document: dict[str, Any], previous: dict[str, Any]) -> dict[str, Any]:
    """Merge a previous inventory's records into a fresh scan document."""
    registry = Registry()
    for record in records_from_document(previous):
        registry.upsert(record)
    for record in records_from_document(document):
        registry.upsert(record)
    merged = dict(document)
    merged["records"] = [
        r.to_dict() for r in sorted(registry.records, key=lambda x: x.record_id)
    ]
    for rec_raw in merged["records"]:
        rec_raw["missing_metadata_fields"] = [
            key for key, _ in GOVERNANCE_FIELDS
            if getattr_by_key(rec_raw, key) in (None, "", "unknown")
        ]
    return refresh_scan_counts(merged)


def getattr_by_key(rec: dict[str, Any], key: str) -> Any:
    return rec.get(key)
