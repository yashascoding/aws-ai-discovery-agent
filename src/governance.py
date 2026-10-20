"""ISO/IEC 42001-oriented governance gap analysis.

IMPORTANT framing (also stated in docs/iso42001.md):
ISO/IEC 42001:2023 defines requirements for an AI Management System (AIMS).
It does NOT prescribe a registry database schema, and running this tool does
not establish or imply certification. This module maps *available registry
fields* to the kind of documented-information an AIMS typically needs
(cl. 6.1.2 context, 6.2 AI policy, 7.5 documented information, 8.2 AI system
impact assessment, 8.3 AI system development, 8.5 AI system operation, 9.1
monitoring, 10.2 incident response) and reports *what is missing* — it never
asserts that a control is satisfied.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .config import utcnow
from .registry import GOVERNANCE_FIELDS, RegistryRecord

# (field_key, AIMS-relevant documentation expectation)
FIELD_AIMS_MAPPING: dict[str, str] = {
    "ai_system_name": "Identified AI system (cl. 8.1 AI system life cycle; 8.2 impact assessment inputs)",
    "intended_purpose": "Documented intended purpose and limitations (cl. 8.2.2; 8.3.2)",
    "system_owner": "Assigned accountability/ownership (cl. 5.3 organizational roles; 6.1.2)",
    "business_owner": "Business accountability for the AI system (cl. 5.3)",
    "technical_owner": "Technical responsibility for operation (cl. 8.5.1)",
    "intended_users": "Affected parties and context of use (cl. 6.1.2.2; 8.2.2)",
    "data_categories": "Data/information needs documented (cl. 8.3.3; 8.2.2)",
    "data_classification": "Information security/controls over data (cl. 6.1.2.3; Annex A)",
    "personal_data_involved": "Personal data considerations (cl. 6.1.2.2; 8.2.2)",
    "human_oversight": "Human oversight measures (cl. 8.2.2 c; 8.5.2)",
    "risk_assessment_status": "AI system impact/risk assessment status (cl. 8.2)",
    "known_risks_and_mitigations": "Identified risks and treatment options (cl. 6.1.2; 8.2.4)",
    "guardrails_or_safety_controls": "Implemented controls for AI system operation (cl. 8.5)",
    "monitoring_arrangements": "Monitoring, evaluation of AI system behaviour (cl. 8.5.3; 9.1)",
    "deployment_environment": "Deployment context (cl. 8.3; 8.5.1)",
    "lifecycle_stage": "Life-cycle stage documentation (cl. 8.1; 8.3; 8.5)",
}


@dataclass
class RecordGap:
    record_id: str
    resource_name: str | None
    aws_service: str
    resource_type: str
    classification: str
    usage_status: str
    human_review_status: str
    missing_fields: list[str] = field(default_factory=list)
    missing_descriptions: list[dict[str, str]] = field(default_factory=list)
    follow_up_actions: list[str] = field(default_factory=list)
    priority: str = "medium"  # high | medium | low

    def as_dict(self) -> dict[str, Any]:
        return {
            "record_id": self.record_id,
            "resource_name": self.resource_name,
            "aws_service": self.aws_service,
            "resource_type": self.resource_type,
            "classification": self.classification,
            "usage_status": self.usage_status,
            "human_review_status": self.human_review_status,
            "missing_fields": self.missing_fields,
            "missing_descriptions": self.missing_descriptions,
            "follow_up_actions": self.follow_up_actions,
            "priority": self.priority,
        }


def _priority_for(record: RegistryRecord) -> str:
    if record.classification == "CONFIRMED_AI_ACTIVITY":
        return "high"
    if record.classification in {"POTENTIAL_AI_USAGE", "CONFIGURED_AI_RESOURCE"}:
        return "medium"
    if record.classification == "INACTIVE_OR_STALE":
        return "medium"
    return "low"


def analyze_gaps(records: list[RegistryRecord]) -> dict[str, Any]:
    """Produce the governance gaps document from registry records.

    Catalogue-only records are excluded from per-record gaps (they are not
    organizational AI systems) but counted separately.
    """
    field_labels = dict(GOVERNANCE_FIELDS)
    gaps: list[RecordGap] = []
    catalog_records = 0
    reviewed = 0
    escalated = 0

    for record in records:
        if record.resource_kind == "catalog" and record.classification == "UNKNOWN":
            catalog_records += 1
            continue
        if record.human_review_status == "reviewed":
            reviewed += 1
        if record.human_review_status == "escalated":
            escalated += 1

        missing = record.missing_metadata_fields or [
            key for key, _ in GOVERNANCE_FIELDS
            if getattr(record, key, None) in (None, "", "unknown")
        ]
        if not missing and record.human_review_status in {"pending", "not_required"}:
            continue

        gap = RecordGap(
            record_id=record.record_id,
            resource_name=record.resource_name,
            aws_service=record.aws_service,
            resource_type=record.resource_type,
            classification=record.classification,
            usage_status=record.usage_status,
            human_review_status=record.human_review_status,
            missing_fields=missing,
            missing_descriptions=[
                {
                    "field": key,
                    "label": field_labels.get(key, key),
                    "aims_reference": FIELD_AIMS_MAPPING.get(key, "documented information (cl. 7.5)"),
                }
                for key in missing
            ],
            follow_up_actions=list(record.follow_up_actions),
            priority=_priority_for(record),
        )
        gaps.append(gap)

    gaps.sort(key=lambda g: ({"high": 0, "medium": 1, "low": 2}[g.priority], g.record_id))

    return {
        "generated_at": utcnow().isoformat(),
        "framework_note": (
            "Field mapping reflects ISO/IEC 42001:2023 AIMS documented-information "
            "expectations. This report does not assert conformity or certification, "
            "and ISO/IEC 42001 does not prescribe a registry schema."
        ),
        "records_analyzed": len(records),
        "catalog_records_excluded": catalog_records,
        "records_fully_documented": sum(
            1
            for r in records
            if r.resource_kind != "catalog"
            and not (
                r.missing_metadata_fields
                or [k for k, _ in GOVERNANCE_FIELDS if getattr(r, k, None) in (None, "", "unknown")]
            )
        ),
        "records_pending_review": sum(
            1 for r in records if r.human_review_status == "pending"
        ),
        "records_escalated": escalated,
        "priority_counts": {
            "high": sum(1 for g in gaps if g.priority == "high"),
            "medium": sum(1 for g in gaps if g.priority == "medium"),
            "low": sum(1 for g in gaps if g.priority == "low"),
        },
        "field_completeness": _field_completeness(records),
        "gaps": [g.as_dict() for g in gaps],
    }


def _field_completeness(records: list[RegistryRecord]) -> dict[str, Any]:
    relevant = [r for r in records if r.resource_kind != "catalog"]
    total = len(relevant) or 1
    out: dict[str, Any] = {}
    for key, label in GOVERNANCE_FIELDS:
        known = sum(
            1 for r in relevant if getattr(r, key, None) not in (None, "", "unknown")
        )
        out[key] = {
            "label": label,
            "known": known,
            "missing": len(relevant) - known,
            "coverage_pct": round(100 * known / total, 1),
        }
    return out
