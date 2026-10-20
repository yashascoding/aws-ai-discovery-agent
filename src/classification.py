"""Transparent, explainable AI-usage classification.

Categories (mutually exclusive, ordered by evidentiary strength)
----------------------------------------------------------------
1. CONFIRMED_AI_ACTIVITY  — direct, attributable evidence of an AI API
   invocation (CloudTrail event matched to this resource).
2. CONFIGURED_AI_RESOURCE — a concrete AI/ML resource exists in the account;
   activity not verified.
3. POTENTIAL_AI_USAGE     — indirect evidence (config association, governance
   tag) suggests an application may use AI.
4. INACTIVE_OR_STALE      — configured resource, no activity evidence in the
   observation window, and last modified > STALE_AFTER_DAYS ago (policy in
   src/config.py; documented in docs/limitations.md).
5. UNKNOWN                — insufficient evidence.

Every classification stores machine-readable reasons plus the evidence IDs
used, so a human reviewer can audit the decision. This module never calls an
LLM and never invents metadata.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

from .config import STALE_AFTER_DAYS, utcnow
from .evidence.cloudtrail import ActivityEvent
from .registry import RegistryRecord

# Ordered strongest -> weakest. Used for merge precedence too.
CLASSIFICATION_ORDER = (
    "CONFIRMED_AI_ACTIVITY",
    "CONFIGURED_AI_RESOURCE",
    "POTENTIAL_AI_USAGE",
    "INACTIVE_OR_STALE",
    "UNKNOWN",
)

AI_NATIVE_RESOURCE_PREFIXES = (
    "bedrock",
    "sagemaker",
    "glue_ml_transform",
)

DETECTION_AWS_LISTING = "aws_api_listing"
DETECTION_ACTIVITY = "cloudtrail_activity"
DETECTION_TAG = "governance_tag"
DETECTION_STATIC_ASSOCIATION = "static_configuration_association"


@dataclass
class ClassificationOutcome:
    classification: str
    usage_status: str
    reasons: list[str] = field(default_factory=list)
    confidence: str | None = None
    detection_methods: list[str] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    review_status: str = "pending"
    evidence_limitations: list[str] = field(default_factory=list)
    follow_up_actions: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "classification": self.classification,
            "usage_status": self.usage_status,
            "reasons": self.reasons,
            "confidence": self.confidence,
            "detection_methods": self.detection_methods,
            "evidence_ids": self.evidence_ids,
            "review_status": self.review_status,
            "evidence_limitations": self.evidence_limitations,
            "follow_up_actions": self.follow_up_actions,
        }


# --------------------------------------------------------------------------- #
# Event -> record matching
# --------------------------------------------------------------------------- #
@dataclass
class EventMatch:
    record_id: str
    events: list[ActivityEvent] = field(default_factory=list)
    match_basis: str = ""


def _id_variants(value: str) -> set[str]:
    """Normalized match keys for a resource identifier or event target.

    Bedrock model ids contain colons (``...-v1:0``) so colon-splitting is
    unsafe; only ARN-style path suffixes are additionally considered.
    """
    cleaned = value.strip().lower()
    variants = {cleaned}
    if "/" in cleaned:
        variants.add(cleaned.rsplit("/", 1)[-1])
    if cleaned.startswith("arn:"):
        variants.add(cleaned)  # full ARN already present
    return {v for v in variants if v}


def match_events_to_records(
    records: Iterable[RegistryRecord], events: Iterable[ActivityEvent]
) -> tuple[list[EventMatch], list[ActivityEvent]]:
    """Link activity events to records.

    Returns (matches, unmatched_events). Unmatched *invocation* events are
    used to synthesise activity records by the caller; unmatched management
    events are dropped from record linkage but kept in the evidence file.
    """
    records_list = list(records)
    by_field: dict[str, list[RegistryRecord]] = {}
    by_arn: dict[str, RegistryRecord] = {}

    for rec in records_list:
        if rec.resource_arn:
            by_arn[rec.resource_arn.lower()] = rec
        for key, value in (
            ("modelId", rec.foundation_model_id),
            ("modelId", rec.inference_profile_id),
            ("endpointName", rec.sagemaker_endpoint_name),
            ("endpointName", rec.resource_name if rec.resource_type == "sagemaker_endpoint" else None),
            ("agentId", rec.bedrock_agent_id),
            ("knowledgeBaseId", rec.bedrock_knowledge_base_id),
            ("guardrailIdentifier", rec.bedrock_guardrail_id),
            ("pipelineName", rec.resource_id if rec.resource_type == "sagemaker_pipeline" else None),
            ("trainingJobName", rec.sagemaker_training_job_name),
            ("trainingJobName", rec.resource_name if rec.resource_type == "sagemaker_training_job" else None),
        ):
            if value and isinstance(value, str):
                for variant in _id_variants(value):
                    key_name = f"{key}={variant}"
                    bucket = by_field.setdefault(key_name, [])
                    if rec not in bucket:
                        bucket.append(rec)
                # Model ids also index under the raw id for exact matches.
                if key == "modelId":
                    raw = value.lower()
                    bucket = by_field.setdefault(f"modelId={raw}", [])
                    if rec not in bucket:
                        bucket.append(rec)

    matches: dict[str, EventMatch] = {}
    unmatched: list[ActivityEvent] = []

    for event in events:
        targets: list[RegistryRecord] = []
        basis = ""

        for arn in event.resource_arns:
            rec = by_arn.get(arn.lower())
            if rec is not None:
                targets.append(rec)
                basis = "resource_arn"

        if not targets:
            for key, value in event.target.items():
                candidates: list[RegistryRecord] = []
                for variant in _id_variants(value):
                    candidates.extend(by_field.get(f"{key}={variant}", []))
                if candidates:
                    targets.extend(candidates)
                    basis = f"target:{key}"
                    break

        if not targets:
            unmatched.append(event)
            continue
        for rec in targets:
            match = matches.setdefault(
                rec.record_id, EventMatch(record_id=rec.record_id, match_basis=basis)
            )
            if event not in match.events:
                match.events.append(event)

    return list(matches.values()), unmatched


# --------------------------------------------------------------------------- #
# Classification
# --------------------------------------------------------------------------- #
def classify_record(
    record: RegistryRecord,
    matched_events: list[ActivityEvent],
    *,
    now: datetime | None = None,
) -> ClassificationOutcome:
    """Produce the classification outcome for one record with full rationale."""
    now = now or utcnow()
    outcome = ClassificationOutcome(
        classification="UNKNOWN",
        usage_status="unknown",
        review_status="pending",
    )

    invocations = [e for e in matched_events if e.is_invocation]
    successful = [e for e in invocations if e.success]
    failed = [e for e in invocations if not e.success]
    management = [e for e in matched_events if not e.is_invocation]

    # ---- 1. Direct activity evidence -------------------------------- #
    if successful:
        outcome.classification = "CONFIRMED_AI_ACTIVITY"
        outcome.usage_status = "confirmed"
        outcome.confidence = "high"
        outcome.reasons.append(
            f"CloudTrail evidence: {len(successful)} successful "
            f"{'invocation' if len(successful) == 1 else 'invocations'} "
            f"(e.g. {successful[0].event_name} on {successful[0].event_source}) "
            f"within the observation window"
        )
        outcome.evidence_limitations.append(
            "A successful API invocation confirms the call completed at the API "
            "level; it does not by itself prove an end user consumed the AI response"
        )
        outcome.review_status = "pending"
        outcome.follow_up_actions.append(
            "Confirm whether observed invocations map to a business workload and "
            "record intended purpose/owner in the registry"
        )
    elif failed:
        outcome.classification = "CONFIRMED_AI_ACTIVITY"
        outcome.usage_status = "configured_but_unverified"
        outcome.confidence = "medium"
        outcome.reasons.append(
            f"CloudTrail evidence: {len(failed)} attempted AI invocation(s) "
            f"(e.g. {failed[0].event_name}) observed, but ALL failed with errors "
            f"({failed[0].error_code or 'unknown error'}); success not verified"
        )
        outcome.evidence_limitations.append(
            "Only failed invocation attempts were observed; no successful AI "
            "response is evidenced in the window"
        )
        outcome.follow_up_actions.append(
            "Investigate why AI invocations failed (permissions, model access, throttling)"
        )

    if invocations:
        outcome.detection_methods.append(DETECTION_ACTIVITY)
        outcome.evidence_ids.extend(e.evidence_id for e in invocations)

    # ---- 2/3/4. Evidence-driven non-activity branches ---------------- #
    is_catalog = record.resource_kind == "catalog"
    is_ai_native = record.resource_type.startswith(AI_NATIVE_RESOURCE_PREFIXES)

    if outcome.classification == "CONFIRMED_AI_ACTIVITY":
        if failed and successful:
            outcome.evidence_limitations.append(
                "Mixed evidence: both successful and failed invocations observed"
            )
            outcome.review_status = "escalated"
            outcome.follow_up_actions.append(
                "Review mixed success/failure invocation evidence for this resource"
            )
    elif is_catalog:
        # Test A: catalogue availability is never usage.
        outcome.classification = "UNKNOWN"
        outcome.usage_status = "unknown"
        outcome.confidence = "high"
        outcome.reasons.append(
            "Catalogue entry (AWS-provided/global availability, e.g. Bedrock "
            "foundation models or system-defined inference profiles): this lists "
            "what is available in the Region, not an account-specific deployed or "
            "invoked resource"
        )
        outcome.detection_methods.append(DETECTION_AWS_LISTING)
        outcome.review_status = "not_required"
        outcome.evidence_limitations.append(
            "Catalogue presence must not be read as organizational AI usage"
        )
    elif record.tags.get("AI-System") and not is_ai_native:
        # Governance tag on a non-AI-native resource: human-asserted association.
        outcome.classification = "POTENTIAL_AI_USAGE"
        outcome.usage_status = "potential"
        outcome.confidence = "low"
        outcome.reasons.append(
            f"Governance tag AI-System={record.tags['AI-System']!r} asserts an AI "
            "association on a non-AI-native resource; tag values are human-asserted "
            "claims, not verified runtime behaviour"
        )
        outcome.detection_methods.append(DETECTION_TAG)
        outcome.evidence_ids.append(f"tag:{record.resource_arn or record.resource_id}")
        outcome.follow_up_actions.append(
            "Validate the AI-System tag claim against actual workload behaviour"
        )
    elif _association_marker(record):
        association = _association_marker(record)
        indicators = ", ".join(
            i.get("detail", "") for i in association.get("indicators", [])[:3]
        )
        outcome.classification = "POTENTIAL_AI_USAGE"
        outcome.usage_status = "potential"
        outcome.confidence = "low"
        outcome.reasons.append(
            f"Static configuration evidence ({association.get('basis')}) suggests "
            f"possible AI usage: [{indicators}]; configuration is not runtime proof"
        )
        outcome.detection_methods.append(DETECTION_STATIC_ASSOCIATION)
        outcome.evidence_ids.append(f"assoc:{record.resource_id}")
        outcome.evidence_limitations.append(
            "Inferred from static configuration only: no invocation evidence found"
        )
        outcome.follow_up_actions.append(
            "Instrument or inspect runtime behaviour to confirm/deny AI usage"
        )
    elif is_ai_native:
        outcome.detection_methods.append(DETECTION_AWS_LISTING)
        stale = _assess_staleness(record, now)
        if stale is not None and stale:
            outcome.classification = "INACTIVE_OR_STALE"
            outcome.usage_status = "inactive"
            outcome.confidence = "medium"
            outcome.reasons.append(
                f"Concrete AI resource ({record.resource_type}) exists but has no "
                f"activity evidence in the observation window and was last modified "
                f"more than {STALE_AFTER_DAYS} days ago (staleness policy)"
            )
            outcome.evidence_limitations.append(
                "Staleness is assessed from resource metadata and available "
                "CloudTrail evidence; data events may be disabled, so absence of "
                "events is not proof of zero usage"
            )
            outcome.follow_up_actions.append(
                "Confirm with the resource owner whether it is still required"
            )
        else:
            outcome.classification = "CONFIGURED_AI_RESOURCE"
            outcome.usage_status = "configured_but_unverified"
            outcome.confidence = "medium"
            outcome.reasons.append(
                f"Concrete AI/ML resource ({record.resource_type}) discovered via "
                f"AWS API listing "
                f"({record.provenance.get('resource_type', {}).get('source', 'aws api listing')}); "
                "no invocation evidence available in the observation window"
            )
            outcome.evidence_limitations.append(
                "Absence of CloudTrail events does not prove non-use: invocation "
                "data events may be disabled or outside retention"
            )
            if stale is None:
                outcome.evidence_limitations.append(
                    "Creation/modification time unknown; staleness not assessable"
                )
    else:
        # Non-AI-native resource without association or tag evidence.
        outcome.classification = "UNKNOWN"
        outcome.usage_status = "unknown"
        outcome.confidence = "high"
        outcome.reasons.append(
            "No AI-specific evidence found: resource type is not AI-native and no "
            "association, tag, or activity evidence was observed"
        )
        outcome.review_status = "not_required"

    # ---- Activity enrichment common to all branches ------------------- #
    if management and outcome.classification != "UNKNOWN":
        latest_mgmt = management[0]
        if latest_mgmt.event_name.startswith(("Create", "Register", "Provision")):
            if not record.creator_or_last_actor and latest_mgmt.caller_arn:
                record.creator_or_last_actor = latest_mgmt.caller_arn
                record.creator_or_last_actor_kind = "creator"
        elif not record.creator_or_last_actor and latest_mgmt.caller_arn:
            record.creator_or_last_actor = latest_mgmt.caller_arn
            record.creator_or_last_actor_kind = "recent_api_caller"
        outcome.evidence_ids.extend(e.evidence_id for e in management)

    if record.missing_metadata_fields and outcome.review_status == "pending":
        outcome.follow_up_actions.append(
            "Complete missing governance metadata: "
            + ", ".join(record.missing_metadata_fields[:6])
        )

    # Deduplicate while preserving order.
    outcome.reasons = list(dict.fromkeys(outcome.reasons))
    outcome.evidence_ids = list(dict.fromkeys(outcome.evidence_ids))
    outcome.follow_up_actions = list(dict.fromkeys(outcome.follow_up_actions))
    outcome.evidence_limitations = list(dict.fromkeys(outcome.evidence_limitations))
    outcome.detection_methods = list(dict.fromkeys(outcome.detection_methods))
    return outcome


def apply_outcome(record: RegistryRecord, outcome: ClassificationOutcome) -> None:
    record.classification = outcome.classification
    record.classification_reasons = outcome.reasons
    record.classification_confidence = outcome.confidence
    record.usage_status = outcome.usage_status
    record.detection_method = outcome.detection_methods
    record.human_review_status = outcome.review_status
    record.evidence_limitations = outcome.evidence_limitations
    for action in outcome.follow_up_actions:
        if action not in record.follow_up_actions:
            record.follow_up_actions.append(action)
    seen = {e.get("evidence_id") for e in record.evidence}
    for evidence_id in outcome.evidence_ids:
        if evidence_id in seen:
            continue
        record.evidence.append(
            {
                "evidence_id": evidence_id,
                "kind": (
                    "cloudtrail_event"
                    if evidence_id.startswith("ev-")
                    else "tag"
                    if evidence_id.startswith("tag:")
                    else "association"
                ),
                "source": "cloudtrail.lookup_events"
                if evidence_id.startswith("ev-")
                else "resource_groups_tagging_api"
                if evidence_id.startswith("tag:")
                else "static_configuration",
            }
        )


# --------------------------------------------------------------------------- #
def apply_activity_to_record(record: RegistryRecord, events: list[ActivityEvent]) -> None:
    """Populate activity fields on a record from matched events."""
    if not events:
        return
    invocations = sorted(
        [e for e in events if e.is_invocation], key=lambda e: e.event_time, reverse=True
    )
    successful = [e for e in invocations if e.success]
    all_sorted = sorted(events, key=lambda e: e.event_time, reverse=True)

    if invocations:
        record.last_invocation_time = invocations[0].event_time
    if successful:
        record.last_successful_invocation_time = successful[0].event_time
    if all_sorted:
        record.last_observed_activity_time = all_sorted[0].event_time
        record.evidence_event_time = all_sorted[0].event_time
        record.evidence_source = "cloudtrail.lookup_events"
    if all_sorted and all_sorted[0].caller_arn:
        record.calling_principal = all_sorted[0].caller_arn

    invocation_event_ids = [e.event_id for e in invocations if e.success]
    other_ids = [e.event_id for e in all_sorted if e.event_id not in invocation_event_ids]
    record.cloudtrail_event_ids = list(
        dict.fromkeys(invocation_event_ids + other_ids)
    )[:50]


def _assess_staleness(record: RegistryRecord, now: datetime) -> bool | None:
    """True = stale under policy, False = recently modified, None = unknown."""
    reference: str | None = record.last_modified_time or record.creation_time
    if not reference:
        return None
    try:
        ts = datetime.fromisoformat(str(reference).replace("Z", "+00:00"))
    except ValueError:
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    age_days = (now - ts).total_seconds() / 86400
    return age_days > STALE_AFTER_DAYS


def _association_marker(record: RegistryRecord) -> dict[str, Any] | None:
    """Fetch AI-association info if the record carries it."""
    value = getattr(record, "ai_association", None)
    if isinstance(value, dict) and value:
        return value
    return None


def classify_all(
    records: Iterable[RegistryRecord],
    events: Iterable[ActivityEvent],
    *,
    window_days: int,
    now: datetime | None = None,
) -> dict[str, list[EventMatch]]:
    """Match events to records, classify everything, mutate records in place.

    Returns unmatched-event matches keyed 'unmatched' for caller synthesis.
    """
    records_list = list(records)
    # Defensive dedupe by CloudTrail event id: duplicate deliveries must never
    # inflate invocation counts.
    deduped: dict[str, ActivityEvent] = {}
    for event in sorted(events, key=lambda e: e.event_time, reverse=True):
        deduped.setdefault(event.event_id, event)
    events_list = list(deduped.values())
    matches, unmatched = match_events_to_records(records_list, events_list)
    by_id = {m.record_id: m for m in matches}

    for record in records_list:
        match = by_id.get(record.record_id)
        matched = match.events if match else []
        if matched:
            for event in matched:
                if event.is_invocation:
                    record.invocation_window_days = window_days
            apply_activity_to_record(record, matched)
            record.invocation_count_in_window = sum(
                1 for e in matched if e.is_invocation
            )
        outcome = classify_record(record, matched, now=now)
        apply_outcome(record, outcome)

    return {"matched": matches, "unmatched": unmatched}
