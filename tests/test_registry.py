"""Registry: stable IDs, merge semantics, provenance, missing-field logic."""
from src.registry import (
    Registry,
    RegistryRecord,
    compute_missing_fields,
    make_record_id,
    merge_records,
)


def test_record_id_is_stable_and_unique():
    a = make_record_id("111122223333", "ap-south-1", "sagemaker", "sagemaker_model", "m1")
    b = make_record_id("111122223333", "ap-south-1", "sagemaker", "sagemaker_model", "m1")
    c = make_record_id("111122223333", "us-east-1", "sagemaker", "sagemaker_model", "m1")
    assert a == b
    assert a != c
    assert a.startswith("air-") and len(a) == 20


def test_provenance_records_first_source_and_never_overwrites_with_none():
    rec = RegistryRecord(
        record_id=make_record_id("1", "r", "svc", "t", "id"),
        aws_service="svc",
        resource_type="t",
    )
    rec.set_field("intended_purpose", "score fraud", "tag:Owner")
    rec.set_field("intended_purpose", None, "other")
    rec.set_field("intended_purpose", "other value", "other")
    assert rec.intended_purpose == "score fraud"
    assert rec.provenance["intended_purpose"]["source"] == "tag:Owner"


def test_merge_lets_fresh_classification_win_and_unions_lists():
    # Previous scan: configured resource. Fresh scan: now confirmed via activity.
    previously_configured = RegistryRecord(
        record_id="air-" + "0" * 16,
        aws_service="bedrock",
        resource_type="bedrock_guardrail",
        classification="CONFIGURED_AI_RESOURCE",
        classification_reasons=["configured exists"],
        usage_status="configured_but_unverified",
        detection_method=["aws_api_listing"],
        record_version=1,
    )
    freshly_confirmed = RegistryRecord(
        record_id="air-" + "0" * 16,
        aws_service="bedrock",
        resource_type="bedrock_guardrail",
        classification="CONFIRMED_AI_ACTIVITY",
        classification_reasons=["successful invocation"],
        usage_status="confirmed",
        detection_method=["cloudtrail_activity"],
        evidence=[{"evidence_id": "ev-1", "kind": "cloudtrail_event", "source": "cloudtrail.lookup_events"}],
        record_version=1,
        last_seen_scan="scan-2",
    )
    merged = merge_records(previously_configured, freshly_confirmed)
    assert merged.classification == "CONFIRMED_AI_ACTIVITY"
    assert merged.usage_status == "confirmed"
    # Audit trail retains both reason sets.
    assert "configured exists" in merged.classification_reasons
    assert "successful invocation" in merged.classification_reasons
    assert set(merged.detection_method) == {"aws_api_listing", "cloudtrail_activity"}
    assert merged.record_version == 2
    assert merged.last_seen_scan == "scan-2"


def test_merge_keeps_evidenced_activity_when_fresh_scan_sees_unknown():
    # A resource previously confirmed via CloudTrail must not be silently
    # demoted to UNKNOWN just because the fresh listing returned no evidence.
    confirmed = RegistryRecord(
        record_id="air-" + "1" * 16,
        aws_service="sagemaker",
        resource_type="sagemaker_endpoint",
        classification="CONFIRMED_AI_ACTIVITY",
        usage_status="confirmed",
        detection_method=["cloudtrail_activity"],
    )
    incoming_unknown = RegistryRecord(
        record_id="air-" + "1" * 16,
        aws_service="sagemaker",
        resource_type="sagemaker_endpoint",
        classification="UNKNOWN",
        usage_status="unknown",
        detection_method=["aws_api_listing"],
    )
    merged = merge_records(confirmed, incoming_unknown)
    assert merged.classification == "CONFIRMED_AI_ACTIVITY"
    assert merged.usage_status == "confirmed"


def test_merge_allows_fresh_reclassification_without_activity_evidence():
    # Conversely, a corrected reclassification (e.g. an AWS-managed resource
    # that should be catalogue-only) must supersede a stale stronger label when
    # the previous label was NOT backed by direct activity evidence.
    stale_configured = RegistryRecord(
        record_id="air-" + "3" * 16,
        aws_service="bedrock",
        resource_type="bedrock_inference_profile",
        classification="INACTIVE_OR_STALE",
        usage_status="inactive",
        detection_method=["aws_api_listing"],
    )
    fresh_catalog = RegistryRecord(
        record_id="air-" + "3" * 16,
        aws_service="bedrock",
        resource_type="bedrock_inference_profile",
        resource_kind="catalog",
        classification="UNKNOWN",
        usage_status="unknown",
        detection_method=["aws_api_listing"],
    )
    merged = merge_records(stale_configured, fresh_catalog)
    assert merged.classification == "UNKNOWN"
    assert merged.usage_status == "unknown"
    assert merged.resource_kind == "catalog"


def test_registry_upsert_deduplicates_by_record_id():
    registry = Registry()
    for _ in range(3):
        registry.upsert(
            RegistryRecord(
                record_id=make_record_id("1", "r", "svc", "t", "x"),
                aws_service="svc",
                resource_type="t",
            )
        )
    assert len(registry) == 1


def test_missing_fields_flagged_for_partially_documented_records():
    rec = RegistryRecord(
        record_id="air-" + "2" * 16,
        aws_service="sagemaker",
        resource_type="sagemaker_endpoint",
        ai_system_name="Fraud Scoring",
        intended_purpose="Score claims",
    )
    missing = compute_missing_fields(rec)
    assert "system_owner" in missing
    assert "human_oversight" in missing
    assert "ai_system_name" not in missing
    assert "intended_purpose" not in missing
