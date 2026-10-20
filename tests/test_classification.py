"""Classification: categories, rationale, evidence links, staleness policy."""
from datetime import datetime, timedelta, timezone

from src.classification import classify_all, classify_record
from src.evidence.cloudtrail import ActivityEvent
from src.registry import RegistryRecord

NOW = datetime(2026, 10, 20, tzinfo=timezone.utc)


def _event(
    event_id: str,
    name: str = "InvokeModel",
    success: bool = True,
    days_ago: int = 1,
    target: dict | None = None,
) -> ActivityEvent:
    return ActivityEvent(
        evidence_id="ev-" + event_id[:8],
        event_id=event_id,
        event_name=name,
        event_source="bedrock-runtime.amazonaws.com",
        event_time=(NOW - timedelta(days=days_ago)).isoformat(),
        region="ap-south-1",
        caller_arn="arn:aws:iam::111122223333:role/Workload",
        user_identity_type="AssumedRole",
        error_code=None if success else "AccessDenied",
        success=success,
        is_invocation=name in {"InvokeModel", "Converse", "InvokeEndpoint", "InvokeAgent"},
        target=target or {},
    )


def _record(**kwargs) -> RegistryRecord:
    defaults = dict(
        record_id="air-" + "a" * 16,
        aws_service="bedrock",
        resource_type="bedrock_guardrail",
        aws_account_id="111122223333",
        aws_region="ap-south-1",
    )
    defaults.update(kwargs)
    return RegistryRecord(**defaults)


def test_successful_invocation_is_confirmed_with_high_confidence():
    rec = _record()
    outcome = classify_record(rec, [_event("e1", success=True)], now=NOW)
    assert outcome.classification == "CONFIRMED_AI_ACTIVITY"
    assert outcome.usage_status == "confirmed"
    assert outcome.confidence == "high"
    assert any("successful" in r for r in outcome.reasons)
    assert outcome.evidence_ids


def test_failed_only_invocation_is_confirmed_activity_but_not_verified_success():
    rec = _record()
    outcome = classify_record(rec, [_event("e1", success=False)], now=NOW)
    assert outcome.classification == "CONFIRMED_AI_ACTIVITY"
    assert outcome.usage_status == "configured_but_unverified"
    assert any("failed" in r for r in outcome.reasons)
    assert any("no successful AI" in lim for lim in outcome.evidence_limitations)


def test_ai_native_resource_without_activity_is_configured():
    rec = _record(resource_type="sagemaker_endpoint", aws_service="sagemaker",
                  creation_time=(NOW - timedelta(days=5)).isoformat())
    outcome = classify_record(rec, [], now=NOW)
    assert outcome.classification == "CONFIGURED_AI_RESOURCE"
    assert outcome.usage_status == "configured_but_unverified"


def test_stale_ai_resource_is_inactive_after_policy_threshold():
    rec = _record(
        resource_type="sagemaker_model",
        aws_service="sagemaker",
        creation_time=(NOW - timedelta(days=300)).isoformat(),
        last_modified_time=(NOW - timedelta(days=200)).isoformat(),
    )
    outcome = classify_record(rec, [], now=NOW)
    assert outcome.classification == "INACTIVE_OR_STALE"
    assert outcome.usage_status == "inactive"
    assert any("staleness policy" in r for r in outcome.reasons)


def test_recent_ai_resource_is_not_stale():
    rec = _record(
        resource_type="sagemaker_model",
        aws_service="sagemaker",
        creation_time=(NOW - timedelta(days=10)).isoformat(),
    )
    outcome = classify_record(rec, [], now=NOW)
    assert outcome.classification == "CONFIGURED_AI_RESOURCE"


def test_catalogue_entry_without_activity_is_never_usage():
    rec = _record(
        resource_type="bedrock_foundation_model_catalog_entry",
        resource_kind="catalog",
    )
    outcome = classify_record(rec, [], now=NOW)
    assert outcome.classification == "UNKNOWN"
    assert outcome.usage_status == "unknown"
    assert outcome.review_status == "not_required"


def test_catalogue_entry_with_direct_invocation_evidence_is_confirmed():
    rec = _record(
        resource_type="bedrock_foundation_model_catalog_entry",
        resource_kind="catalog",
        foundation_model_id="anthropic.claude-haiku-4-5-20251001-v1:0",
    )
    outcome = classify_record(
        rec, [_event("e1", target={"modelId": "anthropic.claude-haiku-4-5-20251001-v1:0"})],
        now=NOW,
    )
    assert outcome.classification == "CONFIRMED_AI_ACTIVITY"


def test_governance_tag_on_non_ai_resource_is_potential():
    rec = _record(
        aws_service="s3",
        resource_type="s3_resource",
        resource_kind="application_association",
        tags={"AI-System": "Doc Embeddings"},
    )
    outcome = classify_record(rec, [], now=NOW)
    assert outcome.classification == "POTENTIAL_AI_USAGE"
    assert outcome.usage_status == "potential"


def test_static_configuration_association_is_potential_not_confirmed():
    rec = _record(
        aws_service="lambda",
        resource_type="lambda_function",
        resource_kind="application_association",
        ai_association={
            "confidence": "low",
            "basis": "static_configuration",
            "indicators": [{"basis": "environment_variable_key", "detail": "BEDROCK_MODEL_ID"}],
        },
    )
    outcome = classify_record(rec, [], now=NOW)
    assert outcome.classification == "POTENTIAL_AI_USAGE"
    assert any("not runtime proof" in r or "configuration" in r for r in outcome.reasons)


def test_plain_non_ai_resource_is_unknown():
    rec = _record(aws_service="s3", resource_type="s3_resource")
    outcome = classify_record(rec, [], now=NOW)
    assert outcome.classification == "UNKNOWN"
    assert outcome.review_status == "not_required"


def test_classify_all_links_events_and_counts_invocations():
    rec = _record(foundation_model_id="m-1", resource_type="bedrock_foundation_model_catalog_entry",
                  resource_kind="catalog")
    events = [
        _event("e1", target={"modelId": "m-1"}),
        _event("e1", target={"modelId": "m-1"}),  # duplicate id handled by caller normally
        _event("e2", name="InvokeEndpoint", success=False, days_ago=2,
               target={"endpointName": "missing-endpoint"}),
    ]
    classify_all([rec], events, window_days=30, now=NOW)
    assert rec.classification == "CONFIRMED_AI_ACTIVITY"
    assert rec.last_invocation_time is not None
    # Duplicate event id 'e1' is deduplicated inside classify_all.
    assert rec.invocation_count_in_window == 1
