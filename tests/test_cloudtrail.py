"""CloudTrail evidence: parsing, sanitization, window filtering, dedupe."""
from datetime import datetime, timedelta, timezone

from src.config import ScanConfig
from src.evidence.cloudtrail import (
    collect_activity_events,
    filter_window,
    parse_cloudtrail_event,
    summarize_events,
)
from tests.testkit import fixture_session

NOW = datetime.now(timezone.utc)


def _wrapper(event_id="e-1", name="InvokeModel", source="bedrock-runtime.amazonaws.com",
             days_ago=-1, detail_overrides=None):
    detail = {
        "eventName": name,
        "eventSource": source,
        "eventTime": (NOW + timedelta(days=days_ago)).isoformat(),
        "awsRegion": "ap-south-1",
        "eventID": event_id,
        "requestID": "req-1",
        "userIdentity": {"type": "AssumedRole", "arn": "arn:aws:iam::1:role/R"},
        "requestParameters": {"modelId": "m-1"},
        "requestPayload": {"body": "PROMPT-CONTENT-MUST-NOT-LEAK"},
        "responseElements": {"output": "MODEL-OUTPUT-MUST-NOT-LEAK"},
    }
    detail.update(detail_overrides or {})
    import json
    return {
        "EventId": event_id,
        "EventName": name,
        "EventSource": source,
        "EventTime": (NOW + timedelta(days=days_ago)).isoformat(),
        "CloudTrailEvent": json.dumps(detail),
    }


def test_parse_extracts_metadata_and_whitelisted_targets_only():
    event = parse_cloudtrail_event(_wrapper(), "ap-south-1")
    assert event is not None
    assert event.event_name == "InvokeModel"
    assert event.target == {"modelId": "m-1"}
    assert event.success is True
    assert event.is_invocation is True
    assert event.caller_arn == "arn:aws:iam::1:role/R"
    serialized = repr(event.as_dict())
    assert "PROMPT-CONTENT-MUST-NOT-LEAK" not in serialized
    assert "MODEL-OUTPUT-MUST-NOT-LEAK" not in serialized


def test_parse_marks_errors_as_unsuccessful_non_success():
    event = parse_cloudtrail_event(
        _wrapper(detail_overrides={"errorCode": "ModelNotReadyException"}),
        "ap-south-1",
    )
    assert event.success is False
    assert event.error_code == "ModelNotReadyException"


def test_management_events_are_not_invocations():
    event = parse_cloudtrail_event(_wrapper(name="CreateEndpoint", source="sagemaker.amazonaws.com"), "ap-south-1")
    assert event.is_invocation is False


def test_window_filter_drops_historical_events():
    recent = parse_cloudtrail_event(_wrapper(event_id="r1", days_ago=-5), "ap-south-1")
    old = parse_cloudtrail_event(_wrapper(event_id="o1", days_ago=-120), "ap-south-1")
    start = NOW - timedelta(days=30)
    kept = filter_window([recent, old], start, NOW)
    assert [e.event_id for e in kept] == ["r1"]


def test_collect_activity_events_dedupes_and_summarizes():
    config = ScanConfig(profile="synthetic", regions=["ap-south-1"], activity_days=30)
    session = fixture_session()
    events = collect_activity_events(session, "ap-south-1", config, errors=[])
    ids = [e.event_id for e in events]
    assert len(ids) == len(set(ids)), "duplicate CloudTrail deliveries must collapse"
    # Fixture set: success invoke, failed invoke, create job, 120-day-old invoke.
    within = filter_window(events, config.observation_start)
    assert len(within) == len(events) - 1  # old event present in raw feed, dropped by window
    summary = summarize_events(within)
    assert summary["successful_invocations"] == 1
    assert summary["failed_invocations"] == 1
    assert summary["management_events"] == 1


def test_observation_window_is_configurable():
    from src.config import utcnow

    config = ScanConfig(profile="s", regions=["ap-south-1"], activity_days=7)
    expected = utcnow() - timedelta(days=7)
    assert abs((config.observation_start - expected).total_seconds()) < 5
