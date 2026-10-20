"""CloudTrail activity evidence for AI-related API operations (read-only).

What this collects (metadata only)
----------------------------------
Event ID, event name, event source, event time, Region, caller identity ARN,
target identifiers (modelId, endpoint name, agent id...), request ID, and
success/error status. Prompt bodies, model outputs, and request payloads are
NEVER stored: only whitelisted keys are extracted from the event record.

Known limitations (documented, not worked around)
-------------------------------------------------
- CloudTrail Event History retains 90 days and is throttled (lookup_events
  ~5 req/s/burst). Outside-window events are not visible here.
- Bedrock runtime *data-plane* events (InvokeModel, Converse, ...) appear in
  Event History only when the operator has enabled appropriate CloudTrail
  data events / model invocation logging. Absence of events is NOT proof of
  no usage.
- Event delivery is typically delayed seconds-to-minutes after a call; a
  just-performed call may not be queryable yet.
- Optional CloudTrail Lake / S3 trail sources can be configured but are never
  created automatically by this tool.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

from botocore.exceptions import BotoCoreError, ClientError

from ..config import ScanConfig, utcnow
from ..errors import OperationError, classify_exception, error_message, get_logger, with_retry
from ..discovery.paginate import collect_pages

logger = get_logger(__name__)

# AI-relevant event sources queried in each Region (one LookupEvents call each).
AI_EVENT_SOURCES = (
    "bedrock.amazonaws.com",
    "bedrock-runtime.amazonaws.com",
    "bedrock-agent.amazonaws.com",
    "bedrock-agent-runtime.amazonaws.com",
    "sagemaker.amazonaws.com",
    "sagemaker-runtime.amazonaws.com",
)

# Data-plane API calls that constitute AI invocation evidence.
INVOCATION_EVENT_NAMES = frozenset(
    {
        "InvokeModel",
        "InvokeModelWithResponseStream",
        "Converse",
        "ConverseStream",
        "InvokeAgent",
        "Retrieve",
        "RetrieveAndGenerate",
        "InvokeEndpoint",
        "InvokeEndpointWithResponseStream",
        "InvokeEndpointAsync",
    }
)

# Whitelisted requestParameters keys (metadata only; never payloads).
REQUEST_PARAM_ALLOWLIST = (
    "modelId",
    "endpointName",
    "agentId",
    "knowledgeBaseId",
    "guardrailIdentifier",
    "inferenceProfileId",
    "pipelineName",
    "transformId",
    "modelName",
    "trainingJobName",
    "processingJobName",
    "experimentName",
    "executionPipelineName",
)

MAX_RESULTS_PER_PAGE = 50
INTER_SOURCE_DELAY_SECONDS = 0.25  # stay well under LookupEvents throttles


@dataclass
class ActivityEvent:
    """One sanitized CloudTrail event used as AI activity evidence."""

    evidence_id: str
    event_id: str
    event_name: str
    event_source: str
    event_time: str
    region: str | None
    caller_arn: str | None
    user_identity_type: str | None
    error_code: str | None
    success: bool
    is_invocation: bool
    target: dict[str, str] = field(default_factory=dict)
    resource_arns: list[str] = field(default_factory=list)
    request_id: str | None = None
    read_only: bool | None = None
    user_agent: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "event_id": self.event_id,
            "event_name": self.event_name,
            "event_source": self.event_source,
            "event_time": self.event_time,
            "region": self.region,
            "caller_arn": self.caller_arn,
            "user_identity_type": self.user_identity_type,
            "error_code": self.error_code,
            "success": self.success,
            "is_invocation": self.is_invocation,
            "target": self.target,
            "resource_arns": self.resource_arns,
            "request_id": self.request_id,
            "read_only": self.read_only,
            "user_agent": self.user_agent,
        }


def _iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


def evidence_id_for(event_id: str) -> str:
    return "ev-" + hashlib.sha256(event_id.encode("utf-8")).hexdigest()[:16]


def parse_cloudtrail_event(wrapper: dict[str, Any], region_hint: str | None) -> ActivityEvent | None:
    """Parse a LookupEvents item into a sanitized ActivityEvent."""
    event_id = wrapper.get("EventId")
    if not event_id:
        return None
    raw = wrapper.get("CloudTrailEvent")
    detail: dict[str, Any] = {}
    if isinstance(raw, str):
        try:
            detail = json.loads(raw)
        except json.JSONDecodeError:
            detail = {}
    elif isinstance(raw, dict):
        detail = raw

    event_time = wrapper.get("EventTime") or detail.get("eventTime")
    if isinstance(event_time, datetime):
        event_time_str = _iso(event_time)
    else:
        event_time_str = str(event_time) if event_time else None

    identity = detail.get("userIdentity") or {}
    caller_arn = (
        identity.get("arn")
        or identity.get("principalId")
        or detail.get("username")
    )
    if isinstance(caller_arn, str) and not caller_arn.startswith("arn:"):
        caller_arn = caller_arn or None

    request_params = detail.get("requestParameters") or {}
    target: dict[str, str] = {}
    for key in REQUEST_PARAM_ALLOWLIST:
        value = request_params.get(key)
        if isinstance(value, str) and value:
            target[key] = value

    resource_arns: list[str] = []
    for res in detail.get("resources") or []:
        arn = res.get("ARN") or res.get("arn")
        if isinstance(arn, str):
            resource_arns.append(arn)

    event_name = wrapper.get("EventName") or detail.get("eventName") or ""
    event_source = wrapper.get("EventSource") or detail.get("eventSource") or ""
    error_code = detail.get("errorCode")

    return ActivityEvent(
        evidence_id=evidence_id_for(event_id),
        event_id=event_id,
        event_name=event_name,
        event_source=event_source,
        event_time=event_time_str or "",
        region=detail.get("awsRegion") or region_hint,
        caller_arn=caller_arn,
        user_identity_type=identity.get("type"),
        error_code=error_code,
        success=error_code is None,
        is_invocation=event_name in INVOCATION_EVENT_NAMES,
        target=target,
        resource_arns=resource_arns,
        request_id=detail.get("requestID"),
        read_only=detail.get("readOnly"),
        user_agent=(detail.get("userAgent") or None),
    )


def collect_activity_events(
    session,
    region: str,
    config: ScanConfig,
    errors: list[OperationError] | None = None,
) -> list[ActivityEvent]:
    """Collect AI-related CloudTrail events for the configured observation window."""
    start = config.observation_start
    end = utcnow()
    try:
        client = session.client("cloudtrail", region_name=region)
    except (ClientError, BotoCoreError) as exc:
        if errors is not None:
            errors.append(
                OperationError(
                    service="cloudtrail",
                    operation="LookupEvents",
                    region=region,
                    error_type=classify_exception(exc),
                    message=error_message(exc),
                    scan_id=config.scan_id,
                )
            )
        return []

    collected: dict[str, ActivityEvent] = {}
    for event_source in AI_EVENT_SOURCES:
        if errors is not None and any(
            e.error_type == "access_denied" and e.service == "cloudtrail" for e in errors
        ):
            break  # already denied; stop hammering a denied API
        kwargs = {
            "StartTime": start,
            "EndTime": end,
            "LookupAttributes": [{"AttributeKey": "EventSource", "AttributeValue": event_source}],
            "MaxResults": MAX_RESULTS_PER_PAGE,
        }
        try:
            with_retry(
                lambda k=kwargs: _collect_source(client, k, region, collected),
                max_retries=config.max_retries + 2,
                base_delay=config.retry_base_delay * 2,
                logger=logger,
                context=f"cloudtrail.lookup_events[{event_source}]",
            )
        except (ClientError, BotoCoreError) as exc:
            if errors is not None:
                errors.append(
                    OperationError(
                        service="cloudtrail",
                        operation="LookupEvents",
                        region=region,
                        error_type=classify_exception(exc),
                        message=f"{event_source}: {error_message(exc)}",
                        scan_id=config.scan_id,
                    )
                )
        time.sleep(INTER_SOURCE_DELAY_SECONDS)

    events = list(collected.values())
    events.sort(key=lambda e: e.event_time, reverse=True)
    logger.info(
        "collected activity events",
        extra={"region": region, "operation": f"count={len(events)}"},
    )
    return events


def _collect_source(
    client, kwargs: dict[str, Any], region: str, sink: dict[str, ActivityEvent]
) -> None:
    """One paginated LookupEvents pass for a single event source (dedup by event id)."""
    pages = collect_pages(
        client,
        "lookup_events",
        "Events",
        dict(kwargs),
        max_pages=40,
    )
    for page in pages:
        event = parse_cloudtrail_event(page, region)
        if event is None:
            continue
        sink.setdefault(event.event_id, event)  # Test H: deduplicate


def filter_window(
    events: Iterable[ActivityEvent], start: datetime, end: datetime | None = None
) -> list[ActivityEvent]:
    """Drop events outside the observation window (defensive; API also filters)."""
    end = end or utcnow()
    out = []
    for event in events:
        try:
            ts = datetime.fromisoformat(event.event_time)
        except ValueError:
            continue
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        if start <= ts <= end:
            out.append(event)
    return out


def summarize_events(events: Iterable[ActivityEvent]) -> dict[str, Any]:
    events = list(events)
    invocations = [e for e in events if e.is_invocation]
    return {
        "total_events": len(events),
        "invocation_events": len(invocations),
        "successful_invocations": sum(1 for e in invocations if e.success),
        "failed_invocations": sum(1 for e in invocations if not e.success),
        "management_events": len(events) - len(invocations),
        "distinct_callers": len({e.caller_arn for e in events if e.caller_arn}),
        "earliest_event": min((e.event_time for e in events), default=None),
        "latest_event": max((e.event_time for e in events), default=None),
    }
