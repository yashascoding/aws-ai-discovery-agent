"""Resource Groups Tagging API adapter + ARN tag enrichment.

Two capabilities:
1. Adapter: discover *any* taggable resource carrying governance AI tags
   (AI-System, Owner, BusinessPurpose, ...) — catches AI usage tagged in
   non-AI-native services (Test E).
2. ``collect_tags``: batch-fetch tags for already-discovered ARNs so records
   carry tag evidence without one API call per resource.

APIs used
---------
- resourcegroupstaggingapi.GetResources (paginated; TagFilters and/or
  ResourceARNList batches)

Blind spots
-----------
- Untagged resources are invisible to capability 1 (by design).
- Services that do not support tagging are not returned.
- Tag values are governance *claims* recorded by humans, not verified facts.
"""
from __future__ import annotations

from typing import Any, Iterable

from botocore.exceptions import BotoCoreError, ClientError

from ..config import GOVERNANCE_TAG_KEYS, ScanConfig
from ..errors import OperationError, classify_exception, error_message, get_logger, with_retry
from .base import AdapterResult, BaseAdapter, DiscoveredResource, register_adapter
from .paginate import collect_pages

logger = get_logger(__name__)

ARN_BATCH_SIZE = 50

# Discovery (finding AI-associated resources outside AI-native services) only
# queries tags that *assert an AI association*. Broader governance tags
# (Owner, Environment, ...) are still collected for discovered ARNs by
# collect_tags() enrichment — but they must not turn ordinary resources into
# scan candidates by themselves.
AI_ASSOCIATION_TAG_KEYS = ("AI-System",)

# Services whose resources are covered by dedicated adapters (or the
# application adapter); tagging-discovered records for them would duplicate.
AI_NATIVE_OR_APP_SERVICES = frozenset(
    {"bedrock", "bedrock-agent", "bedrock-runtime", "bedrock-agent-runtime",
     "sagemaker", "sagemaker-runtime", "glue", "lambda"}
)


def collect_tags(
    session,
    region: str,
    arns: Iterable[str],
    config: ScanConfig,
    errors: list[OperationError] | None = None,
) -> dict[str, dict[str, str]]:
    """Batch-fetch tags for the given ARNs. Returns {arn: {tag_key: tag_value}}."""
    arn_list = [a for a in arns if a]
    tags: dict[str, dict[str, str]] = {}
    if not arn_list:
        return tags
    try:
        client = session.client("resourcegroupstaggingapi", region_name=region)
    except (ClientError, BotoCoreError) as exc:
        if errors is not None:
            errors.append(
                OperationError(
                    service="resourcegroupstaggingapi",
                    operation="GetResources",
                    region=region,
                    error_type=classify_exception(exc),
                    message=error_message(exc),
                    scan_id=config.scan_id,
                )
            )
        return tags

    for start in range(0, len(arn_list), ARN_BATCH_SIZE):
        batch = arn_list[start : start + ARN_BATCH_SIZE]
        try:
            paginator = client.get_paginator("get_resources")
            for page in paginator.paginate(ResourceARNList=batch):
                for mapping in page.get("ResourceTagMappingList", []):
                    arn = mapping.get("ResourceARN")
                    if not arn:
                        continue
                    tag_dict = {
                        t["Key"]: t["Value"] for t in mapping.get("Tags", []) if "Key" in t
                    }
                    tags[arn] = tag_dict
        except (ClientError, BotoCoreError) as exc:
            if errors is not None:
                errors.append(
                    OperationError(
                        service="resourcegroupstaggingapi",
                        operation="GetResources",
                        region=region,
                        error_type=classify_exception(exc),
                        message=error_message(exc),
                        scan_id=config.scan_id,
                    )
                )
            break
    return tags


@register_adapter
class TaggingAdapter(BaseAdapter):
    """Discover resources that carry AI governance tags."""

    name = "tags"
    service = "resourcegroupstaggingapi"

    def api_operations(self) -> list[tuple[str, str]]:
        return [("resourcegroupstaggingapi", "GetResources")]

    def required_permissions(self) -> list[str]:
        return ["tagging:GetResources"]

    def documented_blind_spots(self) -> list[str]:
        return [
            "Only finds resources that already carry the configured tag keys; "
            "untagged AI usage is out of scope for this adapter.",
            "Tag values are human-asserted metadata and are not verified "
            "against runtime behaviour.",
            "Some AI services (e.g. certain Bedrock resource types) do not "
            "support tags and will not appear.",
        ]

    def discover(self, session, region: str) -> AdapterResult:
        result = AdapterResult()
        operation = "get_resources"
        result.operations_attempted.append(f"tagging.{operation}")
        try:
            client = session.client("resourcegroupstaggingapi", region_name=region)
            found: list[dict[str, Any]] = []
            for key in AI_ASSOCIATION_TAG_KEYS:
                pages = with_retry(
                    lambda k=key: collect_pages(
                        client,
                        operation,
                        "ResourceTagMappingList",
                        {"TagFilters": [{"Key": k}]},
                    ),
                    max_retries=self.config.max_retries,
                    base_delay=self.config.retry_base_delay,
                    logger=logger,
                    context=f"tagging.get_resources[{key}]",
                )
                found.extend(pages)
            result.operations_succeeded.append(f"tagging.{operation}")
        except (ClientError, BotoCoreError) as exc:
            result.errors.append(
                OperationError(
                    service=self.service,
                    operation="GetResources",
                    region=region,
                    error_type=classify_exception(exc),
                    message=error_message(exc),
                    scan_id=self.config.scan_id,
                )
            )
            return result

        seen: set[str] = set()
        for mapping in found:
            arn = mapping.get("ResourceARN")
            if not arn or arn in seen:
                continue
            seen.add(arn)
            tag_dict = {
                t["Key"]: t["Value"] for t in mapping.get("Tags", []) if "Key" in t
            }
            service, resource_type = _parse_arn(arn)
            # Resources in AI-native services are already discovered (with
            # full metadata) by their dedicated adapters; their tags arrive
            # through collect_tags enrichment instead. Creating duplicate
            # records here would corrupt stable record IDs.
            if service in AI_NATIVE_OR_APP_SERVICES:
                continue
            result.resources.append(
                DiscoveredResource(
                    service=service or "unknown",
                    resource_type=resource_type or "tagged_resource",
                    resource_id=arn,
                    region=region,
                    arn=arn,
                    name=tag_dict.get("AI-System") or arn.split("/")[-1],
                    tags=tag_dict,
                    metadata={"resource_kind": "application_association", "matched_governance_tags": True},
                    source_operation="resourcegroupstaggingapi.GetResources",
                )
            )
        return result


def _parse_arn(arn: str) -> tuple[str | None, str | None]:
    """arn:aws:service:region:account:resource -> (service, resource_type).

    Handles slash/colon qualified ARNs; unqualified ARNs (e.g. S3 buckets)
    fall back to "<service>_resource" instead of using the resource name.
    """
    try:
        parts = arn.split(":", 5)
        if len(parts) < 6:
            return None, None
        service = parts[2]
        resource = parts[5]
        if "/" in resource:
            rtype = resource.split("/", 1)[0]
        elif ":" in resource:
            rtype = resource.split(":", 1)[0]
        else:
            rtype = f"{service}_resource" if service else "resource"
        return service, rtype
    except Exception:  # pragma: no cover - defensive
        return None, None
