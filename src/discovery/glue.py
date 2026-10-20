"""AWS Glue ML transforms discovery adapter.

APIs used
---------
- glue.ListMLTransforms (paginated)

Why it matters
--------------
Glue ML transforms are concrete, deployed ML resources living outside
Bedrock/SageMaker; without them an AI inventory would be incomplete.

Blind spots
-----------
- Transform job run history (who ran what, when) requires
  Glue.GetMLTaskRuns / GetJobRun and is summarised only when cheap to fetch.
- Glue DevEndpoints and Blueprints are out of scope for this POC.
"""
from __future__ import annotations

from botocore.exceptions import BotoCoreError, ClientError

from ..config import ScanConfig
from ..errors import OperationError, classify_exception, error_message, get_logger, with_retry
from .base import AdapterResult, BaseAdapter, DiscoveredResource, register_adapter
from .paginate import collect_pages

logger = get_logger(__name__)

# Upper bound on GetMLTransform detail calls per Region (rate-limit friendly).
MAX_TRANSFORM_DETAILS = 50


@register_adapter
class GlueAdapter(BaseAdapter):
    name = "glue"
    service = "glue"

    def api_operations(self) -> list[tuple[str, str]]:
        return [("glue", "ListMLTransforms")]

    def required_permissions(self) -> list[str]:
        return ["glue:ListMLTransforms", "glue:GetMLTransform"]

    def documented_blind_spots(self) -> list[str]:
        return [
            "Only ML transforms are covered; ordinary Glue ETL jobs are "
            "excluded because they are not ML resources by default.",
            "Task-run history is not collected in this POC.",
        ]

    def discover(self, session, region: str) -> AdapterResult:
        result = AdapterResult()
        operation = "list_ml_transforms"
        result.operations_attempted.append(f"glue.{operation}")
        try:
            client = session.client("glue", region_name=region)
            transform_ids = with_retry(
                lambda: collect_pages(client, operation, "TransformIds", {"MaxResults": 100}),
                max_retries=self.config.max_retries,
                base_delay=self.config.retry_base_delay,
                logger=logger,
                context="glue.list_ml_transforms",
            )
            result.operations_succeeded.append(f"glue.{operation}")
        except (ClientError, BotoCoreError) as exc:
            result.errors.append(
                OperationError(
                    service=self.service,
                    operation="ListMLTransforms",
                    region=region,
                    error_type=classify_exception(exc),
                    message=error_message(exc),
                    scan_id=self.config.scan_id,
                )
            )
            return result

        # ListMLTransforms returns IDs only; fetch details per transform
        # (bounded) to obtain ARN/name/status metadata.
        for transform_id in [t for t in transform_ids if isinstance(t, str)][:MAX_TRANSFORM_DETAILS]:
            try:
                detail = with_retry(
                    lambda t=transform_id: client.get_ml_transform(TransformId=t),
                    max_retries=self.config.max_retries,
                    base_delay=self.config.retry_base_delay,
                    logger=logger,
                    context="glue.get_ml_transform",
                )
            except (ClientError, BotoCoreError) as exc:
                result.errors.append(
                    OperationError(
                        service=self.service,
                        operation="GetMLTransform",
                        region=region,
                        error_type=classify_exception(exc),
                        message=error_message(exc),
                        scan_id=self.config.scan_id,
                    )
                )
                continue
            t = detail or {}
            result.resources.append(
                DiscoveredResource(
                    service="glue",
                    resource_type="glue_ml_transform",
                    resource_id=t.get("TransformId") or t.get("Name") or transform_id,
                    region=region,
                    arn=t.get("Arn"),
                    name=t.get("Name"),
                    description=t.get("Description"),
                    status=t.get("State"),
                    created_time=str(t.get("CreateTime")) if t.get("CreateTime") else None,
                    modified_time=str(t.get("UpdateTime")) if t.get("UpdateTime") else None,
                    metadata={
                        "transform_type": t.get("TransformType"),
                        "glue_version": t.get("GlueVersion"),
                        "role": t.get("Role"),
                        "transform_id": transform_id,
                    },
                    source_operation="glue.ListMLTransforms+GetMLTransform",
                )
            )
        return result
