"""Amazon SageMaker AI discovery adapter.

APIs used
---------
- sagemaker.ListModels
- sagemaker.ListEndpoints
- sagemaker.ListEndpointConfigs
- sagemaker.ListTrainingJobs
- sagemaker.ListProcessingJobs
- sagemaker.ListPipelines
- sagemaker.ListModelPackages
- sagemaker.ListInferenceComponents
- sagemaker.ListExperiments
- sagemaker.ListTagsForResource (per resource is NOT called; tags come from
  the Resource Groups Tagging API adapter to limit API volume)

Region behaviour
----------------
SageMaker is regional. A Region without the service enabled returns an
endpoint connection or access error recorded per operation.

Blind spots
-----------
- Resource metadata (creation, status) is visible; *who last invoked an
  endpoint* is not available from these APIs — runtime invocation evidence
  comes from CloudTrail (separate evidence adapter).
- Experiment versions and lineage entities are only summarised.
- Studio domains, user profiles, apps, spaces, projects, A2I flow
  definitions, human task UIs, and human loops are enumerated when present.
- Human-loop listing is per flow definition and bounded.
"""
from __future__ import annotations

from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from ..config import ScanConfig
from ..errors import OperationError, classify_exception, error_message, get_logger, with_retry
from .base import AdapterResult, BaseAdapter, DiscoveredResource, register_adapter
from .paginate import collect_pages

logger = get_logger(__name__)


def _iso(value: Any) -> str | None:
    return None if value is None else str(value)


@register_adapter
class SageMakerAdapter(BaseAdapter):
    name = "sagemaker"
    service = "sagemaker"

    def api_operations(self) -> list[tuple[str, str]]:
        return [
            ("sagemaker", "ListModels"),
            ("sagemaker", "ListEndpoints"),
            ("sagemaker", "ListEndpointConfigs"),
            ("sagemaker", "ListTrainingJobs"),
            ("sagemaker", "ListProcessingJobs"),
            ("sagemaker", "ListPipelines"),
            ("sagemaker", "ListModelPackages"),
            ("sagemaker", "ListInferenceComponents"),
            ("sagemaker", "ListExperiments"),
            ("sagemaker", "ListDomains"),
            ("sagemaker", "ListUserProfiles"),
            ("sagemaker", "ListApps"),
            ("sagemaker", "ListSpaces"),
            ("sagemaker", "ListProjects"),
            ("sagemaker", "ListFlowDefinitions"),
            ("sagemaker", "ListHumanTaskUis"),
            ("sagemaker-a2i-runtime", "ListHumanLoops"),
        ]

    def required_permissions(self) -> list[str]:
        return [
            "sagemaker:ListModels",
            "sagemaker:ListEndpoints",
            "sagemaker:ListEndpointConfigs",
            "sagemaker:ListTrainingJobs",
            "sagemaker:ListProcessingJobs",
            "sagemaker:ListPipelines",
            "sagemaker:ListModelPackages",
            "sagemaker:ListInferenceComponents",
            "sagemaker:ListExperiments",
            "sagemaker:ListDomains",
            "sagemaker:ListUserProfiles",
            "sagemaker:ListApps",
            "sagemaker:ListSpaces",
            "sagemaker:ListProjects",
            "sagemaker:ListFlowDefinitions",
            "sagemaker:ListHumanTaskUis",
            "sagemaker:ListTags",
            "sagemaker:ListHumanLoops",
        ]

    def documented_blind_spots(self) -> list[str]:
        return [
            "Endpoint runtime invocation counts are not exposed by list APIs; "
            "last-used evidence requires CloudTrail data events (often disabled).",
            "Deleted models/endpoints outside the CloudTrail retention window "
            "are invisible.",
            "SageMaker feature groups and lineage entities are not enumerated.",
            "Human-loop listing requires a flow definition ARN and is bounded; "
            "loops without a discoverable flow definition are invisible.",
            "Pipeline executions are discovered per pipeline; very large "
            "execution histories are summarised rather than fully enumerated.",
        ]

    # ------------------------------------------------------------------ #
    def discover(self, session, region: str) -> AdapterResult:
        result = AdapterResult()
        client = session.client("sagemaker", region_name=region)

        self._list(
            client, region, result,
            operation="list_models", result_key="Models",
            resource_type="sagemaker_model", id_key="ModelName", arn_key="ModelArn",
            name_key="ModelName", created_key="CreationTime",
            metadata_builder=lambda i: {"sagemaker_model_arn": i.get("ModelArn")},
        )
        self._list(
            client, region, result,
            operation="list_endpoints", result_key="Endpoints",
            resource_type="sagemaker_endpoint", id_key="EndpointName", arn_key="EndpointArn",
            name_key="EndpointName", status_key="EndpointStatus",
            created_key="CreationTime", modified_key="LastModifiedTime",
            metadata_builder=lambda i: {"sagemaker_endpoint_name": i.get("EndpointName")},
        )
        self._list(
            client, region, result,
            operation="list_endpoint_configs", result_key="EndpointConfigs",
            resource_type="sagemaker_endpoint_config", id_key="EndpointConfigName",
            arn_key="EndpointConfigArn", name_key="EndpointConfigName",
            created_key="CreationTime", modified_key="LastModifiedTime",
        )
        self._list(
            client, region, result,
            operation="list_training_jobs", result_key="TrainingJobSummaries",
            resource_type="sagemaker_training_job", id_key="TrainingJobName",
            arn_key="TrainingJobArn", name_key="TrainingJobName",
            status_key="TrainingJobStatus", created_key="CreationTime",
            metadata_builder=lambda i: {"sagemaker_training_job_name": i.get("TrainingJobName")},
        )
        self._list(
            client, region, result,
            operation="list_processing_jobs", result_key="ProcessingJobSummaries",
            resource_type="sagemaker_processing_job", id_key="ProcessingJobName",
            arn_key="ProcessingJobArn", name_key="ProcessingJobName",
            status_key="ProcessingJobStatus", created_key="CreationTime",
        )
        self._list(
            client, region, result,
            operation="list_pipelines", result_key="PipelineSummaries.Pipelines",
            resource_type="sagemaker_pipeline", id_key="PipelineName",
            arn_key="PipelineArn", name_key="PipelineName",
            created_key="CreationTime", modified_key="LastModifiedTime",
            metadata_builder=lambda i: {"sagemaker_pipeline_arn": i.get("PipelineArn")},
        )
        self._list(
            client, region, result,
            operation="list_model_packages", result_key="ModelPackageSummaryList",
            resource_type="sagemaker_model_package", id_key="ModelPackageName",
            arn_key="ModelPackageArn", name_key="ModelPackageName",
            status_key="ModelPackageStatus", created_key="CreationTime",
        )
        self._list(
            client, region, result,
            operation="list_inference_components", result_key="InferenceComponents",
            resource_type="sagemaker_inference_component", id_key="InferenceComponentName",
            arn_key="InferenceComponentArn", name_key="InferenceComponentName",
            status_key="InferenceComponentStatus",
            created_key="CreationTime", modified_key="LastModifiedTime",
        )
        self._list(
            client, region, result,
            operation="list_experiments", result_key="ExperimentSummaries",
            resource_type="sagemaker_experiment", id_key="ExperimentName",
            arn_key="ExperimentArn", name_key="ExperimentName",
            created_key="CreationTime", modified_key="LastModifiedTime",
        )

        self._list(
            client, region, result,
            operation="list_domains", result_key="Domains",
            resource_type="sagemaker_studio_domain", id_key="DomainId",
            arn_key="DomainArn", name_key="DomainName", status_key="Status",
            created_key="CreationTime", modified_key="LastModifiedTime",
        )
        self._list(
            client, region, result,
            operation="list_user_profiles", result_key="UserProfiles",
            resource_type="sagemaker_studio_user_profile", id_key="UserProfileName",
            arn_key="UserProfileArn", name_key="UserProfileName", status_key="Status",
            created_key="CreationTime", modified_key="LastModifiedTime",
            metadata_builder=lambda i: {"sagemaker_studio_domain_id": i.get("DomainId")},
        )
        self._list(
            client, region, result,
            operation="list_apps", result_key="Apps",
            resource_type="sagemaker_studio_app", id_key="AppName",
            arn_key="AppArn", name_key="AppName", status_key="Status",
            created_key="CreationTime",
            metadata_builder=lambda i: {"app_type": i.get("AppType"), "domain_id": i.get("DomainId")},
        )
        self._list(
            client, region, result,
            operation="list_spaces", result_key="Spaces",
            resource_type="sagemaker_studio_space", id_key="SpaceName",
            arn_key="SpaceArn", name_key="SpaceName", status_key="Status",
            created_key="CreationTime", modified_key="LastModifiedTime",
            metadata_builder=lambda i: {"domain_id": i.get("DomainId")},
        )
        self._list(
            client, region, result,
            operation="list_projects", result_key="ProjectSummaryList",
            resource_type="sagemaker_project", id_key="ProjectName",
            arn_key="ProjectArn", name_key="ProjectName", status_key="ProjectStatus",
            created_key="CreationTime",
        )
        self._list(
            client, region, result,
            operation="list_flow_definitions", result_key="FlowDefinitionSummaries",
            resource_type="sagemaker_a2i_flow_definition", id_key="FlowDefinitionName",
            arn_key="FlowDefinitionArn", name_key="FlowDefinitionName",
            status_key="FlowDefinitionStatus", created_key="CreationTime",
        )
        self._list(
            client, region, result,
            operation="list_human_task_uis", result_key="HumanTaskUiSummaries",
            resource_type="sagemaker_a2i_human_task_ui", id_key="HumanTaskUiName",
            arn_key="HumanTaskUiArn", name_key="HumanTaskUiName",
            created_key="CreationTime",
        )

        # Best-effort enrichment: pipeline executions per pipeline (bounded).
        self._pipeline_executions(client, region, result)
        self._human_loops(session, region, result)
        return result

    # ------------------------------------------------------------------ #
    def _pipeline_executions(self, client, region: str, result: AdapterResult) -> None:
        pipelines = [
            r for r in result.resources if r.resource_type == "sagemaker_pipeline"
        ]
        for pipeline in pipelines:
            name = pipeline.resource_id
            if not name:
                continue
            operation = "list_pipeline_executions"
            result.operations_attempted.append(f"sagemaker.{operation}")
            try:
                executions = collect_pages(
                    client,
                    operation,
                    "PipelineExecutionSummaries",
                    {"PipelineName": name},
                    max_pages=5,
                )
                result.operations_succeeded.append(f"sagemaker.{operation}")
                if executions:
                    latest = executions[0]
                    pipeline.metadata["latest_execution_status"] = latest.get(
                        "PipelineExecutionStatus"
                    )
                    pipeline.metadata["latest_execution_start"] = _iso(
                        latest.get("StartTime")
                    )
                    pipeline.metadata["execution_count_observed"] = len(executions)
            except (ClientError, BotoCoreError) as exc:
                self._record_error(result, region, operation, exc)

    def _human_loops(self, session, region: str, result: AdapterResult) -> None:
        """List A2I human loops per flow definition (bounded, read-only)."""
        flows = [r for r in result.resources if r.resource_type == "sagemaker_a2i_flow_definition"]
        if not flows:
            return
        try:
            a2i = session.client("sagemaker-a2i-runtime", region_name=region)
        except BotoCoreError as exc:
            self._record_error(result, region, "ListHumanLoops", exc)
            return
        for flow in flows:
            if not flow.arn:
                continue
            operation = "list_human_loops"
            result.operations_attempted.append(f"sagemaker-a2i-runtime.{operation}")
            try:
                loops = collect_pages(
                    a2i, operation, "HumanLoopSummaries",
                    {"FlowDefinitionArn": flow.arn}, max_pages=5,
                )
                result.operations_succeeded.append(f"sagemaker-a2i-runtime.{operation}")
            except (ClientError, BotoCoreError) as exc:
                self._record_error(result, region, "ListHumanLoops", exc)
                continue
            for loop in loops:
                result.resources.append(DiscoveredResource(
                    service="sagemaker",
                    resource_type="sagemaker_a2i_human_loop",
                    resource_id=loop.get("HumanLoopArn") or loop.get("HumanLoopName"),
                    region=region,
                    arn=loop.get("HumanLoopArn"),
                    name=loop.get("HumanLoopName"),
                    status=loop.get("HumanLoopStatus"),
                    created_time=_iso(loop.get("CreationTime")),
                    metadata={"flow_definition_arn": flow.arn},
                    source_operation="sagemaker-a2i-runtime.ListHumanLoops",
                ))

    def _record_error(self, result: AdapterResult, region: str, operation: str, exc: Exception) -> None:
        result.errors.append(
            OperationError(
                service=self.service,
                operation=operation,
                region=region,
                error_type=classify_exception(exc),
                message=error_message(exc),
                scan_id=self.config.scan_id,
            )
        )
        logger.warning(
            "sagemaker operation failed",
            extra={"region": region, "operation": operation, "service": self.service},
        )

    def _list(
        self,
        client,
        region: str,
        result: AdapterResult,
        *,
        operation: str,
        result_key: str,
        resource_type: str,
        id_key: str,
        arn_key: str | None,
        name_key: str | None,
        status_key: str | None = None,
        created_key: str | None = None,
        modified_key: str | None = None,
        metadata_builder=None,
    ) -> None:
        result.operations_attempted.append(f"sagemaker.{operation}")
        try:
            items = with_retry(
                lambda: collect_pages(client, operation, result_key),
                max_retries=self.config.max_retries,
                base_delay=self.config.retry_base_delay,
                logger=logger,
                context=f"sagemaker.{operation}",
            )
            result.operations_succeeded.append(f"sagemaker.{operation}")
        except (ClientError, BotoCoreError) as exc:
            self._record_error(result, region, operation, exc)
            return

        for item in items:
            metadata: dict[str, Any] = {}
            if metadata_builder:
                metadata.update(metadata_builder(item) or {})
            result.resources.append(
                DiscoveredResource(
                    service="sagemaker",
                    resource_type=resource_type,
                    resource_id=item.get(id_key) or f"unknown-{resource_type}",
                    region=region,
                    arn=item.get(arn_key) if arn_key else None,
                    name=item.get(name_key) if name_key else None,
                    status=item.get(status_key) if status_key else None,
                    created_time=_iso(item.get(created_key)) if created_key else None,
                    modified_time=_iso(item.get(modified_key)) if modified_key else None,
                    metadata=metadata,
                    source_operation=f"sagemaker.{operation}",
                )
            )
