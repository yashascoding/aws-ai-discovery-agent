"""Amazon Bedrock discovery adapter.

APIs used
---------
- bedrock.ListFoundationModels        (model catalogue; not an account resource)
- bedrock.ListInferenceProfiles
- bedrock.ListProvisionedModelThroughputs
- bedrock.ListCustomModels
- bedrock.ListGuardrails
- bedrock-agent.ListAgents
- bedrock-agent.ListAgentAliases     (one call per discovered agent)
- bedrock-agent.ListKnowledgeBases
- bedrock-agent.ListPrompts
- bedrock-agent.ListFlows

Region behaviour
----------------
Bedrock is not available in every Region; unsupported Regions fail with a
ValidationException and are recorded as ``unsupported`` errors, not as
"no resources".

Blind spots
-----------
- Catalogue listings show *availability*, never usage.
- Model invocation activity is only observable through CloudTrail evidence
  (separate adapter), and even then only for API-call events retained.
- Bedrock model invocation logging / CloudTrail data events must already be
  enabled by the operator; this adapter never enables them.
"""
from __future__ import annotations

from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from ..config import ScanConfig
from ..errors import OperationError, classify_exception, error_message, get_logger, with_retry
from .base import AdapterResult, BaseAdapter, DiscoveredResource, register_adapter
from .paginate import call_single, collect_pages

logger = get_logger(__name__)


def _iso(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


# Cross-region inference prefixes AWS uses for system-defined (AWS-managed)
# inference profiles. Application-created profiles have plain ids.
_SYSTEM_INFERENCE_PROFILE_PREFIXES = ("apac.", "global.", "us.", "eu.", "in.", "ap.", "ca.", "sa.", "me.", "af.")


def _inference_profile_kind(item: dict[str, Any]) -> str | None:
    """Classify an inference profile as ``catalog`` (AWS-managed) or account.

    AWS ``ListInferenceProfiles`` returns both system-defined and
    application-created profiles in the same list. System-defined profiles are
    AWS-managed routing resources available to every account, so they belong in
    the catalogue (availability), never in the organizational AI inventory.
    """
    profile_type = str(item.get("type") or "").upper()
    if profile_type == "SYSTEM_DEFINED":
        return "catalog"
    profile_id = str(item.get("inferenceProfileId") or "").lower()
    if any(profile_id.startswith(prefix) for prefix in _SYSTEM_INFERENCE_PROFILE_PREFIXES):
        return "catalog"
    return None


@register_adapter
class BedrockAdapter(BaseAdapter):
    name = "bedrock"
    service = "bedrock"

    def __init__(self, config: ScanConfig) -> None:
        super().__init__(config)

    def api_operations(self) -> list[tuple[str, str]]:
        return [
            ("bedrock", "ListFoundationModels"),
            ("bedrock", "ListInferenceProfiles"),
            ("bedrock", "ListProvisionedModelThroughputs"),
            ("bedrock", "ListCustomModels"),
            ("bedrock", "ListGuardrails"),
            ("bedrock", "ListTagsForResource"),
            ("bedrock-agent", "ListAgents"),
            ("bedrock-agent", "ListAgentAliases"),
            ("bedrock-agent", "ListKnowledgeBases"),
            ("bedrock-agent", "ListPrompts"),
            ("bedrock-agent", "ListFlows"),
        ]

    def required_permissions(self) -> list[str]:
        return [
            "bedrock:ListFoundationModels",
            "bedrock:ListInferenceProfiles",
            "bedrock:ListProvisionedModelThroughputs",
            "bedrock:ListCustomModels",
            "bedrock:ListGuardrails",
            "bedrock:ListTagsForResource",
            "bedrock-agent:ListAgents",
            "bedrock-agent:ListAgentAliases",
            "bedrock-agent:ListKnowledgeBases",
            "bedrock-agent:ListPrompts",
            "bedrock-agent:ListFlows",
        ]

    def documented_blind_spots(self) -> list[str]:
        return [
            "Foundation model listings are catalogue metadata (availability), "
            "not evidence of deployed or invoked models.",
            "Model invocation usage requires CloudTrail evidence; Bedrock "
            "invocation events may be absent unless an operator-enabled trail "
            "or Lake event source exists.",
            "Cross-region inference profile targets are only partially visible "
            "in profile metadata.",
            "Bedrock Studio workspaces and streaming sessions are not covered.",
        ]

    # ------------------------------------------------------------------ #
    def discover(self, session, region: str) -> AdapterResult:
        result = AdapterResult()
        bedrock = session.client("bedrock", region_name=region)
        agent = session.client("bedrock-agent", region_name=region)

        self._discover_catalogue(bedrock, region, result)
        self._discover_simple(
            bedrock, region, result,
            operation="list_inference_profiles",
            result_key="inferenceProfileSummaries",
            resource_type="bedrock_inference_profile",
            id_key="inferenceProfileId",
            arn_key="inferenceProfileArn",
            name_key="inferenceProfileName",
            status_key="status",
            description_key="description",
            created_key="createdAt",
            modified_key="updatedAt",
            metadata_builder=lambda i: {
                "inference_profile_type": i.get("type"),
                "profile_models": [m.get("modelId") for m in (i.get("models") or []) if isinstance(m, dict)],
            },
            kind_builder=_inference_profile_kind,
        )
        self._discover_simple(
            bedrock, region, result,
            operation="list_provisioned_model_throughputs",
            result_key="provisionedModelSummaries",
            resource_type="bedrock_provisioned_throughput",
            id_key="provisionedModelName",
            arn_key="provisionedModelArn",
            name_key="provisionedModelName",
            status_key="status",
            description_key=None,
            created_key="creationTime",
            modified_key="lastModifiedTime",
        )
        self._discover_simple(
            bedrock, region, result,
            operation="list_custom_models",
            result_key="modelSummaries",
            resource_type="bedrock_custom_model",
            id_key="modelName",
            arn_key="modelArn",
            name_key="modelName",
            status_key="modelStatus",
            created_key="creationTime",
        )
        self._discover_guardrails(bedrock, region, result)
        self._discover_agents(agent, region, result)
        self._discover_knowledge_bases(agent, region, result)
        self._discover_simple(
            agent, region, result,
            operation="list_prompts",
            result_key="promptSummaries",
            resource_type="bedrock_prompt",
            id_key="id",
            arn_key="arn",
            name_key="name",
            created_key="createdAt",
            modified_key="updatedAt",
        )
        self._discover_simple(
            agent, region, result,
            operation="list_flows",
            result_key="flowSummaries",
            resource_type="bedrock_flow",
            id_key="id",
            arn_key="arn",
            name_key="name",
            status_key="status",
            created_key="createdAt",
            modified_key="updatedAt",
        )
        return result

    # ------------------------------------------------------------------ #
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
            "bedrock operation failed",
            extra={"region": region, "operation": operation, "service": self.service},
        )

    def _discover_catalogue(self, client, region: str, result: AdapterResult) -> None:
        """Test A: collect foundation model catalogue metadata.

        Catalogue entries are marked ``resource_kind='catalog'`` so downstream
        classification never treats global model availability as account usage.
        """
        operation = "list_foundation_models"
        result.operations_attempted.append(f"bedrock.{operation}")
        try:
            response = with_retry(
                lambda: call_single(client, operation),
                max_retries=self.config.max_retries,
                base_delay=self.config.retry_base_delay,
                logger=logger,
                context=f"bedrock.{operation}",
            )
            result.operations_succeeded.append(f"bedrock.{operation}")
            for model in response.get("modelSummaries", []):
                lifecycle = model.get("modelLifecycle") or {}
                result.resources.append(
                    DiscoveredResource(
                        service="bedrock",
                        resource_type="bedrock_foundation_model_catalog_entry",
                        resource_id=model.get("modelId") or "unknown-model",
                        region=region,
                        arn=None,
                        name=model.get("modelName"),
                        description=model.get("description"),
                        status=lifecycle.get("status"),
                        metadata={
                            "resource_kind": "catalog",
                            "foundation_model_id": model.get("modelId"),
                            "model_provider": model.get("providerName"),
                            "model_lifecycle_status": lifecycle.get("status"),
                            "input_modalities": model.get("inputModalities"),
                            "output_modalities": model.get("outputModalities"),
                            "customizations": model.get("customizations"),
                            "inference_types": model.get("inferenceTypesSupported"),
                        },
                        source_operation="bedrock.ListFoundationModels",
                    )
                )
        except (ClientError, BotoCoreError) as exc:
            self._record_error(result, region, "ListFoundationModels", exc)

    def _discover_guardrails(self, client, region: str, result: AdapterResult) -> None:
        operation = "list_guardrails"
        result.operations_attempted.append(f"bedrock.{operation}")
        try:
            guardrails = with_retry(
                lambda: collect_pages(client, operation, "guardrails"),
                max_retries=self.config.max_retries,
                base_delay=self.config.retry_base_delay,
                logger=logger,
                context=f"bedrock.{operation}",
            )
            result.operations_succeeded.append(f"bedrock.{operation}")
            for g in guardrails:
                arn = g.get("arn")
                result.resources.append(
                    DiscoveredResource(
                        service="bedrock",
                        resource_type="bedrock_guardrail",
                        resource_id=g.get("id") or (arn or "unknown-guardrail"),
                        region=region,
                        arn=arn,
                        name=g.get("name"),
                        description=g.get("description"),
                        status=g.get("status"),
                        created_time=_iso(g.get("createdAt")),
                        modified_time=_iso(g.get("updatedAt")),
                        metadata={
                            "bedrock_guardrail_id": g.get("id"),
                            "guardrail_version": g.get("version"),
                        },
                        source_operation="bedrock.ListGuardrails",
                    )
                )
        except (ClientError, BotoCoreError) as exc:
            self._record_error(result, region, "ListGuardrails", exc)

    def _discover_agents(self, client, region: str, result: AdapterResult) -> None:
        operation = "list_agents"
        result.operations_attempted.append(f"bedrock-agent.{operation}")
        try:
            agents = with_retry(
                lambda: collect_pages(client, operation, "agentSummaries"),
                max_retries=self.config.max_retries,
                base_delay=self.config.retry_base_delay,
                logger=logger,
                context=f"bedrock-agent.{operation}",
            )
            result.operations_succeeded.append(f"bedrock-agent.{operation}")
        except (ClientError, BotoCoreError) as exc:
            self._record_error(result, region, "ListAgents", exc)
            return

        for a in agents:
            agent_id = a.get("agentId")
            result.resources.append(
                DiscoveredResource(
                    service="bedrock-agent",
                    resource_type="bedrock_agent",
                    resource_id=agent_id or "unknown-agent",
                    region=region,
                    arn=a.get("agentArn"),
                    name=a.get("agentName"),
                    description=a.get("description"),
                    status=a.get("status"),
                    created_time=_iso(a.get("createdAt")),
                    modified_time=_iso(a.get("updatedAt")),
                    metadata={"bedrock_agent_id": agent_id},
                    source_operation="bedrock-agent.ListAgents",
                )
            )
            if not agent_id:
                continue
            alias_op = "list_agent_aliases"
            result.operations_attempted.append(f"bedrock-agent.{alias_op}")
            try:
                aliases = collect_pages(
                    client, alias_op, "agentAliasSummaries", {"agentId": agent_id}
                )
                result.operations_succeeded.append(f"bedrock-agent.{alias_op}")
                for alias in aliases:
                    result.resources.append(
                        DiscoveredResource(
                            service="bedrock-agent",
                            resource_type="bedrock_agent_alias",
                            resource_id=alias.get("agentAliasId") or "unknown-alias",
                            region=region,
                            arn=alias.get("agentAliasArn"),
                            name=alias.get("agentAliasName"),
                            status=alias.get("status"),
                            created_time=_iso(alias.get("createdAt")),
                            modified_time=_iso(alias.get("updatedAt")),
                            metadata={
                                "bedrock_agent_id": agent_id,
                                "parent_agent_name": a.get("agentName"),
                            },
                            source_operation="bedrock-agent.ListAgentAliases",
                        )
                    )
            except (ClientError, BotoCoreError) as exc:
                self._record_error(result, region, "ListAgentAliases", exc)

    def _discover_knowledge_bases(self, client, region: str, result: AdapterResult) -> None:
        operation = "list_knowledge_bases"
        result.operations_attempted.append(f"bedrock-agent.{operation}")
        try:
            kbs = with_retry(
                lambda: collect_pages(client, operation, "knowledgeBaseSummaries"),
                max_retries=self.config.max_retries,
                base_delay=self.config.retry_base_delay,
                logger=logger,
                context=f"bedrock-agent.{operation}",
            )
            result.operations_succeeded.append(f"bedrock-agent.{operation}")
            for kb in kbs:
                result.resources.append(
                    DiscoveredResource(
                        service="bedrock-agent",
                        resource_type="bedrock_knowledge_base",
                        resource_id=kb.get("knowledgeBaseId") or "unknown-kb",
                        region=region,
                        arn=kb.get("knowledgeBaseArn"),
                        name=kb.get("name"),
                        description=kb.get("description"),
                        status=kb.get("status"),
                        created_time=_iso(kb.get("createdAt")),
                        modified_time=_iso(kb.get("updatedAt")),
                        metadata={
                            "bedrock_knowledge_base_id": kb.get("knowledgeBaseId"),
                            "knowledge_base_type": kb.get("knowledgeBaseType"),
                        },
                        source_operation="bedrock-agent.ListKnowledgeBases",
                    )
                )
        except (ClientError, BotoCoreError) as exc:
            self._record_error(result, region, "ListKnowledgeBases", exc)

    def _discover_simple(
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
        description_key: str | None = None,
        created_key: str | None = None,
        modified_key: str | None = None,
        metadata_builder=None,
        kind_builder=None,
    ) -> None:
        client_name = client.meta.service_model.service_name
        result.operations_attempted.append(f"{client_name}.{operation}")
        try:
            items = with_retry(
                lambda: collect_pages(client, operation, result_key),
                max_retries=self.config.max_retries,
                base_delay=self.config.retry_base_delay,
                logger=logger,
                context=f"{client_name}.{operation}",
            )
            result.operations_succeeded.append(f"{client_name}.{operation}")
        except (ClientError, BotoCoreError) as exc:
            self._record_error(result, region, operation, exc)
            return

        for item in items:
            metadata: dict[str, Any] = {}
            if metadata_builder:
                metadata.update(metadata_builder(item) or {})
            if kind_builder:
                kind = kind_builder(item)
                if kind:
                    metadata["resource_kind"] = kind
            result.resources.append(
                DiscoveredResource(
                    service=client_name,
                    resource_type=resource_type,
                    resource_id=item.get(id_key) or f"unknown-{resource_type}",
                    region=region,
                    arn=item.get(arn_key) if arn_key else None,
                    name=item.get(name_key) if name_key else None,
                    description=item.get(description_key) if description_key else None,
                    status=item.get(status_key) if status_key else None,
                    created_time=_iso(item.get(created_key)) if created_key else None,
                    modified_time=_iso(item.get(modified_key)) if modified_key else None,
                    metadata=metadata,
                    source_operation=f"{client_name}.{operation}",
                )
            )
