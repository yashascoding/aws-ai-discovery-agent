"""Offline test kit: fake boto3 sessions backed by synthetic AWS fixtures.

Used by `python -m src.cli test-fixtures` and unit tests. No network calls,
no credentials, no fabricated "live" results: everything here is explicitly
synthetic and labelled as such in outputs.
"""
from __future__ import annotations

import copy
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable

from botocore.exceptions import ClientError

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "examples" / "fixtures"


# --------------------------------------------------------------------------- #
# Fixture loading
# --------------------------------------------------------------------------- #
def load_fixture(name: str) -> Any:
    path = FIXTURES_DIR / name
    if not path.exists():
        raise FileNotFoundError(f"Fixture not found: {path}")
    return json.loads(path.read_text())


def resolve_time_offsets(value: Any, now: datetime | None = None) -> Any:
    """Replace {"__offset_days__": -5} markers with absolute UTC ISO timestamps.

    A {"__json_string__": {...}} wrapper serialises the inner structure to a
    JSON string after resolution (used for CloudTrailEvent payloads).
    """
    now = now or datetime.now(timezone.utc)
    if isinstance(value, dict):
        if set(value) == {"__offset_days__"}:
            delta = timedelta(days=float(value["__offset_days__"]))
            return (now + delta).isoformat()
        if set(value) == {"__json_string__"}:
            inner = resolve_time_offsets(value["__json_string__"], now)
            return json.dumps(inner, default=str)
        return {k: resolve_time_offsets(v, now) for k, v in value.items()}
    if isinstance(value, list):
        return [resolve_time_offsets(v, now) for v in value]
    return value


def load_resolved(name: str, now: datetime | None = None) -> Any:
    return resolve_time_offsets(load_fixture(name), now)


# --------------------------------------------------------------------------- #
# Fakes
# --------------------------------------------------------------------------- #
class _OpModel:
    def __init__(self) -> None:
        self.input_shape = SimpleNamespace(members={})
        self.output_shape = SimpleNamespace(members={})


class _ServiceModel:
    def __init__(self, service_name: str) -> None:
        self.service_name = service_name

    def operation_model(self, _name: str) -> _OpModel:
        return _OpModel()


class _Paginator:
    def __init__(self, pages: list[dict[str, Any]]) -> None:
        self._pages = pages

    def paginate(self, **_kwargs: Any):
        for page in self._pages:
            yield copy.deepcopy(page)


class FakeClient:
    """Minimal boto3-client stand-in returning canned pages per operation.

    - ``pages``: {operation_name_lower: [page1, page2, ...]}
    - ``errors``: {operation_name_lower: ClientError} raised on call
    - paged operations (listed in ``paginated``) serve pages via paginator;
      others serve the first page directly.
    """

    def __init__(
        self,
        service_name: str,
        pages: dict[str, list[dict[str, Any]]] | None = None,
        errors: dict[str, Exception] | None = None,
        paginated: set[str] | None = None,
    ) -> None:
        self._service_name = service_name
        self._pages = pages or {}
        self._errors = errors or {}
        self._paginated = paginated or set()
        self.meta = SimpleNamespace(service_model=_ServiceModel(service_name))

    @property
    def _region(self) -> str | None:
        return getattr(self, "_current_region", None)

    def can_paginate(self, operation: str) -> bool:
        return operation.lower() in self._paginated

    def get_paginator(self, operation: str) -> _Paginator:
        return _Paginator(self._pages.get(operation.lower(), []))

    def __getattr__(self, operation: str) -> Callable[..., dict[str, Any]]:
        if operation.startswith("_"):
            raise AttributeError(operation)

        def call(**kwargs: Any) -> dict[str, Any]:
            key = operation.lower()
            if key in self._errors:
                raise self._errors[key]
            pages = self._pages.get(key)
            if not pages:
                raise ClientError(
                    {
                        "Error": {
                            "Code": "ResourceNotFoundException",
                            "Message": f"Synthetic error: no fixture for {self._service_name}.{operation}",
                        },
                        "ResponseMetadata": {},
                    },
                    operation,
                )
            if key in self._paginated:
                # Manual-token path callers expect the first page.
                return copy.deepcopy(pages[0])
            return copy.deepcopy(pages[0])

        return call


def access_denied(operation: str, service: str = "bedrock") -> ClientError:
    return ClientError(
        {
            "Error": {
                "Code": "AccessDeniedException",
                "Message": f"User is not authorized to perform: {operation} on resource",
            },
            "ResponseMetadata": {"HTTPStatusCode": 403},
        },
        operation,
    )


class FakeSession:
    """boto3.Session stand-in serving per-service FakeClients per region."""

    def __init__(
        self,
        fixture_map: dict[str, dict[str, Any]],
        region_name: str | None = None,
        errors: dict[tuple[str, str], Exception] | None = None,
        paginated: dict[str, set[str]] | None = None,
    ) -> None:
        """fixture_map: {service: {"operations": {op: [pages]}, "errors": {op: exc}}}

        ``errors`` maps (service, region) -> exception applied to every
        operation of that service in that region (used for permission tests).
        """
        self.region_name = region_name
        self._fixture_map = fixture_map
        self._errors = errors or {}
        self._paginated = paginated or {}

    def get_credentials(self):  # parity with boto3.Session; never returns secrets
        return None

    def client(self, service_name: str, region_name: str | None = None, **_kw: Any) -> "FakeClient":
        region = region_name or self.region_name or "ap-south-1"
        spec = self._fixture_map.get(service_name, {})
        pages = spec.get("operations", {})
        errors = dict(spec.get("errors", {}))
        regional = self._errors.get((service_name, region))
        if regional is not None:
            errors.update({op: regional for op in pages})
        return FakeClient(
            service_name,
            pages=pages,
            errors=errors,
            paginated=self._paginated.get(service_name, set()),
        )


def fixture_session(
    fixture_map: dict[str, dict[str, Any]] | None = None,
    region_name: str = "ap-south-1",
    errors: dict[tuple[str, str], Exception] | None = None,
    paginated: dict[str, set[str]] | None = None,
) -> FakeSession:
    if fixture_map is None:
        fixture_map = default_fixture_map()
    if paginated is None:
        paginated = {"sagemaker": {"list_models", "list_endpoints"}}
    return FakeSession(
        fixture_map, region_name=region_name, errors=errors, paginated=paginated
    )


def default_fixture_map() -> dict[str, dict[str, Any]]:
    """Canonical synthetic fixture set used by the offline suite."""
    return {
        "sts": {"operations": {"get_caller_identity": [{
            "Account": "111122223333",
            "Arn": "arn:aws:iam::111122223333:role/SyntheticDiscoveryRole",
            "UserId": "AROAEXAMPLE:SyntheticSession",
        }]}},
        "bedrock": {
            "operations": {
                "list_foundation_models": load_resolved("bedrock_catalog.json"),
                "list_inference_profiles": load_resolved("bedrock_inference_profiles.json"),
                "list_provisioned_model_throughputs": [
                    {"provisionedModelSummaries": []}
                ],
                "list_custom_models": [{"modelSummaries": []}],
                "list_guardrails": load_resolved("bedrock_guardrails.json"),
            },
        },
        "bedrock-agent": {
            "operations": {
                "list_agents": load_resolved("bedrock_agents.json"),
                "list_agent_aliases": load_resolved("bedrock_agent_aliases.json"),
                "list_knowledge_bases": load_resolved("bedrock_knowledge_bases.json"),
                "list_prompts": [{"promptSummaries": []}],
                "list_flows": [{"flowSummaries": []}],
            },
        },
        "sagemaker": {
            "operations": {
                "list_models": load_resolved("sagemaker_models_pages.json"),
                "list_endpoints": load_resolved("sagemaker_endpoints.json"),
                "list_endpoint_configs": [{"EndpointConfigs": []}],
                "list_training_jobs": load_resolved("sagemaker_training_jobs.json"),
                "list_processing_jobs": [{"ProcessingJobSummaries": []}],
                "list_pipelines": [{"PipelineSummaries": {"Pipelines": []}}],
                "list_model_packages": [{"ModelPackageSummaryList": []}],
                "list_inference_components": [{"InferenceComponentSummaries": []}],
                "list_experiments": [{"ExperimentSummaries": []}],
                "list_pipeline_executions": [{"PipelineExecutionSummaries": []}],
            },
        },
        "glue": load_resolved("glue_fixture_map.json"),
        "lambda": {
            "operations": {"list_functions": load_resolved("lambda_functions.json")},
        },
        "resourcegroupstaggingapi": {
            "operations": {"get_resources": load_resolved("tag_mappings.json")},
        },
        "cloudtrail": {
            "operations": {"lookup_events": load_resolved("cloudtrail_events.json")},
        },
        "ec2": {"operations": {"describe_regions": [{"Regions": [
            {"RegionName": "ap-south-1"}, {"RegionName": "us-east-1"},
        ]}]}},
    }


def empty_fixture_map() -> dict[str, dict[str, Any]]:
    """Empty-environment fixtures: every API succeeds with zero results."""
    return {
        "sts": {"operations": {"get_caller_identity": [{
            "Account": "111122223333",
            "Arn": "arn:aws:iam::111122223333:role/SyntheticDiscoveryRole",
            "UserId": "AROAEXAMPLE:SyntheticSession",
        }]}},
        "bedrock": {"operations": {
            "list_foundation_models": [{"modelSummaries": []}],
            "list_inference_profiles": [{"inferenceSummaries": []}],
            "list_provisioned_model_throughputs": [{"provisionedModelSummaries": []}],
            "list_custom_models": [{"modelSummaries": []}],
            "list_guardrails": [{"guardrails": []}],
        }},
        "bedrock-agent": {"operations": {
            "list_agents": [{"agentSummaries": []}],
            "list_agent_aliases": [{"agentAliasSummaries": []}],
            "list_knowledge_bases": [{"knowledgeBaseSummaries": []}],
            "list_prompts": [{"promptSummaries": []}],
            "list_flows": [{"flowSummaries": []}],
        }},
        "sagemaker": {"operations": {
            "list_models": [{"Models": []}],
            "list_endpoints": [{"Endpoints": []}],
            "list_endpoint_configs": [{"EndpointConfigs": []}],
            "list_training_jobs": [{"TrainingJobSummaries": []}],
            "list_processing_jobs": [{"ProcessingJobSummaries": []}],
            "list_pipelines": [{"PipelineSummaries": {"Pipelines": []}}],
            "list_model_packages": [{"ModelPackageSummaryList": []}],
            "list_inference_components": [{"InferenceComponentSummaries": []}],
            "list_experiments": [{"ExperimentSummaries": []}],
            "list_pipeline_executions": [{"PipelineExecutionSummaries": []}],
        }},
        "glue": {"operations": {"list_ml_transforms": [{"Transforms": []}]}},
        "lambda": {"operations": {"list_functions": [{"Functions": []}]}},
        "resourcegroupstaggingapi": {"operations": {"get_resources": [{"ResourceTagMappingList": []}]}},
        "cloudtrail": {"operations": {"lookup_events": [{"Events": []}]}},
        "ec2": {"operations": {"describe_regions": [{"Regions": [
            {"RegionName": "ap-south-1"}, {"RegionName": "us-east-1"},
        ]}]}},
    }
