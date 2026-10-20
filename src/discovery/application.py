"""Application-level AI association adapter (Lambda functions).

Test D: establish *inferred* AI association from configuration evidence and
keep it distinct from direct invocation evidence.

An AI association is asserted only when defensible evidence exists:
- an environment variable KEY (name only, never the value) referencing a known
  AI/ML SDK or service (bedrock, sagemaker, anthropic, openai, ...),
- a Lambda layer ARN referencing bedrock/sagemaker utilities, or
- description/tags mentioning model invocation.

A match yields DiscoveredResource.ai_association with ``confidence='low'`` and
``basis='static_configuration'`` so classification yields POTENTIAL_AI_USAGE —
static configuration never proves runtime AI usage.

Blind spots
-----------
- Code packaged inline or in S3 is not executed or inspected.
- The same function may call AI services only under certain events.
- Association detection depends on keyword coverage (documented keyword list).
"""
from __future__ import annotations

import re
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from ..config import ScanConfig
from ..errors import OperationError, classify_exception, error_message, get_logger, with_retry
from .base import AdapterResult, BaseAdapter, DiscoveredResource, register_adapter
from .paginate import collect_pages

logger = get_logger(__name__)

# Keyword list is evidence basis, not a detection guarantee.
AI_INDICATOR_PATTERNS = [
    r"bedrock",
    r"sagemaker",
    r"anthropic",
    r"claude",
    r"openai",
    r"gpt",
    r"titan-embed",
    r"titan-text",
    r"ai21",
    r"cohere",
    r"stability-ai",
    r"mistral",
    r"llama",
    r"invoke_model",
    r"converse\b",
    r"embedding",
    r"\brag\b",
    r"\bllm\b",
    r"generative[-_ ]?ai",
    r"gen[-_]?ai",
]
AI_INDICATOR_RE = re.compile("|".join(AI_INDICATOR_PATTERNS), re.IGNORECASE)

MAX_MATCHES_PER_FUNCTION = 10


def find_ai_indicators(function: dict[str, Any]) -> list[dict[str, str]]:
    """Return evidence items describing *why* a function looks AI-related.

    Only key names / layer names / description snippets are returned; secret
    environment variable VALUES are never copied.
    """
    matches: list[dict[str, str]] = []

    code = function.get("Code") or {}
    for key in (function.get("Environment") or {}).get("Variables", {}) or {}:
        if AI_INDICATOR_RE.search(key):
            matches.append({"basis": "environment_variable_key", "detail": key})
    layers = function.get("Layers") or code.get("Layers") or []
    for layer_arn in layers:
        arn = layer_arn if isinstance(layer_arn, str) else str(
            layer_arn.get("Arn", layer_arn) if isinstance(layer_arn, dict) else layer_arn
        )
        if AI_INDICATOR_RE.search(arn):
            matches.append({"basis": "layer_arn", "detail": arn.split(":")[-1]})

    description = function.get("Description") or ""
    if description and AI_INDICATOR_RE.search(description):
        snippet = description[:120]
        matches.append({"basis": "description", "detail": snippet})
    return matches[:MAX_MATCHES_PER_FUNCTION]


@register_adapter
class ApplicationAdapter(BaseAdapter):
    """Defensible AI association for generic application resources."""

    name = "application"
    service = "lambda"

    def api_operations(self) -> list[tuple[str, str]]:
        return [("lambda", "ListFunctions"), ("lambda", "ListTags")]

    def required_permissions(self) -> list[str]:
        return ["lambda:ListFunctions", "lambda:ListTags"]

    def documented_blind_spots(self) -> list[str]:
        return [
            "Static configuration is not runtime proof: a function with AI "
            "environment keys may never call AI services, and a function "
            "without them may still do so.",
            "Function code is never downloaded or executed.",
            "ECS/EKS/EC2 application workloads are not scanned in this POC; "
            "adding them requires analogous defensible association rules.",
        ]

    def discover(self, session, region: str) -> AdapterResult:
        result = AdapterResult()
        operation = "list_functions"
        result.operations_attempted.append(f"lambda.{operation}")
        try:
            client = session.client("lambda", region_name=region)
            functions = with_retry(
                lambda: collect_pages(client, operation, "Functions"),
                max_retries=self.config.max_retries,
                base_delay=self.config.retry_base_delay,
                logger=logger,
                context="lambda.list_functions",
            )
            result.operations_succeeded.append(f"lambda.{operation}")
        except (ClientError, BotoCoreError) as exc:
            result.errors.append(
                OperationError(
                    service=self.service,
                    operation="ListFunctions",
                    region=region,
                    error_type=classify_exception(exc),
                    message=error_message(exc),
                    scan_id=self.config.scan_id,
                )
            )
            return result

        associated = 0
        for fn in functions:
            indicators = find_ai_indicators(fn)
            if not indicators:
                # Negative control (Test F): ordinary functions are skipped,
                # not registered as AI systems.
                continue
            associated += 1
            arn = fn.get("FunctionArn")
            result.resources.append(
                DiscoveredResource(
                    service="lambda",
                    resource_type="lambda_function",
                    resource_id=fn.get("FunctionName") or "unknown-function",
                    region=region,
                    arn=arn,
                    name=fn.get("FunctionName"),
                    description=(fn.get("Description") or None),
                    status=None,
                    created_time=str(fn.get("LastModified")) if fn.get("LastModified") else None,
                    metadata={"runtime": fn.get("Runtime"), "memory_mb": fn.get("MemorySize")},
                    ai_association={
                        "confidence": "low",
                        "basis": "static_configuration",
                        "indicators": indicators,
                        "note": (
                            "Inferred from configuration metadata only; static "
                            "configuration does not prove runtime AI usage."
                        ),
                    },
                    source_operation="lambda.ListFunctions",
                )
            )
        result.notes.append(
            f"scanned {len(functions)} lambda functions; {associated} carried "
            "defensible AI-association evidence"
        )
        return result
