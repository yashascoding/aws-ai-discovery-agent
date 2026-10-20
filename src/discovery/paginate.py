"""Pagination helper that works with paginated, token-based, and single-call APIs."""
from __future__ import annotations

from typing import Any, Callable


def collect_pages(
    client,
    operation: str,
    result_key: str | None = None,
    kwargs: dict[str, Any] | None = None,
    max_pages: int = 100,
) -> list[Any]:
    """Return all items for an operation across pages.

    Strategy:
    1. If the operation supports paginators, use botocore's paginator.
    2. Else, if the request accepts ``nextToken``/``NextToken`` and the
       response returns one, follow it manually.
    3. Else, perform a single call.

    ``result_key`` may be a dotted path into the response (e.g.
    ``modelSummaries`` or ``PipelineSummaries.Pipelines``). Items may be
    structures (dicts) or plain strings (e.g. Glue TransformIds).
    """
    kwargs = dict(kwargs or {})
    if client.can_paginate(operation):
        paginator = client.get_paginator(operation)
        items: list[dict[str, Any]] = []
        for page in paginator.paginate(**kwargs):
            items.extend(_extract(page, result_key))
        return items

    # Manual token loop for non-paginated operations that still page.
    try:
        op_model = client.meta.service_model.operation_model(
            _operation_name(client, operation)
        )
        input_tokens = [
            t for t in ("nextToken", "NextToken") if t in op_model.input_shape.members
        ]
        output_tokens = [
            t
            for t in ("nextToken", "NextToken", "NextMarker", "nextMarker")
            if op_model.output_shape and t in op_model.output_shape.members
        ]
    except Exception:  # stub clients or unknown operations -> single call
        input_tokens, output_tokens = [], []
    if not input_tokens or not output_tokens:
        response = getattr(client, operation)(**kwargs)
        return _extract(response, result_key)

    token_param = input_tokens[0]
    token_output = output_tokens[0]
    items = []
    seen_tokens: set[str] = set()
    for _ in range(max_pages):
        response = getattr(client, operation)(**kwargs)
        items.extend(_extract(response, result_key))
        token = response.get(token_output)
        if not token or token in seen_tokens:
            break
        seen_tokens.add(token)
        kwargs[token_param] = token
    return items


def call_single(client, operation: str, kwargs: dict[str, Any] | None = None) -> dict[str, Any]:
    return getattr(client, operation)(**(kwargs or {}))


def _extract(response: dict[str, Any], result_key: str | None) -> list[Any]:
    if result_key is None:
        return [response]
    value: Any = response
    for part in result_key.split("."):
        if not isinstance(value, dict):
            return []
        value = value.get(part)
    if value is None:
        return []
    if isinstance(value, list):
        return list(value)
    return [value]


def _operation_name(client, operation: str) -> str:
    for name in client.meta.service_model.operation_names:
        if name.lower() == operation.lower():
            return name
    return operation
