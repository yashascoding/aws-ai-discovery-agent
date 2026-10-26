"""Shared error types, throttling-aware retry, and structured logging."""
from __future__ import annotations

import json
import logging
import random
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, TypeVar

from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    ConnectionError as BotoConnectionError,
    ConnectTimeoutError,
    EndpointConnectionError,
    ReadTimeoutError,
)

T = TypeVar("T")

RETRYABLE_CODES = {
    "Throttling",
    "ThrottlingException",
    "TooManyRequestsException",
    "RequestLimitExceeded",
    "ProvisionedThroughputExceededException",
    "ServiceUnavailable",
    "InternalError",
    "InternalFailure",
    "SlowDown",
    "RequestTimeout",
}
ACCESS_DENIED_CODES = {
    "AccessDenied",
    "AccessDeniedException",
    "UnauthorizedOperation",
    "ForbiddenException",
}
NOT_CONFIGURED_CODES = {
    "OptInRequired",
    "SubscriptionRequiredException",
    "SubscriptionRequired",
    "ServiceNotSubscribed",
}
NOT_AVAILABLE_CODES = {
    "UnrecognizedClientException",
    "InvalidClientTokenId",
    "UnknownOperationException",
}


class DiscoveryError(Exception):
    """Base error for discovery operations."""


@dataclass
class OperationError:
    """Record of a failed or unsupported API operation during a scan."""

    service: str
    operation: str
    region: str | None
    error_type: str  # access_denied | not_configured | not_available | throttled | unsupported | not_found | timeout | sdk_error | other
    message: str
    scan_id: str | None = None
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def as_dict(self) -> dict[str, Any]:
        return {
            "service": self.service,
            "operation": self.operation,
            "region": self.region,
            "error_type": self.error_type,
            "message": self.message,
            "scan_id": self.scan_id,
            "timestamp": self.timestamp,
        }


def classify_exception(exc: Exception) -> str:
    if isinstance(exc, ClientError):
        code = exc.response.get("Error", {}).get("Code", "")
        if code in ACCESS_DENIED_CODES or "AccessDenied" in code:
            return "access_denied"
        if code in NOT_CONFIGURED_CODES:
            return "not_configured"
        if code in NOT_AVAILABLE_CODES:
            return "not_available"
        if code in RETRYABLE_CODES or "Throttl" in code:
            return "throttled"
        if code in {"ResourceNotFoundException", "NotFoundException"}:
            return "not_found"
        if code in {"ValidationException", "InvalidRequestException"}:
            return "unsupported"
        return "other"
    if isinstance(exc, EndpointConnectionError):
        return "not_available"
    if isinstance(exc, (ConnectTimeoutError, ReadTimeoutError, BotoConnectionError)):
        return "timeout"
    if isinstance(exc, BotoCoreError):
        return "sdk_error"
    return "other"


def error_message(exc: Exception) -> str:
    if isinstance(exc, ClientError):
        err = exc.response.get("Error", {})
        return f"{err.get('Code', 'Unknown')}: {err.get('Message', str(exc))}"
    return f"{type(exc).__name__}: {exc}"


def with_retry(
    fn: Callable[[], T],
    *,
    max_retries: int = 3,
    base_delay: float = 0.5,
    logger: logging.Logger | None = None,
    context: str = "",
) -> T:
    """Call fn with bounded exponential backoff on throttling/transient errors."""
    attempt = 0
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in RETRYABLE_CODES and attempt < max_retries:
                delay = base_delay * (2**attempt) + random.uniform(0, base_delay)
                if logger:
                    logger.warning(
                        "retrying after throttling",
                        extra={"context": context, "attempt": attempt + 1, "delay": round(delay, 2)},
                    )
                time.sleep(delay)
                attempt += 1
                continue
            raise
        except (ConnectTimeoutError, ReadTimeoutError) as exc:
            if attempt < max_retries:
                delay = base_delay * (2**attempt)
                if logger:
                    logger.warning(
                        "retrying after transient network error",
                        extra={"context": context, "attempt": attempt + 1},
                    )
                time.sleep(delay)
                attempt += 1
                continue
            raise


class JsonLogFormatter(logging.Formatter):
    """Emit one JSON object per log line for machine-readable logs."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key in ("context", "attempt", "delay", "region", "service", "operation"):
            if hasattr(record, key):
                payload[key] = getattr(record, key)
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def get_logger(name: str = "ai_discovery", level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(JsonLogFormatter())
        logger.addHandler(handler)
        logger.setLevel(level)
        logger.propagate = False
    return logger
