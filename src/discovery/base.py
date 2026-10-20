"""Discovery adapter framework: base class, result types, adapter registry."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Iterable

from ..config import ScanConfig
from ..errors import OperationError


@dataclass
class DiscoveredResource:
    """Normalized pre-classification representation of one AWS resource.

    Adapters emit these; the registry builder converts them into
    RegistryRecord entries with provenance.
    """

    service: str
    resource_type: str
    resource_id: str
    region: str | None = None
    arn: str | None = None
    name: str | None = None
    description: str | None = None
    status: str | None = None
    created_time: str | None = None
    modified_time: str | None = None
    tags: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    # Optional explicit AI linkage for non-AI-native services (e.g. Lambda -> Bedrock).
    ai_association: dict[str, Any] | None = None
    source_operation: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "service": self.service,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "region": self.region,
            "arn": self.arn,
            "name": self.name,
            "description": self.description,
            "status": self.status,
            "created_time": self.created_time,
            "modified_time": self.modified_time,
            "tags": self.tags,
            "metadata": self.metadata,
            "ai_association": self.ai_association,
            "source_operation": self.source_operation,
        }


@dataclass
class AdapterResult:
    resources: list[DiscoveredResource] = field(default_factory=list)
    errors: list[OperationError] = field(default_factory=list)
    operations_attempted: list[str] = field(default_factory=list)
    operations_succeeded: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


class BaseAdapter(ABC):
    """One AWS service discovery adapter.

    Contract:
    - Read-only API calls only; paginators wherever supported.
    - Failures are recorded as OperationError, never raised, so a scan can
      continue with partial results.
    - ``discover`` must be safe to call multiple times (idempotent).
    """

    #: Adapter name used by --services filter and docs.
    name: str = "base"
    #: AWS service client names this adapter uses.
    service: str = "base"
    #: Regions this adapter works in; None = all.
    supported_regions: frozenset[str] | None = None
    #: True when the service is only available in a subset of regions.
    global_service: bool = False

    def __init__(self, config: ScanConfig) -> None:
        self.config = config

    @abstractmethod
    def discover(self, session, region: str) -> AdapterResult:
        """Perform read-only discovery in ``region`` and return results."""

    @abstractmethod
    def api_operations(self) -> list[tuple[str, str]]:
        """List of (client_name, operation_name) used by this adapter."""

    @abstractmethod
    def required_permissions(self) -> list[str]:
        """IAM actions required for this adapter to work fully."""

    @abstractmethod
    def documented_blind_spots(self) -> list[str]:
        """Known limitations / what this adapter cannot see."""

    def supports_region(self, region: str) -> bool:
        if self.supported_regions is None:
            return True
        return region in self.supported_regions


class AdapterRegistry:
    """Registry of available discovery adapters; extend without editing the scanner."""

    def __init__(self) -> None:
        self._adapters: dict[str, type[BaseAdapter]] = {}

    def register(self, adapter_cls: type[BaseAdapter]) -> type[BaseAdapter]:
        self._adapters[adapter_cls.name] = adapter_cls
        return adapter_cls

    def names(self) -> list[str]:
        return sorted(self._adapters)

    def get(self, name: str) -> type[BaseAdapter]:
        if name not in self._adapters:
            raise KeyError(f"Unknown adapter: {name}. Available: {self.names()}")
        return self._adapters[name]

    def build(self, config: ScanConfig, names: Iterable[str] | None = None) -> list[BaseAdapter]:
        selected = list(names) if names else self.names()
        adapters = []
        for name in selected:
            adapters.append(self.get(name)(config))
        return adapters


# Global registry populated by discovery adapters at import time.
ADAPTERS = AdapterRegistry()


def register_adapter(cls: type[BaseAdapter]) -> type[BaseAdapter]:
    return ADAPTERS.register(cls)
