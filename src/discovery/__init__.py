"""Discovery subpackage: AWS service adapters.

Importing this package registers all built-in adapters.
"""
from .base import ADAPTERS, AdapterRegistry, AdapterResult, BaseAdapter, DiscoveredResource, register_adapter
from . import bedrock as _bedrock  # noqa: F401  (registers bedrock adapter)
from . import sagemaker as _sagemaker  # noqa: F401
from . import tagging as _tagging  # noqa: F401
from . import glue as _glue  # noqa: F401
from . import application as _application  # noqa: F401

__all__ = [
    "ADAPTERS",
    "AdapterRegistry",
    "AdapterResult",
    "BaseAdapter",
    "DiscoveredResource",
    "register_adapter",
]
