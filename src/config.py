"""Scan configuration for the AWS AI discovery agent.

All values are read from environment variables or CLI flags. No secrets are
stored in this module.
"""
from __future__ import annotations

import os
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

DEFAULT_REGION = "ap-south-1"
DEFAULT_ACTIVITY_DAYS = 30
DEFAULT_REPORT_DIR = "reports"

# Staleness policy (documented): an otherwise configured AI resource with no
# observable activity evidence in the observation window AND a creation/last
# modified timestamp older than this many days is classified INACTIVE_OR_STALE.
STALE_AFTER_DAYS = 90

# Services whose resources are, by construction, AI/ML resources.
AI_NATIVE_SERVICES = frozenset(
    {
        "bedrock",
        "bedrock-agent",
        "bedrock-agent-runtime",
        "sagemaker",
        "sagemaker-runtime",
        "glue",
    }
)

# Tag keys treated as governance metadata when present.
GOVERNANCE_TAG_KEYS = (
    "AI-System",
    "AI-System-Owner",
    "Owner",
    "BusinessPurpose",
    "Environment",
    "DataClassification",
    "HumanOversight",
    "RiskAssessment",
)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_scan_id() -> str:
    return f"scan-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}"


def parse_regions(spec: str | None) -> list[str]:
    """Parse a comma separated region list; empty/None means default region."""
    if not spec:
        return [DEFAULT_REGION]
    regions = [r.strip().lower() for r in spec.split(",") if r.strip()]
    for r in regions:
        if not re.fullmatch(r"[a-z]{2}(-[a-z]+)+-\d", r):
            raise ValueError(f"Invalid AWS Region name: {r!r}")
    seen: set[str] = set()
    ordered = []
    for r in regions:
        if r not in seen:
            seen.add(r)
            ordered.append(r)
    return ordered or [DEFAULT_REGION]


@dataclass
class ScanConfig:
    """Immutable-ish configuration for a single scan run."""

    profile: str | None = field(
        default_factory=lambda: os.environ.get("AWS_PROFILE") or None
    )
    role_arn: str | None = None
    external_id: str | None = None
    regions: list[str] = field(default_factory=lambda: [DEFAULT_REGION])
    activity_days: int = DEFAULT_ACTIVITY_DAYS
    report_dir: str = DEFAULT_REPORT_DIR
    scan_id: str = field(default_factory=new_scan_id)
    services: list[str] | None = None  # None = all enabled adapters
    # Safety switches: read-only by default.
    enable_live_tests: bool = False
    enable_model_invocation: bool = False
    max_retries: int = 3
    retry_base_delay: float = 0.5
    request_timeout_seconds: int = 30
    # Optional evidence sources (off by default; never created automatically).
    cloudtrail_trail_name: str | None = None
    cloudtrail_lake_query_id: str | None = None
    # Usage/cost enrichment. Collections are read-only and opt-out-able.
    enable_usage_collection: bool = True
    enable_cost_collection: bool = True
    usage_lookback_days: int = 14
    cost_lookback_days: int = 30
    max_metrics_per_namespace: int = 25
    max_datapoints_per_metric: int = 60
    cost_region: str = "us-east-1"
    enable_resource_level_costs: bool = False
    cur_bucket: str | None = None
    cur_prefix: str | None = None

    @property
    def observation_start(self) -> datetime:
        from datetime import timedelta

        return utcnow() - timedelta(days=self.activity_days)

    def describe(self) -> dict:
        return {
            "profile": self.profile,
            "role_arn": self.role_arn,
            "regions": list(self.regions),
            "activity_days": self.activity_days,
            "report_dir": self.report_dir,
            "scan_id": self.scan_id,
            "services": self.services or "all",
            "observation_start": self.observation_start.isoformat(),
            "usage_collection": self.enable_usage_collection,
            "cost_collection": self.enable_cost_collection,
            "usage_lookback_days": self.usage_lookback_days,
            "cost_lookback_days": self.cost_lookback_days,
            "read_only": True,
        }
