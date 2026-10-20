"""Region enumeration and scan-coverage reporting (read-only)."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from .config import ScanConfig
from .errors import OperationError, classify_exception, error_message, get_logger, with_retry

logger = get_logger(__name__)


@dataclass
class RegionCoverage:
    region: str
    status: str  # scanned | skipped | unreachable | permission_error
    services_attempted: list[str] = field(default_factory=list)
    services_succeeded: list[str] = field(default_factory=list)
    services_failed: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "region": self.region,
            "status": self.status,
            "services_attempted": sorted(self.services_attempted),
            "services_succeeded": sorted(self.services_succeeded),
            "services_failed": sorted(self.services_failed),
            "notes": self.notes,
        }


def list_enabled_regions(session, config: ScanConfig) -> tuple[list[str], list[OperationError]]:
    """Return account-enabled Regions via EC2 DescribeRegions (all Regions=False).

    Falls back to the configured region list if the call fails, recording the error.
    """
    errors: list[OperationError] = []
    try:
        client = session.client("ec2", region_name=config.regions[0])
        response = with_retry(
            lambda: client.describe_regions(AllRegions=False),
            max_retries=config.max_retries,
            base_delay=config.retry_base_delay,
            logger=logger,
            context="ec2.describe_regions",
        )
        regions = sorted(r["RegionName"] for r in response.get("Regions", []))
        if not regions:
            regions = list(config.regions)
        return regions, errors
    except (ClientError, BotoCoreError) as exc:
        errors.append(
            OperationError(
                service="ec2",
                operation="DescribeRegions",
                region=config.regions[0],
                error_type=classify_exception(exc),
                message=error_message(exc),
                scan_id=config.scan_id,
            )
        )
        logger.warning("DescribeRegions failed; falling back to configured regions")
        return list(config.regions), errors


def resolve_scan_regions(session, config: ScanConfig) -> tuple[list[str], list[OperationError], list[OperationError]]:
    """Resolve which Regions to scan.

    Returns (regions_to_scan, region_errors, not_enabled_errors).
    Configured regions not enabled in the account are reported, not scanned.
    """
    if len(config.regions) == 1:
        return list(config.regions), [], []

    enabled, errors = list_enabled_regions(session, config)
    enabled_set = set(enabled)
    to_scan: list[str] = []
    not_enabled: list[OperationError] = []
    for region in config.regions:
        if region in enabled_set:
            to_scan.append(region)
        else:
            not_enabled.append(
                OperationError(
                    service="ec2",
                    operation="DescribeRegions",
                    region=region,
                    error_type="not_found",
                    message=f"Region {region} is not enabled for this account",
                    scan_id=config.scan_id,
                )
            )
    return to_scan or list(config.regions), errors, not_enabled
