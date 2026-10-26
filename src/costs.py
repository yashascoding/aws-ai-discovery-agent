"""AWS cost collection through Cost Explorer and optional CUR CSV exports.

Cost Explorer is the authoritative source for reported billed cost. CUR is
optional because it requires an operator-created report and S3 access. The
collector never estimates cost from resource names, instance counts, or model
catalogue entries.
"""
from __future__ import annotations

import csv
import gzip
import hashlib
import io
import json
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, Iterable

from botocore.exceptions import BotoCoreError, ClientError

from .capabilities import ServiceCapability
from .config import ScanConfig, utcnow
from .errors import OperationError, classify_exception, error_message, get_logger, with_retry
from .registry import RegistryRecord

logger = get_logger(__name__)

MAX_CE_PAGES = 40
MAX_CUR_FILES = 3
MAX_CUR_BYTES = 64 * 1024 * 1024
MAX_CUR_ROWS = 250_000


@dataclass
class CostRecord:
    cost_record_id: str
    source: str
    period_start: str
    period_end: str | None
    granularity: str
    service_name: str
    capability_keys: list[str] = field(default_factory=list)
    category: str | None = None
    region: str | None = None
    usage_type: str | None = None
    usage_account_id: str | None = None
    amount: float | None = None
    usage_quantity: float | None = None
    currency: str = "USD"
    record_type: str = "Usage"
    estimated: bool | None = None
    attribution_confidence: str = "service_level"
    resource_record_id: str | None = None
    resource_id: str | None = None
    data_through: str | None = None
    limitation: str | None = None
    observed_at: str = field(default_factory=lambda: utcnow().isoformat())

    def as_dict(self) -> dict[str, Any]:
        return {
            "cost_record_id": self.cost_record_id,
            "source": self.source,
            "period_start": self.period_start,
            "period_end": self.period_end,
            "granularity": self.granularity,
            "service_name": self.service_name,
            "capability_keys": self.capability_keys,
            "category": self.category,
            "region": self.region,
            "usage_type": self.usage_type,
            "usage_account_id": self.usage_account_id,
            "amount": self.amount,
            "usage_quantity": self.usage_quantity,
            "currency": self.currency,
            "record_type": self.record_type,
            "estimated": self.estimated,
            "attribution_confidence": self.attribution_confidence,
            "resource_record_id": self.resource_record_id,
            "resource_id": self.resource_id,
            "data_through": self.data_through,
            "limitation": self.limitation,
            "observed_at": self.observed_at,
        }


@dataclass
class CostCollectionResult:
    records: list[CostRecord] = field(default_factory=list)
    status: str = "not_configured"
    reason: str | None = None
    data_through: str | None = None
    mapped_amount: float = 0.0
    unattributed_amount: float = 0.0
    currency: str = "USD"
    notes: list[str] = field(default_factory=list)
    observed_at: str = field(default_factory=lambda: utcnow().isoformat())


def _cid(*parts: Any) -> str:
    raw = "|".join("" if p is None else str(p) for p in parts)
    return "cost-" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _norm(value: str | None) -> str:
    return "".join(ch for ch in (value or "").lower() if ch.isalnum())


def _capability_map(capabilities: Iterable[ServiceCapability]) -> dict[str, list[ServiceCapability]]:
    out: dict[str, list[ServiceCapability]] = {}
    for cap in capabilities:
        for name in cap.cost_service_names:
            out.setdefault(_norm(name), []).append(cap)
    return out


def _capabilities_for_service(
    service_name: str, capabilities: list[ServiceCapability]
) -> list[ServiceCapability]:
    needle = _norm(service_name)
    exact = [c for c in capabilities if any(_norm(n) == needle for n in c.cost_service_names)]
    if exact:
        return exact
    # CUR product codes are often concatenated forms of the display names.
    return [
        c for c in capabilities
        if any(needle.startswith(_norm(n)) or _norm(n).startswith(needle) for n in c.cost_service_names)
    ]


def _decode_amount(value: Any) -> float | None:
    try:
        return float(Decimal(str(value)))
    except (InvalidOperation, TypeError, ValueError):
        return None


def _record_ids_by_resource(records: list[RegistryRecord]) -> dict[str, RegistryRecord]:
    out: dict[str, RegistryRecord] = {}
    for rec in records:
        for value in (rec.resource_arn, rec.resource_id):
            if value:
                out.setdefault(str(value).lower(), rec)
    return out


def _cost_record(
    *, source: str, period_start: str, period_end: str | None, granularity: str,
    service_name: str, capabilities: list[ServiceCapability], category: str | None,
    region: str | None, amount: float | None, currency: str, record_type: str,
    estimated: bool | None, data_through: str | None, usage_type: str | None = None,
    usage_account_id: str | None = None, usage_quantity: float | None = None,
    resource_record_id: str | None = None, resource_id: str | None = None,
    attribution_confidence: str = "service_level", limitation: str | None = None,
) -> CostRecord:
    return CostRecord(
        cost_record_id=_cid(source, period_start, period_end, service_name, region, usage_type, resource_id, record_type),
        source=source,
        period_start=period_start,
        period_end=period_end,
        granularity=granularity,
        service_name=service_name,
        capability_keys=[c.key for c in capabilities],
        category=category,
        region=region,
        usage_type=usage_type,
        usage_account_id=usage_account_id,
        amount=(round(amount, 6) if amount is not None else None),
        usage_quantity=(round(usage_quantity, 6) if usage_quantity is not None else None),
        currency=currency,
        record_type=record_type,
        estimated=estimated,
        attribution_confidence=attribution_confidence,
        resource_record_id=resource_record_id,
        resource_id=resource_id,
        data_through=data_through,
        limitation=limitation,
    )


def _category(caps: list[ServiceCapability]) -> str | None:
    if not caps:
        return None
    categories = {c.category for c in caps}
    return categories.pop() if len(categories) == 1 else "mixed"


def collect_costs(
    session,
    config: ScanConfig,
    capabilities: list[ServiceCapability],
    records: list[RegistryRecord],
    errors: list[OperationError],
) -> CostCollectionResult:
    result = CostCollectionResult()
    if not config.enable_cost_collection:
        result.reason = "Cost collection disabled by configuration (ENABLE_COST_COLLECTION=false)."
        return result
    if not any(c.cost_service_names for c in capabilities):
        result.status = "unsupported"
        result.reason = "No capability has a Cost Explorer service name."
        return result

    ce_ok, ce_status, ce_reason, ce_count = _cost_explorer(
        session, config, capabilities, records, errors, result
    )
    cur_ok = False
    cur_status = None
    if config.cur_bucket:
        cur_ok, cur_status, cur_reason, cur_count = _cur(
            session, config, capabilities, records, errors, result
        )
        result.notes.append(f"CUR: {cur_reason} ({cur_count} records)")
        if not cur_ok and not ce_ok:
            result.status = cur_status or "collection_failed"
        elif not cur_ok and ce_ok:
            result.status = "partial"
            result.reason = f"Cost Explorer succeeded; CUR failed: {cur_reason}"
        elif cur_ok and not ce_ok:
            result.status = "partial"
            result.reason = f"CUR succeeded; Cost Explorer failed: {ce_reason}"
        else:
            result.status = "collected"
    else:
        result.status = ce_status
        result.reason = ce_reason

    result.mapped_amount = round(sum(r.amount or 0 for r in result.records if (r.amount or 0) > 0), 6)
    result.unattributed_amount = round(sum(
        r.amount or 0 for r in result.records
        if (r.amount or 0) > 0 and r.resource_record_id is None
    ), 6)
    if result.records:
        currencies = {r.currency for r in result.records}
        result.currency = currencies.pop() if len(currencies) == 1 else "MIXED"
    return result


def _cost_explorer(
    session,
    config: ScanConfig,
    capabilities: list[ServiceCapability],
    records: list[RegistryRecord],
    errors: list[OperationError],
    result: CostCollectionResult,
) -> tuple[bool, str, str, int]:
    client = session.client("ce", region_name=config.cost_region)
    end = date.today()
    start = end - timedelta(days=max(1, config.cost_lookback_days))
    try:
        pages = _ce_pages(client, start, end)
    except (ClientError, BotoCoreError) as exc:
        errors.append(OperationError(
            service="ce", operation="GetCostAndUsage", region=config.cost_region,
            error_type=classify_exception(exc), message=error_message(exc),
            scan_id=config.scan_id,
        ))
        if classify_exception(exc) in {"access_denied", "not_configured"}:
            return False, "permission_denied", f"Cost Explorer permission/opt-in failure: {error_message(exc)}", 0
        return False, "collection_failed", f"Cost Explorer failure: {error_message(exc)}", 0

    resource_index = _record_ids_by_resource(records)
    added = 0
    data_through = None
    for page in pages:
        for period in page.get("ResultsByTime", []):
            period_start = (period.get("TimePeriod") or {}).get("Start") or ""
            period_end = (period.get("TimePeriod") or {}).get("End")
            data_through = period_end or data_through
            estimated = str(period.get("Estimated", "")).lower() == "true"
            for group in period.get("Groups", []):
                keys = group.get("Keys") or []
                service_name = keys[0] if keys else "Unknown"
                region = keys[1] if len(keys) > 1 else None
                caps = _capabilities_for_service(service_name, capabilities)
                if not caps:
                    continue
                amount = _decode_amount((group.get("Metrics") or {}).get("UnblendedCost", {}).get("Amount"))
                if amount is None:
                    continue
                if abs(amount) < 0.000001:
                    continue
                rec = _match_cost_resource(keys, service_name, region, records, resource_index, caps)
                result.records.append(_cost_record(
                    source="cost_explorer", period_start=period_start, period_end=period_end,
                    granularity="DAILY",
                    service_name=service_name, capabilities=caps, category=_category(caps),
                    region=region, amount=amount,
                    currency=(group.get("Metrics") or {}).get("UnblendedCost", {}).get("Unit", "USD") or "USD",
                    record_type="Usage", estimated=estimated, data_through=data_through,
                    resource_record_id=(rec.record_id if rec else None),
                    resource_id=(rec.resource_id if rec else None),
                    attribution_confidence=("resource_billing_identifier" if rec else "service_level"),
                    limitation=(
                        "Cost Explorer reports service/Region cost. The amount is not distributed across "
                        "individual resources unless a resource-level billing identifier matched."
                    ),
                ))
                added += 1
    if added:
        return True, "collected", f"Cost Explorer returned {added} daily service/Region cost records through {data_through}.", added
    return True, "collected", f"Cost Explorer succeeded but returned no costs for mapped AI services through {data_through}; this is a valid billing result.", 0


def _ce_pages(client, start: date, end: date) -> list[dict[str, Any]]:
    pages = []
    kwargs = {
        "TimePeriod": {"Start": start.isoformat(), "End": end.isoformat()},
        "Granularity": "DAILY",
        "Metrics": ["UnblendedCost", "UsageQuantity"],
        "GroupBy": [
            {"Type": "DIMENSION", "Key": "SERVICE"},
            {"Type": "DIMENSION", "Key": "REGION"},
        ],
        "Filter": {"Dimensions": {"Key": "RECORD_TYPE", "Values": ["Usage"]}},
    }
    for _ in range(MAX_CE_PAGES):
        response = client.get_cost_and_usage(**kwargs)
        pages.append(response)
        token = response.get("NextPageToken")
        if not token:
            break
        kwargs["NextPageToken"] = token
    return pages


def _match_cost_resource(
    keys: list[str],
    service_name: str,
    region: str | None,
    records: list[RegistryRecord],
    resource_index: dict[str, RegistryRecord],
    caps: list[ServiceCapability],
) -> RegistryRecord | None:
    for key in keys:
        rec = resource_index.get(str(key).lower())
        if rec is not None:
            return rec
    # No resource identifier in service/Region grouping: do not guess.
    return None


def _cur(
    session,
    config: ScanConfig,
    capabilities: list[ServiceCapability],
    records: list[RegistryRecord],
    errors: list[OperationError],
    result: CostCollectionResult,
) -> tuple[bool, str, str, int]:
    client = session.client("s3", region_name=config.regions[0] if config.regions else "us-east-1")
    prefix = config.cur_prefix or ""
    try:
        response = client.list_objects_v2(Bucket=config.cur_bucket, Prefix=prefix, MaxKeys=100)
        objects = response.get("Contents", [])
    except (ClientError, BotoCoreError) as exc:
        errors.append(OperationError(
            service="s3", operation="ListObjectsV2", region=config.regions[0] if config.regions else None,
            error_type=classify_exception(exc), message=error_message(exc), scan_id=config.scan_id,
        ))
        status = "permission_denied" if classify_exception(exc) == "access_denied" else "collection_failed"
        return False, status, f"CUR bucket listing failed: {error_message(exc)}", 0
    candidates = [
        o for o in objects
        if str(o.get("Key", "")).endswith((".csv", ".csv.gz"))
    ][:MAX_CUR_FILES]
    if not candidates:
        return False, "not_configured", f"No CSV/GZIP CUR objects found under s3://{config.cur_bucket}/{prefix}.", 0
    resource_index = _record_ids_by_resource(records)
    aggregated: dict[tuple[str, str, str | None, str | None, str | None], dict[str, Any]] = {}
    rows = 0
    for obj in candidates:
        key = obj.get("Key")
        if not key:
            continue
        if int(obj.get("Size") or 0) > MAX_CUR_BYTES:
            result.notes.append(f"Skipped CUR object larger than {MAX_CUR_BYTES} bytes: {key}")
            continue
        try:
            body = client.get_object(Bucket=config.cur_bucket, Key=key)["Body"].read(MAX_CUR_BYTES)
        except (ClientError, BotoCoreError) as exc:
            errors.append(OperationError(
                service="s3", operation="GetObject", region=config.regions[0] if config.regions else None,
                error_type=classify_exception(exc), message=f"{key}: {error_message(exc)}",
                scan_id=config.scan_id,
            ))
            continue
        try:
            raw = gzip.decompress(body) if key.endswith(".gz") else body
            text = io.StringIO(raw.decode("utf-8-sig", errors="replace"))
        except (OSError, UnicodeError) as exc:
            result.notes.append(f"Could not decode CUR object {key}: {type(exc).__name__}")
            continue
        reader = csv.DictReader(text)
        for row in reader:
            rows += 1
            if rows > MAX_CUR_ROWS:
                result.notes.append(f"CUR row limit {MAX_CUR_ROWS} reached; remaining rows ignored.")
                break
            if (row.get("line_item_line_item_type") or "").lower() != "usage":
                continue
            product_code = row.get("line_item_product_code") or ""
            caps = _capabilities_for_service(product_code, capabilities)
            if not caps:
                continue
            amount = _decode_amount(row.get("line_item_unblended_cost"))
            if amount is None or abs(amount) < 0.000001:
                continue
            start = row.get("line_item_usage_start_date") or ""
            day = start[:10]
            service_name = caps[0].cost_service_names[0] if caps[0].cost_service_names else product_code
            region = row.get("product_region")
            usage_type = row.get("line_item_usage_type")
            resource_id = row.get("line_item_resource_id") or None
            account = row.get("line_item_usage_account_id") or None
            key = (day, service_name, region, usage_type, resource_id)
            bucket = aggregated.setdefault(key, {"amount": 0.0, "quantity": 0.0, "currency": row.get("line_item_currency_code") or "USD"})
            bucket["amount"] += amount
            bucket["quantity"] += _decode_amount(row.get("line_item_usage_amount")) or 0.0
            bucket["account"] = account
    for (day, service_name, region, usage_type, resource_id), payload in aggregated.items():
        caps = _capabilities_for_service(service_name, capabilities)
        rec = resource_index.get(str(resource_id).lower()) if resource_id else None
        result.records.append(_cost_record(
            source="cur", period_start=day, period_end=day, granularity="daily",
            service_name=service_name, capabilities=caps, category=_category(caps),
            region=region, usage_type=usage_type, usage_account_id=payload.get("account"),
            amount=payload["amount"], usage_quantity=payload["quantity"],
            currency=payload["currency"], record_type="Usage", estimated=False,
            data_through=day, resource_record_id=(rec.record_id if rec else None),
            resource_id=(rec.resource_id if rec else resource_id),
            attribution_confidence=("resource_billing_identifier" if rec or resource_id else "service_level"),
            limitation=(
                "CUR line item retained its resource identifier where present. Service-level rows "
                "without a resource identifier are not allocated to individual assets."
            ),
        ))
    return True, "collected", f"CUR ingested {rows} rows from {len(candidates)} object(s) into {len(result.records)} cost records.", len(result.records)
