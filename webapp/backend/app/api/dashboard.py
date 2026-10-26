from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, or_

from ..db.session import get_db
from ..models.asset import Asset
from ..models.scan import ScanRun
from ..models.insights import CostRecord, Finding, ServiceCapability, UsageMeasurement
from ..core.scan_state import SEVERITY_RANK, latest_completed_scan
from ..deps.auth import get_current_user

router = APIRouter()


@router.get("/summary")
def get_summary(db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    user_accounts = db.query(ScanRun.account_id).filter(ScanRun.owner_user_id == current_user.id, ScanRun.account_id.isnot(None))
    account_assets = db.query(Asset).filter(Asset.aws_account_id.in_(user_accounts))
    total = account_assets.count()
    high_risk = account_assets.filter(Asset.risk_assessment_level == "High").count()
    shadow_ai = account_assets.filter(
        or_(Asset.lifecycle_status == "shadow", Asset.lifecycle_status == "Shadow AI")
    ).count()
    unresolved = account_assets.filter(
        (Asset.risk_assessment_status == "Not assessed") |
        (Asset.risk_assessment_status == None) |
        ((Asset.owner == None) | (Asset.owner == "")) |
        ((Asset.intended_purpose == None) | (Asset.intended_purpose == ""))
    ).count()
    latest_scan = db.query(ScanRun).filter(ScanRun.owner_user_id == current_user.id).order_by(ScanRun.created_at.desc(), ScanRun.id.desc()).first()
    completed = latest_completed_scan(db, current_user.id)
    scan_id = completed.scan_id if completed else None

    cost_rows = []
    usage_count = 0
    finding_rows = []
    capability_rows = []
    if scan_id:
        cost_rows = db.query(CostRecord).filter(CostRecord.scan_id == scan_id).all()
        usage_count = db.query(UsageMeasurement).filter(UsageMeasurement.scan_id == scan_id).count()
        finding_rows = db.query(Finding).filter(Finding.scan_id == scan_id).all()
        capability_rows = db.query(ServiceCapability).filter(ServiceCapability.scan_id == scan_id).all()

    by_category: dict[str, float] = {}
    by_service: dict[str, float] = {}
    currency = None
    data_through = None
    for row in cost_rows:
        if row.amount is None:
            continue
        category = row.category or "unattributed"
        by_category[category] = by_category.get(category, 0.0) + row.amount
        by_service[row.service_name] = by_service.get(row.service_name, 0.0) + row.amount
        currency = currency or row.currency
        if row.data_through and (data_through is None or row.data_through > data_through):
            data_through = row.data_through

    findings_by_severity: dict[str, int] = {}
    open_findings = 0
    for finding in finding_rows:
        if finding.status == "open":
            open_findings += 1
            findings_by_severity[finding.severity] = findings_by_severity.get(finding.severity, 0) + 1
    capabilities_by_status: dict[str, int] = {}
    for cap in capability_rows:
        capabilities_by_status[cap.discovery_status] = capabilities_by_status.get(cap.discovery_status, 0) + 1
    considered = [c for c in capability_rows if c.discovery_status != "unsupported"]
    covered = [c for c in considered if c.discovery_status in ("supported", "partial")]

    metadata = (completed.metadata_json or {}) if completed else {}
    top_findings = sorted(
        (f for f in finding_rows if f.status == "open"),
        key=lambda f: (SEVERITY_RANK.get(f.severity, 9), -(f.id or 0)),
    )[:5]

    return {
        "total_discovered_ai_assets": total,
        "high_risk_assets": high_risk,
        "assets_classified_as_shadow_ai": shadow_ai,
        "assets_with_unresolved_governance_findings": unresolved,
        "latest_discovery_scan_status": latest_scan.status if latest_scan else "unknown",
        "latest_discovery_scan_timestamp": latest_scan.finished_at.isoformat() if latest_scan and latest_scan.finished_at else (latest_scan.created_at.isoformat() if latest_scan else None),
        "insights_scan_id": scan_id,
        "usage_measurement_count": usage_count,
        "usage_collection_status": (metadata.get("usage_collection") or {}).get("status", "not_configured"),
        "cost_collection_status": (metadata.get("cost_collection") or {}).get("status", "not_configured"),
        "cost_data_through": data_through,
        "cost_currency": currency or (metadata.get("cost_collection") or {}).get("currency"),
        "reported_cost_total": round(sum(by_category.values()), 6),
        "reported_cost_by_category": {k: round(v, 6) for k, v in sorted(by_category.items())},
        "top_cost_services": [
            {"service_name": name, "amount": round(amount, 6)}
            for name, amount in sorted(by_service.items(), key=lambda item: item[1], reverse=True)[:5]
        ],
        "open_findings_total": open_findings,
        "findings_by_severity": findings_by_severity,
        "top_findings": [
            {
                "finding_id": f.finding_id,
                "finding_type": f.finding_type,
                "severity": f.severity,
                "title": f.title,
                "service": f.service,
                "resource_record_id": f.resource_record_id,
            }
            for f in top_findings
        ],
        "capabilities_total": len(capability_rows),
        "capabilities_by_discovery_status": capabilities_by_status,
        "discovery_coverage_percent": round(100.0 * len(covered) / len(considered), 1) if considered else None,
    }


@router.get("/capabilities")
def get_capabilities(
    category: str | None = Query(None),
    status: str | None = Query(None),
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user),
):
    completed = latest_completed_scan(db, current_user.id)
    if not completed:
        return {"scan_id": None, "total": 0, "items": []}
    query = db.query(ServiceCapability).filter(ServiceCapability.scan_id == completed.scan_id)
    if category:
        query = query.filter(ServiceCapability.category == category)
    if status:
        query = query.filter(ServiceCapability.discovery_status == status)
    items = query.order_by(ServiceCapability.category, ServiceCapability.key).all()
    return {
        "scan_id": completed.scan_id,
        "total": len(items),
        "items": [
            {
                "key": c.key,
                "display_name": c.display_name,
                "category": c.category,
                "adapter": c.adapter,
                "discovery_status": c.discovery_status,
                "usage_status": c.usage_status,
                "billing_status": c.billing_status,
                "status_reason": c.status_reason,
                "resource_count": c.resource_count,
                "usage_measurement_count": c.usage_measurement_count,
                "cost_record_count": c.cost_record_count,
                "reported_cost": c.reported_cost,
                "cost_currency": c.cost_currency,
                "usage_namespaces": c.usage_namespaces,
                "cost_service_names": c.cost_service_names,
                "limitations": c.limitations,
            }
            for c in items
        ],
    }


@router.get("/findings")
def get_findings(
    severity: str | None = Query(None),
    finding_type: str | None = Query(None),
    service: str | None = Query(None),
    status: str = Query("open"),
    limit: int = Query(200, ge=1, le=1000),
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user),
):
    completed = latest_completed_scan(db, current_user.id)
    if not completed:
        return {"scan_id": None, "total": 0, "items": []}
    query = db.query(Finding).filter(Finding.scan_id == completed.scan_id)
    if status:
        query = query.filter(Finding.status == status)
    if severity:
        query = query.filter(Finding.severity == severity)
    if finding_type:
        query = query.filter(Finding.finding_type == finding_type)
    if service:
        query = query.filter(Finding.service == service)
    rows = query.all()
    rows.sort(key=lambda f: (SEVERITY_RANK.get(f.severity, 9), f.finding_type, f.resource_record_id or ""))
    return {
        "scan_id": completed.scan_id,
        "total": len(rows),
        "items": [
            {
                "finding_id": f.finding_id,
                "finding_type": f.finding_type,
                "severity": f.severity,
                "title": f.title,
                "description": f.description,
                "service": f.service,
                "region": f.region,
                "resource_record_id": f.resource_record_id,
                "resource_id": f.resource_id,
                "capability_keys": f.capability_keys,
                "evidence_refs": f.evidence_refs,
                "confidence": f.confidence,
                "recommendation": f.recommendation,
                "status": f.status,
                "detected_at": f.detected_at.isoformat() if f.detected_at else None,
            }
            for f in rows[:limit]
        ],
    }


@router.get("/costs")
def get_costs(
    category: str | None = Query(None),
    service: str | None = Query(None),
    limit: int = Query(500, ge=1, le=5000),
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user),
):
    completed = latest_completed_scan(db, current_user.id)
    if not completed:
        return {"scan_id": None, "total": 0, "records": [], "by_service": []}
    query = db.query(CostRecord).filter(CostRecord.scan_id == completed.scan_id)
    if category:
        query = query.filter(CostRecord.category == category)
    if service:
        query = query.filter(CostRecord.service_name == service)
    rows = query.order_by(CostRecord.period_start.desc(), CostRecord.service_name).all()
    by_service: dict[str, float] = {}
    for row in rows:
        if row.amount is not None:
            by_service[row.service_name] = by_service.get(row.service_name, 0.0) + row.amount
    return {
        "scan_id": completed.scan_id,
        "total": len(rows),
        "reported_amount": round(sum(by_service.values()), 6),
        "currency": rows[0].currency if rows else None,
        "data_through": max((r.data_through for r in rows if r.data_through), default=None),
        "by_service": [
            {"service_name": name, "amount": round(amount, 6)}
            for name, amount in sorted(by_service.items(), key=lambda item: item[1], reverse=True)
        ],
        "records": [
            {
                "cost_record_id": r.cost_record_id,
                "source": r.source,
                "period_start": r.period_start,
                "period_end": r.period_end,
                "service_name": r.service_name,
                "category": r.category,
                "region": r.region,
                "usage_type": r.usage_type,
                "amount": r.amount,
                "currency": r.currency,
                "estimated": r.estimated,
                "attribution_confidence": r.attribution_confidence,
                "resource_record_id": r.resource_record_id,
                "resource_id": r.resource_id,
                "data_through": r.data_through,
                "limitation": r.limitation,
            }
            for r in rows[:limit]
        ],
    }


@router.get("/usage")
def get_usage(
    service: str | None = Query(None),
    limit: int = Query(500, ge=1, le=5000),
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user),
):
    completed = latest_completed_scan(db, current_user.id)
    if not completed:
        return {"scan_id": None, "total": 0, "by_service": [], "records": []}
    query = db.query(UsageMeasurement).filter(UsageMeasurement.scan_id == completed.scan_id)
    if service:
        query = query.filter(UsageMeasurement.service == service)
    rows = query.order_by(UsageMeasurement.service, UsageMeasurement.metric_name).all()
    by_service: dict[str, int] = {}
    for row in rows:
        by_service[row.service] = by_service.get(row.service, 0) + 1
    return {
        "scan_id": completed.scan_id,
        "total": len(rows),
        "by_service": [
            {"service": name, "measurement_count": count}
            for name, count in sorted(by_service.items(), key=lambda item: item[1], reverse=True)
        ],
        "records": [
            {
                "measurement_id": m.measurement_id,
                "service": m.service,
                "namespace": m.namespace,
                "metric_name": m.metric_name,
                "statistic": m.statistic,
                "scope": m.scope,
                "resource_record_id": m.record_id,
                "datapoint_count": m.datapoint_count,
                "total": m.total,
                "average": m.average,
                "maximum": m.maximum,
                "latest_value": m.latest_value,
                "latest_timestamp": m.latest_timestamp.isoformat() if m.latest_timestamp else None,
                "collection_status": m.collection_status,
                "attribution_confidence": m.attribution_confidence,
                "limitation": m.limitation,
            }
            for m in rows[:limit]
        ],
    }
