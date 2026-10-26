from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional

from ..db.session import get_db
from ..models.asset import Asset
from ..models.audit import AuditEvent
from ..models.insights import CostRecord, Finding, UsageMeasurement
from ..core.scan_state import latest_completed_scan_id, owned_account_ids
from ..deps.auth import get_current_user, require_role
from ..schemas.asset import AssetResponse, AssetUpdate
from ..models.user import User

router = APIRouter()


def _user_assets(db: Session, user: User):
    accounts = owned_account_ids(db, user.id)
    return db.query(Asset).filter(Asset.aws_account_id.in_(accounts)) if accounts else db.query(Asset).filter(False)


@router.get("/", response_model=List[AssetResponse])
def list_assets(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    q: Optional[str] = Query(None, description="Search by name/id/service/owner"),
    risk: Optional[str] = Query(None),
    service: Optional[str] = Query(None),
    lifecycle: Optional[str] = Query(None),
    missing_owner: Optional[bool] = Query(False),
    skip: int = 0,
    limit: int = 100,
):
    query = _user_assets(db, current_user)
    if q:
        qlike = f"%{q}%"
        query = query.filter(
            (Asset.resource_name.ilike(qlike)) |
            (Asset.resource_id.ilike(qlike)) |
            (Asset.aws_service.ilike(qlike)) |
            (Asset.owner.ilike(qlike))
        )
    if risk:
        query = query.filter(Asset.risk_assessment_level == risk)
    if service:
        query = query.filter(Asset.aws_service == service)
    if lifecycle:
        query = query.filter(Asset.lifecycle_status == lifecycle)
    if missing_owner:
        query = query.filter((Asset.owner == None) | (Asset.owner == ""))
    assets = query.offset(skip).limit(limit).all()
    return assets


@router.get("/{record_id}", response_model=AssetResponse)
def get_asset(record_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    asset = _user_assets(db, current_user).filter(Asset.record_id == record_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset


@router.put("/{record_id}", response_model=AssetResponse)
def update_asset(
    record_id: str,
    update: AssetUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("Administrator", "Asset Owner")),
):
    asset = _user_assets(db, current_user).filter(Asset.record_id == record_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    # Audit previous values
    prev = {
        "owner": asset.owner,
        "intended_purpose": asset.intended_purpose,
        "description": asset.description,
        "lifecycle_status": asset.lifecycle_status,
        "risk_assessment_level": asset.risk_assessment_level,
        "risk_assessment_status": asset.risk_assessment_status,
    }
    # Apply updates
    if update.owner is not None:
        asset.owner = update.owner
    if update.intended_purpose is not None:
        asset.intended_purpose = update.intended_purpose
    if update.description is not None:
        asset.description = update.description
    if update.lifecycle_status is not None:
        asset.lifecycle_status = update.lifecycle_status
    if update.risk_assessment_level is not None:
        asset.risk_assessment_level = update.risk_assessment_level
    if update.risk_assessment_status is not None:
        asset.risk_assessment_status = update.risk_assessment_status
    if update.risk_assessment_reason is not None:
        asset.risk_assessment_reason = update.risk_assessment_reason
    db.add(asset)
    # Create audit
    audit = AuditEvent(
        actor_id=current_user.id,
        asset_id=record_id,
        action="update_asset",
        previous_value=prev,
        new_value={
            "owner": asset.owner,
            "intended_purpose": asset.intended_purpose,
            "description": asset.description,
            "lifecycle_status": asset.lifecycle_status,
            "risk_assessment_level": asset.risk_assessment_level,
            "risk_assessment_status": asset.risk_assessment_status,
        },
    )
    db.add(audit)
    db.commit()
    db.refresh(asset)
    return asset


@router.get("/{record_id}/insights")
def get_asset_insights(record_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    asset = _user_assets(db, current_user).filter(Asset.record_id == record_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    scan_id = latest_completed_scan_id(db, current_user.id)
    if not scan_id:
        return {"scan_id": None, "usage_measurements": [], "cost_records": [], "findings": []}
    usage = db.query(UsageMeasurement).filter(
        UsageMeasurement.scan_id == scan_id, UsageMeasurement.record_id == record_id
    ).all()
    costs = db.query(CostRecord).filter(
        CostRecord.scan_id == scan_id, CostRecord.resource_record_id == record_id
    ).all()
    findings = db.query(Finding).filter(
        Finding.scan_id == scan_id, Finding.resource_record_id == record_id
    ).all()
    service = asset.aws_service
    service_usage = db.query(UsageMeasurement).filter(
        UsageMeasurement.scan_id == scan_id, UsageMeasurement.service == service
    ).all()
    scan_costs = db.query(CostRecord).filter(CostRecord.scan_id == scan_id).all()
    service_costs = [
        c for c in scan_costs
        if service in (c.capability_keys or [])
    ]
    scan_findings = db.query(Finding).filter(
        Finding.scan_id == scan_id, Finding.service == service
    ).all()
    service_findings = {f.finding_id: f for f in scan_findings}
    for f in findings:
        service_findings.setdefault(f.finding_id, f)
    return {
        "scan_id": scan_id,
        "usage_measurements": [
            {
                "measurement_id": m.measurement_id,
                "service": m.service,
                "namespace": m.namespace,
                "metric_name": m.metric_name,
                "statistic": m.statistic,
                "scope": m.scope,
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
            for m in usage
        ],
        "cost_records": [
            {
                "cost_record_id": c.cost_record_id,
                "source": c.source,
                "period_start": c.period_start,
                "service_name": c.service_name,
                "category": c.category,
                "amount": c.amount,
                "currency": c.currency,
                "attribution_confidence": c.attribution_confidence,
                "data_through": c.data_through,
                "limitation": c.limitation,
            }
            for c in costs
        ],
        "findings": [
            {
                "finding_id": f.finding_id,
                "finding_type": f.finding_type,
                "severity": f.severity,
                "title": f.title,
                "description": f.description,
                "confidence": f.confidence,
                "recommendation": f.recommendation,
                "status": f.status,
                "evidence_refs": f.evidence_refs,
            }
            for f in findings
        ],
        "service_context": {
            "service": service,
            "note": (
                "Service-level evidence is shared by resources of this service and "
                "is not attributed to this individual resource."
            ),
            "usage_measurements": [
                {
                    "measurement_id": m.measurement_id,
                    "service": m.service,
                    "namespace": m.namespace,
                    "metric_name": m.metric_name,
                    "statistic": m.statistic,
                    "scope": m.scope,
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
                for m in service_usage
            ],
            "cost_records": [
                {
                    "cost_record_id": c.cost_record_id,
                    "source": c.source,
                    "period_start": c.period_start,
                    "service_name": c.service_name,
                    "category": c.category,
                    "amount": c.amount,
                    "currency": c.currency,
                    "attribution_confidence": c.attribution_confidence,
                    "data_through": c.data_through,
                    "limitation": c.limitation,
                }
                for c in service_costs
            ],
            "findings": [
                {
                    "finding_id": f.finding_id,
                    "finding_type": f.finding_type,
                    "severity": f.severity,
                    "title": f.title,
                    "description": f.description,
                    "confidence": f.confidence,
                    "recommendation": f.recommendation,
                    "status": f.status,
                    "evidence_refs": f.evidence_refs,
                }
                for f in service_findings.values()
            ],
        },
    }


@router.get("/{record_id}/audit", response_model=List[dict])
def get_audit(record_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if not _user_assets(db, current_user).filter(Asset.record_id == record_id).first():
        raise HTTPException(status_code=404, detail="Asset not found")
    events = db.query(AuditEvent).filter(AuditEvent.asset_id == record_id).order_by(AuditEvent.timestamp.desc()).all()
    result = []
    for e in events:
        result.append({
            "id": e.id,
            "actor_id": e.actor_id,
            "action": e.action,
            "previous_value": e.previous_value,
            "new_value": e.new_value,
            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
        })
    return result
