from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from pathlib import Path
import sys
import os
import json
from datetime import datetime

# Add parent project to path
sys.path.insert(0, str(Path(__file__).parents[4]))

from ..db.session import get_db
from ..models.asset import Asset
from ..models.scan import ScanRun
from ..models.insights import CostRecord, Finding, ServiceCapability, UsageMeasurement
from ..deps.auth import get_current_user
from ..models.user import User

from src.config import ScanConfig
from src.scanner import build_scan_metadata, run_scan

router = APIRouter()


def _as_datetime(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _import_insights(db: Session, scan_id: str, result) -> dict:
    for model in (UsageMeasurement, CostRecord, Finding, ServiceCapability):
        db.query(model).filter(model.scan_id == scan_id).delete(synchronize_session=False)

    for m in result.usage_measurements:
        db.add(UsageMeasurement(
            measurement_id=m.measurement_id,
            scan_id=scan_id,
            record_id=m.resource_record_id,
            service=m.service,
            namespace=m.namespace,
            metric_name=m.metric_name,
            statistic=m.statistic,
            scope=m.scope,
            resource_id=m.resource_id,
            datapoint_count=m.datapoint_count,
            total=m.total,
            average=m.average,
            minimum=m.minimum,
            maximum=m.maximum,
            latest_value=m.latest_value,
            latest_timestamp=_as_datetime(m.latest_timestamp),
            dimensions=m.dimensions,
            collection_status=m.collection_status,
            attribution_confidence=m.attribution_confidence,
            limitation=m.limitation,
            observed_at=_as_datetime(m.observed_at),
            raw_data=m.as_dict(),
        ))

    for c in result.cost_records:
        db.add(CostRecord(
            cost_record_id=c.cost_record_id,
            scan_id=scan_id,
            source=c.source,
            period_start=str(c.period_start),
            period_end=str(c.period_end) if c.period_end else None,
            granularity=c.granularity,
            service_name=c.service_name,
            capability_keys=c.capability_keys,
            category=c.category,
            region=c.region,
            usage_type=c.usage_type,
            usage_account_id=c.usage_account_id,
            amount=c.amount,
            usage_quantity=c.usage_quantity,
            currency=c.currency,
            record_type=c.record_type,
            estimated=c.estimated,
            attribution_confidence=c.attribution_confidence,
            resource_record_id=c.resource_record_id,
            resource_id=c.resource_id,
            data_through=c.data_through,
            limitation=c.limitation,
            observed_at=_as_datetime(c.observed_at),
            raw_data=c.as_dict(),
        ))

    for f in result.findings:
        db.add(Finding(
            finding_id=f.finding_id,
            scan_id=scan_id,
            finding_type=f.finding_type,
            severity=f.severity,
            title=f.title,
            description=f.description,
            service=f.service,
            region=f.region,
            resource_record_id=f.resource_record_id,
            resource_id=f.resource_id,
            capability_keys=f.capability_keys,
            evidence_refs=f.evidence_refs,
            confidence=f.confidence,
            recommendation=f.recommendation,
            status=f.status,
            detected_at=_as_datetime(f.detected_at),
            raw_data=f.as_dict(),
        ))

    for cap in result.capabilities:
        db.add(ServiceCapability(
            scan_id=scan_id,
            key=cap["key"],
            display_name=cap["display_name"],
            category=cap["category"],
            adapter=cap.get("adapter"),
            discovery_status=cap.get("discovery_status", "unsupported"),
            usage_status=cap.get("usage_status", "unsupported"),
            billing_status=cap.get("billing_status", "unsupported"),
            usage_namespaces=cap.get("usage_namespaces", []),
            cost_service_names=cap.get("cost_service_names", []),
            required_permissions=cap.get("required_permissions", []),
            limitations=cap.get("limitations", []),
            status_reason=cap.get("status_reason"),
            resource_count=cap.get("resource_count") or 0,
            usage_measurement_count=cap.get("usage_measurement_count") or 0,
            cost_record_count=cap.get("cost_record_count") or 0,
            reported_cost=cap.get("reported_cost"),
            cost_currency=cap.get("cost_currency"),
            raw_data=cap,
        ))

    return {
        "usage_measurement_count": len(result.usage_measurements),
        "cost_record_count": len(result.cost_records),
        "finding_count": len(result.findings),
        "capability_count": len(result.capabilities),
    }


def run_discovery_task(db: Session, scan_id: str, regions: list[str], profile: str | None, role_arn: str | None, external_id: str | None):
    scan_run = db.query(ScanRun).filter(ScanRun.scan_id == scan_id).first()
    if not scan_run:
        return
    try:
        scan_run.status = "running"
        scan_run.started_at = datetime.utcnow()
        db.commit()
        config = ScanConfig(profile=profile, regions=regions, role_arn=role_arn, external_id=external_id, scan_id=scan_id)
        result = run_scan(config)
        scan_run.account_id = result.identity.account_id if result.identity else None
        # Import results into DB
        for rec in result.registry.records:
            detection = rec.detection_method
            if isinstance(detection, (list, tuple)):
                detection = ",".join(str(item) for item in detection)
            asset = db.query(Asset).filter(Asset.record_id == rec.record_id).first()
            if asset:
                # Preserve user-maintained metadata - only update discovery fields
                asset.last_seen_scan = config.scan_id
                asset.last_observed = datetime.utcnow()
                asset.classification = rec.classification
                asset.usage_status = rec.usage_status
                asset.raw_data = rec.to_dict() if hasattr(rec, "to_dict") else {}
                db.add(asset)
            else:
                asset = Asset(
                    record_id=rec.record_id,
                    resource_name=rec.resource_name,
                    resource_id=rec.resource_id,
                    aws_account_id=rec.aws_account_id,
                    aws_region=rec.aws_region,
                    aws_service=rec.aws_service,
                    resource_type=rec.resource_type,
                    resource_kind=rec.resource_kind,
                    resource_arn=rec.resource_arn,
                    first_seen_scan=config.scan_id,
                    last_seen_scan=config.scan_id,
                    first_observed=datetime.utcnow(),
                    last_observed=datetime.utcnow(),
                    classification=rec.classification,
                    usage_status=rec.usage_status,
                    detection_method=detection,
                    evidence_refs=[e.as_dict() if hasattr(e, "as_dict") else e for e in getattr(rec, "evidence_refs", [])],
                    provenance=rec.provenance if hasattr(rec, "provenance") else {},
                    tags=rec.tags if hasattr(rec, "tags") else {},
                    raw_data=rec.to_dict() if hasattr(rec, "to_dict") else {},
                    risk_assessment_status="Not assessed",
                )
                db.add(asset)
        try:
            with db.begin_nested():
                summary = _import_insights(db, scan_id, result)
        except Exception as insight_exc:
            summary = {"insight_import_error": str(insight_exc)}
        metadata = build_scan_metadata(result)
        metadata.update(summary)
        metadata["adapter_outcomes"] = result.adapter_outcomes
        scan_run.status = "succeeded" if result.errors == [] else "partially succeeded"
        scan_run.finished_at = datetime.utcnow()
        scan_run.resources_discovered = result.resources_discovered
        scan_run.records_total = len(result.registry.records)
        scan_run.error_count = len(result.errors)
        scan_run.errors = [e.as_dict() if hasattr(e, "as_dict") else str(e) for e in result.errors]
        scan_run.metadata_json = metadata
        db.commit()
    except Exception as e:
        db.rollback()
        scan_run = db.query(ScanRun).filter(ScanRun.scan_id == scan_id).first()
        if scan_run:
            scan_run.status = "failed"
            scan_run.finished_at = datetime.utcnow()
            scan_run.errors = [{"error": str(e)}]
            db.commit()


@router.post("/scan")
def start_scan(
    background_tasks: BackgroundTasks,
    regions: list[str] = ["ap-south-1"],
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    from src.config import new_scan_id
    if not current_user.aws_profile:
        raise HTTPException(status_code=400, detail="Sign in to AWS from AWS connection settings before starting a scan")
    profile = current_user.aws_profile
    role_arn = None
    external_id = None
    scan_id = new_scan_id()
    scan_run = ScanRun(
        scan_id=scan_id,
        status="queued",
        regions=regions,
        owner_user_id=current_user.id,
        metadata_json={"aws_profile": profile},
    )
    db.add(scan_run)
    db.commit()
    background_tasks.add_task(run_discovery_task, db, scan_id, regions, profile, role_arn, external_id)
    return {"scan_id": scan_id, "status": "queued"}


@router.get("/scans")
def list_scans(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    scans = db.query(ScanRun).filter(ScanRun.owner_user_id == current_user.id).order_by(ScanRun.created_at.desc()).all()
    result = []
    for s in scans:
        result.append({
            "id": s.id,
            "scan_id": s.scan_id,
            "status": s.status,
            "regions": s.regions,
            "started_at": s.started_at.isoformat() if s.started_at else None,
            "finished_at": s.finished_at.isoformat() if s.finished_at else None,
            "resources_discovered": s.resources_discovered,
            "records_total": s.records_total,
            "error_count": s.error_count,
            "account_id": s.account_id,
            "errors": s.errors,
        })
    return result
