import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(tempfile.gettempdir()) / "ai-registry-api-tests.db"
DB_PATH.unlink(missing_ok=True)
os.environ["DATABASE_URL"] = f"sqlite:///{DB_PATH}"
os.environ["SECRET_KEY"] = "test-secret"

from fastapi.testclient import TestClient  # noqa: E402
from app.core.security import create_access_token  # noqa: E402
from app.db.session import SessionLocal  # noqa: E402
from app.main import app  # noqa: E402
from app.models.asset import Asset  # noqa: E402
from app.models.insights import (  # noqa: E402
    CostRecord,
    Finding,
    ServiceCapability,
    UsageMeasurement,
)
from app.models.scan import ScanRun  # noqa: E402
from app.models.user import User  # noqa: E402


def _token() -> str:
    return create_access_token({"sub": "1"})


def _seed() -> None:
    db = SessionLocal()
    try:
        db.add(User(id=1, username="admin", email="admin@test.local", hashed_password="x", role="Administrator", is_active=True))
        db.add(ScanRun(scan_id="scan-old", status="succeeded", created_at=datetime(2026, 1, 1, tzinfo=timezone.utc)))
        db.add(ScanRun(
            scan_id="scan-new",
            status="partially succeeded",
            created_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
            metadata_json={"usage_collection": {"measurement_count": 1}, "cost_collection": {"record_count": 1}},
        ))
        db.add(Asset(
            record_id="asset-1",
            resource_name="Bedrock model",
            aws_service="bedrock",
            resource_type="bedrock_foundation_model",
            aws_region="ap-south-1",
            raw_data={},
        ))
        db.add(UsageMeasurement(
            measurement_id="usage-1",
            scan_id="scan-new",
            service="bedrock",
            namespace="AWS/Bedrock",
            metric_name="Invocations",
            statistic="Sum",
            datapoint_count=2,
            total=4,
            collection_status="collected",
        ))
        db.add(CostRecord(
            cost_record_id="cost-1",
            scan_id="scan-new",
            source="cost_explorer",
            period_start="2026-01-01",
            service_name="Amazon Bedrock",
            capability_keys=["bedrock"],
            category="ai_native",
            amount=1.25,
            currency="USD",
            attribution_confidence="service",
        ))
        db.add(Finding(
            finding_id="finding-1",
            scan_id="scan-new",
            finding_type="usage_coverage_gap",
            severity="low",
            title="Usage coverage is partial for Amazon Bedrock",
            description="Telemetry is incomplete.",
            service="bedrock",
            capability_keys=["bedrock"],
            confidence="high",
            status="open",
        ))
        db.add(ServiceCapability(
            scan_id="scan-new",
            key="bedrock",
            display_name="Amazon Bedrock",
            category="ai_native",
            discovery_status="supported",
            usage_status="partial",
            billing_status="collected",
        ))
        db.commit()
    finally:
        db.close()


def test_insight_identifiers_are_unique_per_scan_but_reusable_across_scans():
    db = SessionLocal()
    try:
        for scan_id, amount in (("scan-a", 1.25), ("scan-b", 0.5)):
            db.add(CostRecord(
                cost_record_id="cost-1",
                scan_id=scan_id,
                source="cost_explorer",
                period_start="2026-01-01",
                service_name="Amazon Bedrock",
                amount=amount,
                currency="USD",
            ))
            db.commit()
        assert db.query(CostRecord).filter(CostRecord.scan_id.in_(["scan-a", "scan-b"])).count() == 2
    finally:
        db.close()


def test_dashboard_and_asset_insights_expose_latest_scan_and_service_context():
    _seed()
    client = TestClient(app)
    headers = {"Authorization": f"Bearer {_token()}"}

    summary = client.get("/api/dashboard/summary", headers=headers)
    assert summary.status_code == 200
    body = summary.json()
    assert body["insights_scan_id"] == "scan-new"
    assert body["usage_measurement_count"] == 1
    assert body["reported_cost_total"] == 1.25
    assert body["capabilities_total"] == 1

    asset = client.get("/api/assets/asset-1/insights", headers=headers)
    assert asset.status_code == 200
    data = asset.json()
    assert data["findings"] == []
    context = data["service_context"]
    assert context["service"] == "bedrock"
    assert len(context["usage_measurements"]) == 1
    assert len(context["cost_records"]) == 1
    assert len(context["findings"]) == 1
