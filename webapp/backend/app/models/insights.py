from sqlalchemy import Boolean, Column, Float, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.sql import func
from sqlalchemy import DateTime

from ..db.session import Base


class UsageMeasurement(Base):
    __tablename__ = "usage_measurements"
    __table_args__ = (UniqueConstraint("scan_id", "measurement_id", name="uq_usage_scan_measurement"),)

    id = Column(Integer, primary_key=True, index=True)
    measurement_id = Column(String, index=True, nullable=False)
    scan_id = Column(String, index=True, nullable=False)
    record_id = Column(String, index=True, nullable=True)
    service = Column(String, nullable=True)
    namespace = Column(String, nullable=True)
    metric_name = Column(String, nullable=True)
    statistic = Column(String, nullable=True)
    scope = Column(String, default="service")
    resource_id = Column(String, nullable=True)
    datapoint_count = Column(Integer, default=0)
    total = Column(Float, nullable=True)
    average = Column(Float, nullable=True)
    minimum = Column(Float, nullable=True)
    maximum = Column(Float, nullable=True)
    latest_value = Column(Float, nullable=True)
    latest_timestamp = Column(DateTime(timezone=True), nullable=True)
    dimensions = Column(JSON, default=dict)
    collection_status = Column(String, default="collected")
    attribution_confidence = Column(String, default="service_level")
    limitation = Column(Text, nullable=True)
    observed_at = Column(DateTime(timezone=True), nullable=True)
    raw_data = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class CostRecord(Base):
    __tablename__ = "cost_records"
    __table_args__ = (UniqueConstraint("scan_id", "cost_record_id", name="uq_cost_scan_record"),)

    id = Column(Integer, primary_key=True, index=True)
    cost_record_id = Column(String, index=True, nullable=False)
    scan_id = Column(String, index=True, nullable=False)
    source = Column(String, nullable=False)
    period_start = Column(String, index=True, nullable=False)
    period_end = Column(String, nullable=True)
    granularity = Column(String, default="DAILY")
    service_name = Column(String, index=True, nullable=False)
    capability_keys = Column(JSON, default=list)
    category = Column(String, nullable=True)
    region = Column(String, nullable=True)
    usage_type = Column(String, nullable=True)
    usage_account_id = Column(String, nullable=True)
    amount = Column(Float, nullable=True)
    usage_quantity = Column(Float, nullable=True)
    currency = Column(String, default="USD")
    record_type = Column(String, default="Usage")
    estimated = Column(Boolean, nullable=True)
    attribution_confidence = Column(String, default="service_level")
    resource_record_id = Column(String, index=True, nullable=True)
    resource_id = Column(String, nullable=True)
    data_through = Column(String, nullable=True)
    limitation = Column(Text, nullable=True)
    observed_at = Column(DateTime(timezone=True), nullable=True)
    raw_data = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("scan_id", "finding_id", name="uq_finding_scan_record"),)

    id = Column(Integer, primary_key=True, index=True)
    finding_id = Column(String, index=True, nullable=False)
    scan_id = Column(String, index=True, nullable=False)
    finding_type = Column(String, index=True, nullable=False)
    severity = Column(String, index=True, nullable=False)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    service = Column(String, nullable=True)
    region = Column(String, nullable=True)
    resource_record_id = Column(String, index=True, nullable=True)
    resource_id = Column(String, nullable=True)
    capability_keys = Column(JSON, default=list)
    evidence_refs = Column(JSON, default=list)
    confidence = Column(String, default="medium")
    recommendation = Column(Text, nullable=True)
    status = Column(String, default="open")
    detected_at = Column(DateTime(timezone=True), nullable=True)
    raw_data = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class ServiceCapability(Base):
    __tablename__ = "service_capabilities"
    __table_args__ = (UniqueConstraint("scan_id", "key", name="uq_capability_scan_key"),)

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(String, index=True, nullable=False)
    key = Column(String, index=True, nullable=False)
    display_name = Column(String, nullable=False)
    category = Column(String, nullable=False)
    adapter = Column(String, nullable=True)
    discovery_status = Column(String, nullable=False)
    usage_status = Column(String, nullable=False)
    billing_status = Column(String, nullable=False)
    usage_namespaces = Column(JSON, default=list)
    cost_service_names = Column(JSON, default=list)
    required_permissions = Column(JSON, default=list)
    limitations = Column(JSON, default=list)
    status_reason = Column(Text, nullable=True)
    resource_count = Column(Integer, default=0)
    usage_measurement_count = Column(Integer, default=0)
    cost_record_count = Column(Integer, default=0)
    reported_cost = Column(Float, nullable=True)
    cost_currency = Column(String, nullable=True)
    raw_data = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
