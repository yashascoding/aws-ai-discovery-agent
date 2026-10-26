from sqlalchemy import Boolean, Column, Integer, String, DateTime, Text, JSON
from sqlalchemy.sql import func
from ..db.session import Base


class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    record_id = Column(String, unique=True, index=True, nullable=False)
    resource_name = Column(String, nullable=True)
    resource_id = Column(String, nullable=True)
    aws_account_id = Column(String, nullable=True)
    aws_region = Column(String, nullable=True)
    aws_service = Column(String, nullable=False)
    resource_type = Column(String, nullable=False)
    resource_kind = Column(String, nullable=True)
    resource_arn = Column(Text, nullable=True)
    discovery_source = Column(String, default="aws-discovery-agent")
    first_seen_scan = Column(String, nullable=True)
    last_seen_scan = Column(String, nullable=True)
    first_observed = Column(DateTime(timezone=True), nullable=True)
    last_observed = Column(DateTime(timezone=True), nullable=True)
    last_inventory_scan = Column(DateTime(timezone=True), nullable=True)
    classification = Column(String, nullable=True)
    usage_status = Column(String, nullable=True)
    detection_method = Column(String, nullable=True)
    evidence_refs = Column(JSON, default=list)
    provenance = Column(JSON, default=dict)
    tags = Column(JSON, default=dict)
    raw_data = Column(JSON, default=dict)
    # User-maintained metadata
    owner = Column(String, nullable=True)
    intended_purpose = Column(Text, nullable=True)
    description = Column(Text, nullable=True)
    lifecycle_status = Column(String, nullable=True)
    ai_generated_description = Column(Text, nullable=True)
    ai_description_confirmed = Column(Boolean, default=False)
    ai_description_confirmed_by = Column(Integer, nullable=True)
    ai_description_confirmed_at = Column(DateTime(timezone=True), nullable=True)
    risk_assessment_level = Column(String, nullable=True)
    risk_assessment_status = Column(String, default="Not assessed")
    risk_assessment_reason = Column(Text, nullable=True)
    risk_assessment_evidence = Column(JSON, default=list)
    risk_assessment_timestamp = Column(DateTime(timezone=True), nullable=True)
    review_required = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
