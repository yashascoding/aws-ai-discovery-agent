from pydantic import BaseModel
from typing import Any
from datetime import datetime


class AssetResponse(BaseModel):
    id: int
    record_id: str
    resource_name: str | None = None
    resource_id: str | None = None
    aws_account_id: str | None = None
    aws_region: str | None = None
    aws_service: str
    resource_type: str
    resource_kind: str | None = None
    resource_arn: str | None = None
    discovery_source: str | None = None
    first_observed: datetime | None = None
    last_observed: datetime | None = None
    last_inventory_scan: datetime | None = None
    classification: str | None = None
    usage_status: str | None = None
    detection_method: str | None = None
    evidence_refs: Any = None
    provenance: Any = None
    tags: Any = None
    owner: str | None = None
    intended_purpose: str | None = None
    description: str | None = None
    lifecycle_status: str | None = None
    ai_generated_description: str | None = None
    ai_description_confirmed: bool = False
    risk_assessment_level: str | None = None
    risk_assessment_status: str | None = "Not assessed"
    risk_assessment_reason: str | None = None
    risk_assessment_evidence: Any = None
    review_required: bool = False

    class Config:
        from_attributes = True


class AssetUpdate(BaseModel):
    owner: str | None = None
    intended_purpose: str | None = None
    description: str | None = None
    lifecycle_status: str | None = None
    risk_assessment_level: str | None = None
    risk_assessment_status: str | None = None
    risk_assessment_reason: str | None = None
