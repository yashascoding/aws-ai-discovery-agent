from sqlalchemy import Column, Integer, String, DateTime, Text, JSON
from sqlalchemy.sql import func
from ..db.session import Base


class ScanRun(Base):
    __tablename__ = "scan_runs"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(String, unique=True, index=True)
    status = Column(String, default="queued")  # queued, running, succeeded, partially succeeded, failed
    account_id = Column(String, nullable=True)
    owner_user_id = Column(Integer, index=True, nullable=True)
    regions = Column(JSON, default=list)
    services = Column(JSON, default=list)
    started_at = Column(DateTime(timezone=True), nullable=True)
    finished_at = Column(DateTime(timezone=True), nullable=True)
    duration_seconds = Column(Integer, nullable=True)
    resources_discovered = Column(Integer, default=0)
    records_total = Column(Integer, default=0)
    error_count = Column(Integer, default=0)
    errors = Column(JSON, default=list)
    metadata_json = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
