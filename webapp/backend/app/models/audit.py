from sqlalchemy import Column, Integer, String, DateTime, Text, JSON
from sqlalchemy.sql import func
from ..db.session import Base


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id = Column(Integer, primary_key=True, index=True)
    actor_id = Column(Integer, nullable=True)
    asset_id = Column(String, nullable=True)  # record_id
    action = Column(String, nullable=False)
    previous_value = Column(JSON, nullable=True)
    new_value = Column(JSON, nullable=True)
    request_id = Column(String, nullable=True)
    ip_address = Column(String, nullable=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
