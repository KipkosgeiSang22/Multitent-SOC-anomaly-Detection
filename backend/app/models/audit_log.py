from sqlalchemy import (
    Column, Integer, String, DateTime, ForeignKey, func, Index
)
from sqlalchemy.dialects.postgresql import JSONB
from app.db.base import Base


class AuditLog(Base):
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    role = Column(String, nullable=True)
    event_type = Column(String, nullable=False)
    client_id = Column(Integer, nullable=True)
    target_id = Column(Integer, nullable=True)
    details = Column(JSONB, nullable=True)
    ip_address = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)
    performed_at = Column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        Index("ix_audit_log_user", "user_id", "performed_at"),
        Index("ix_audit_log_client", "client_id", "performed_at"),
        Index("ix_audit_log_event_type", "event_type", "performed_at"),
    )