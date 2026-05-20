from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, func
from sqlalchemy.dialects.postgresql import JSONB
from app.db.base import Base


class GraylogAudit(Base):
    __tablename__ = "graylog_audit"

    id = Column(Integer, primary_key=True)
    analyst_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    client_id = Column(Integer, ForeignKey("clients.id"), nullable=True)
    action_type = Column(String, nullable=True)
    payload = Column(JSONB, nullable=True)
    response_status = Column(Integer, nullable=True)
    performed_at = Column(DateTime(timezone=True), server_default=func.now())