from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime,
    Float, ForeignKey, func, Index
)
from app.db.base import Base


class AuthEvent(Base):
    __tablename__ = "auth_events"

    id = Column(Integer, primary_key=True)
    client_id = Column(Integer, ForeignKey("clients.id"), nullable=False)
    operational_event_id = Column(
        Integer, ForeignKey("operational_events.id"), nullable=True)
    timestamp = Column(DateTime(timezone=True), nullable=True)
    event_id = Column(Integer, nullable=True)
    target_username = Column(String, nullable=True)
    ip_address = Column(String, nullable=True)
    hour = Column(Integer, nullable=True)
    day_of_week = Column(Integer, nullable=True)
    is_weekend = Column(Boolean, nullable=True)
    target_username_freq = Column(Float, nullable=True)
    ip_address_freq = Column(Float, nullable=True)
    anomaly_score = Column(Float, nullable=True)
    rule_reason = Column(String, nullable=True)
    is_anomaly = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        Index("ix_auth_events_client_timestamp", "client_id", "timestamp"),
    )