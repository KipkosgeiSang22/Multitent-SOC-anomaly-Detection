from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime,UniqueConstraint,
    Float, ForeignKey, func, Index
)
from app.db.base import Base


class ProcessEvent(Base):
    __tablename__ = "process_events"
    __table_args__ = (
        UniqueConstraint("operational_event_id", name="uq_process_operational_event"),
    )

    id = Column(Integer, primary_key=True)
    client_id = Column(Integer, ForeignKey("clients.id"), nullable=False)
    operational_event_id = Column(
        Integer, ForeignKey("operational_events.id"), nullable=True)
    timestamp = Column(DateTime(timezone=True), nullable=True)
    event_id = Column(Integer, nullable=True)
    subject_username = Column(String, nullable=True)
    command_line = Column(String, nullable=True)
    hour = Column(Integer, nullable=True)
    day_of_week = Column(Integer, nullable=True)
    is_weekend = Column(Boolean, nullable=True)
    subject_username_freq = Column(Float, nullable=True)
    command_line_freq = Column(Float, nullable=True)
    anomaly_score = Column(Float, nullable=True)
    rule_reason = Column(String, nullable=True)
    is_anomaly = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        Index("ix_process_events_client_timestamp", "client_id", "timestamp"),
    )