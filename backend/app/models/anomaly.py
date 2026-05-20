from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime,
    Float, ForeignKey, func, Index, UniqueConstraint
)
from sqlalchemy.dialects.postgresql import JSONB
from app.db.base import Base


class Anomaly(Base):
    __tablename__ = "anomalies"

    id = Column(Integer, primary_key=True)
    client_id = Column(Integer, ForeignKey("clients.id"), nullable=False)
    operational_event_id = Column(
        Integer, ForeignKey("operational_events.id"), nullable=True)
    typed_event_id = Column(Integer, nullable=True)
    category = Column(String, nullable=False)
    layer = Column(Integer, nullable=False)
    anomaly_type = Column(String, nullable=False)
    anomaly_score = Column(Float, nullable=True)
    details = Column(JSONB, nullable=True)
    is_false_positive = Column(Boolean, default=False)
    detected_at = Column(DateTime(timezone=True), server_default=func.now())
    acknowledged_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    acknowledged_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        UniqueConstraint(
            "operational_event_id", "layer", "anomaly_type",
            name="uq_anomaly_event_layer_type"
        ),
        Index("ix_anomalies_client_detected", "client_id", "detected_at"),
        Index("ix_anomalies_category_layer", "category", "layer"),
        Index(
            "ix_anomalies_unacknowledged",
            "acknowledged_by",
            postgresql_where=Column("acknowledged_by").is_(None)
        ),
    )