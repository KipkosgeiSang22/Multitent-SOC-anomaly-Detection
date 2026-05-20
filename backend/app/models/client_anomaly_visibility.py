from sqlalchemy import Column, Integer, Boolean, DateTime, ForeignKey, func
from app.db.base import Base


class ClientAnomalyVisibility(Base):
    __tablename__ = "client_anomaly_visibility"

    client_id = Column(
        Integer, ForeignKey("clients.id"), primary_key=True)
    visible = Column(Boolean, default=False)
    toggled_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    toggled_at = Column(DateTime(timezone=True), server_default=func.now())