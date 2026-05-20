from sqlalchemy import Column, Integer, String, DateTime, func, Index
from sqlalchemy.dialects.postgresql import JSONB
from app.db.base import Base


class ThreatIntel(Base):
    __tablename__ = "threat_intel"

    id = Column(Integer, primary_key=True)
    source = Column(String, nullable=True)
    title = Column(String, nullable=True)
    summary = Column(String, nullable=True)
    url = Column(String, unique=True, nullable=False)
    severity = Column(String, nullable=True)
    affected_sectors = Column(JSONB, nullable=True)
    attack_types = Column(JSONB, nullable=True)
    iocs = Column(JSONB, nullable=True)
    published_at = Column(DateTime(timezone=True), nullable=True)
    fetched_at = Column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        Index("ix_threat_intel_iocs", "iocs", postgresql_using="gin"),
    )