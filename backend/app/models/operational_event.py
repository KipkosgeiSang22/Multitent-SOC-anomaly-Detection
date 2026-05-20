from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime,
    ForeignKey, func, Text, Index
)
from sqlalchemy.dialects.postgresql import JSONB
from app.db.base import Base


class OperationalEvent(Base):
    __tablename__ = "operational_events"

    id = Column(Integer, primary_key=True)
    client_id = Column(Integer, ForeignKey("clients.id"), nullable=False)
    query_name = Column(String, nullable=False)
    event_fingerprint = Column(String, unique=True, nullable=False)
    timestamp = Column(DateTime(timezone=True), nullable=False)
    source_host = Column(String, nullable=True)
    fields = Column(JSONB, nullable=False)
    time_summary = Column(Text, nullable=True)
    group_key = Column(Text, nullable=True)
    analyzed_at = Column(DateTime(timezone=True), nullable=True)
    confirmed_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    confirmed_at = Column(DateTime(timezone=True), nullable=True)
    issue_text = Column(Text, nullable=True)
    issue_raised_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    issue_raised_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        Index("ix_op_events_client_timestamp", "client_id", "timestamp"),
        Index("ix_op_events_client_query", "client_id", "query_name"),
        Index(
            "ix_op_events_unanalyzed",
            "client_id", "analyzed_at",
            postgresql_where=Column("analyzed_at").is_(None)
        ),
    )