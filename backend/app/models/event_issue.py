from sqlalchemy import (
    Column, Integer, ForeignKey, Text, Boolean, DateTime, func
)
from app.db.base import Base


class EventIssue(Base):
    __tablename__ = "event_issues"

    id = Column(Integer, primary_key=True)
    event_id = Column(Integer, ForeignKey("operational_events.id"), nullable=False)
    client_id = Column(Integer, ForeignKey("clients.id"), nullable=False)
    raised_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    issue_text = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Analyst resolution
    analyst_comment = Column(Text, nullable=True)
    resolved_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True)

    deleted = Column(Boolean, default=False, nullable=False)
    # Set when the client opens the thread after an analyst reply.
    # NULL = unseen reply. Drives the notification badge.
    reply_seen_at = Column(DateTime(timezone=True), nullable=True)