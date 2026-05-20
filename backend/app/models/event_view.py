from sqlalchemy import (
    Column, Integer, DateTime, ForeignKey, func, UniqueConstraint
)
from app.db.base import Base


class EventView(Base):
    __tablename__ = "event_views"

    id = Column(Integer, primary_key=True)
    event_id = Column(Integer, ForeignKey("operational_events.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    viewed_at = Column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        UniqueConstraint("event_id", "user_id", name="uq_event_view"),
    )