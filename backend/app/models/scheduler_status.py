from sqlalchemy import Column, Integer, String, Float, DateTime, func
from app.db.base import Base


class SchedulerStatus(Base):
    __tablename__ = "scheduler_status"

    id = Column(Integer, primary_key=True)
    process_name = Column(String, nullable=False)
    last_run_at = Column(DateTime(timezone=True), nullable=True)
    last_run_status = Column(String, nullable=True)
    last_error = Column(String, nullable=True)
    clients_processed = Column(Integer, nullable=True)
    events_inserted = Column(Integer, nullable=True)
    anomalies_detected = Column(Integer, nullable=True)
    duration_seconds = Column(Float, nullable=True)