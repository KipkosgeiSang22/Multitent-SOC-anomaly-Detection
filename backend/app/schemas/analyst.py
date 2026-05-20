from pydantic import BaseModel, ConfigDict
from typing import Optional
from datetime import datetime
from app.schemas.events import PeriodFilter


class AnalystEventRow(BaseModel):
    id: int
    client_id: int
    client_name: str
    query_name: str
    event_fingerprint: str
    timestamp: datetime
    source_host: Optional[str] = None
    fields: dict
    time_summary: Optional[str] = None
    analyzed_at: Optional[datetime] = None
    confirmed_by: Optional[int] = None
    confirmed_at: Optional[datetime] = None
    confirmed_by_username: Optional[str] = None
    issue_text: Optional[str] = None
    issue_raised_by: Optional[int] = None
    issue_raised_at: Optional[datetime] = None
    issue_raised_by_username: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class AnomalyRow(BaseModel):
    id: int
    client_id: int
    client_name: str
    operational_event_id: Optional[int] = None
    category: str
    layer: int
    anomaly_type: str
    anomaly_score: Optional[float] = None
    details: Optional[dict] = None
    is_false_positive: Optional[bool] = False
    detected_at: datetime
    acknowledged_by: Optional[int] = None
    acknowledged_at: Optional[datetime] = None
    acknowledged_by_username: Optional[str] = None
    event_fields: Optional[dict] = None
    event_query_name: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class AcknowledgeRequest(BaseModel):
    anomaly_id: int
    notes: Optional[str] = None


class SchedulerStatusRow(BaseModel):
    process_name: str
    last_run_at: Optional[datetime] = None
    last_run_status: Optional[str] = None
    last_error: Optional[str] = None
    clients_processed: Optional[int] = None
    events_inserted: Optional[int] = None
    anomalies_detected: Optional[int] = None
    duration_seconds: Optional[float] = None

    model_config = ConfigDict(from_attributes=True)


class DashboardStats(BaseModel):
    total_clients: int
    total_events_today: int
    unacknowledged_anomalies: int
    open_issues: int
    scheduler_status: list[SchedulerStatusRow]