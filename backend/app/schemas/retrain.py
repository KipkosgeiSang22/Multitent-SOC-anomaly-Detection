"""
app/schemas/retrain.py  — Session 11: ML Retraining
"""
from __future__ import annotations
from datetime import datetime
from typing import Optional, List, Any, Dict
from pydantic import BaseModel, ConfigDict

VALID_CATEGORIES = {"AuthenticationEvents", "AccountManagementEvents", "ProcessCreationEvents"}


class RetrainEventRow(BaseModel):
    """One scored row from a typed table + its anomaly info."""
    model_config = ConfigDict(from_attributes=True)

    id: int
    client_id: int
    operational_event_id: Optional[int] = None
    timestamp: Optional[datetime] = None
    event_id: Optional[int] = None
    hour: Optional[int] = None
    day_of_week: Optional[int] = None
    is_weekend: Optional[bool] = None
    anomaly_score: Optional[float] = None
    rule_reason: Optional[str] = None
    is_anomaly: bool = False
    # anomaly join fields
    anomaly_id: Optional[int] = None
    anomaly_type: Optional[str] = None
    layer: Optional[int] = None
    is_false_positive: Optional[bool] = None
    anomaly_details: Optional[Dict[str, Any]] = None
    # category-specific fields (populated by endpoint from dict)
    extra_fields: Optional[Dict[str, Any]] = None


class RetrainPreviewResponse(BaseModel):
    total: int
    page: int
    page_size: int
    rows: List[Dict[str, Any]]


class RetrainStartRequest(BaseModel):
    client_id: int
    category: str
    period_start: datetime
    period_end: datetime
    exclude_ids: List[int] = []   # true positives — exclude from training
    include_ids: List[int] = []   # false positives — force include
    notes: Optional[str] = None


class RetrainStatusResponse(BaseModel):
    job_id: str
    status: str          # started | running | complete | failed
    message: Optional[str] = None
    trained_at: Optional[datetime] = None
    training_rows: Optional[int] = None


class RetrainRollbackResponse(BaseModel):
    client_id: int
    category: str
    model_path: str
    backup_path: str
    message: str
    rolled_back_at: datetime
