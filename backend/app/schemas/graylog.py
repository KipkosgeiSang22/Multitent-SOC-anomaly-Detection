"""
app/schemas/graylog.py — Session 12: Graylog Management
"""
from __future__ import annotations
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict


# ── Confirmation token (destructive actions) ──────────────────────────────────
class ConfirmIntentRequest(BaseModel):
    client_id: int
    action: str          # e.g. "delete_user", "restart_input"
    target: str          # e.g. username or input_id


class ConfirmIntentResponse(BaseModel):
    confirm_token: str
    expires_in_seconds: int = 60
    message: str


class DestructiveRequest(BaseModel):
    confirm_token: str
    password: str


# ── Inputs ────────────────────────────────────────────────────────────────────
class InputRestartRequest(DestructiveRequest):
    pass


class InputResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: Optional[str] = None
    title: Optional[str] = None
    type: Optional[str] = None
    global_: Optional[bool] = None
    created_at: Optional[str] = None
    extra: Optional[Dict[str, Any]] = None


# ── Users ─────────────────────────────────────────────────────────────────────
class GraylogUserCreate(BaseModel):
    username: str
    password: str
    email: str
    full_name: Optional[str] = None
    roles: List[str] = ["Reader"]


class GraylogUserDeleteRequest(DestructiveRequest):
    pass


# ── Dashboards ────────────────────────────────────────────────────────────────
class DashboardCreate(BaseModel):
    title: str
    description: Optional[str] = None


# ── Generic proxy response ────────────────────────────────────────────────────
class GraylogProxyResponse(BaseModel):
    success: bool
    data: Optional[Any] = None
    message: Optional[str] = None


# ── Audit ─────────────────────────────────────────────────────────────────────
class GraylogAuditEntry(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    analyst_id: Optional[int] = None
    client_id: Optional[int] = None
    action_type: Optional[str] = None
    payload: Optional[Dict[str, Any]] = None
    response_status: Optional[int] = None
    performed_at: Optional[datetime] = None
