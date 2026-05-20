from pydantic import BaseModel, ConfigDict, field_validator
from typing import Optional
from datetime import datetime
from enum import Enum


class PeriodFilter(str, Enum):
    last_24h = "last_24h"
    last_7d = "last_7d"
    last_30d = "last_30d"
    custom = "custom"


class QueryTabInfo(BaseModel):
    query_name: str
    display_order: int
    unviewed_count: int
    model_config = ConfigDict(from_attributes=True)


class EventRow(BaseModel):
    id: int
    query_name: str
    event_fingerprint: str
    timestamp: datetime
    source_host: Optional[str] = None
    fields: dict
    time_summary: Optional[str] = None
    confirmed_by: Optional[int] = None
    confirmed_at: Optional[datetime] = None
    confirmed_by_username: Optional[str] = None
    issue_text: Optional[str] = None
    issue_raised_by: Optional[int] = None
    issue_raised_at: Optional[datetime] = None
    issue_raised_by_username: Optional[str] = None
    # Pre-computed issue summary — avoids per-row thread fetch on page load
    open_issue_count: int = 0         # issues with no resolved_at
    resolved_issue_count: int = 0     # issues with resolved_at set
    unread_reply_count: int = 0       # analyst replies not yet seen by THIS user
    model_config = ConfigDict(from_attributes=True)


class ConfirmEventRequest(BaseModel):
    event_id: int


class RaiseIssueRequest(BaseModel):
    event_id: int
    issue_text: str

    @field_validator("issue_text")
    @classmethod
    def not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("issue_text cannot be empty")
        return v.strip()


# ── event_issues (thread model) ──────────────────────────────────────────────

class EventIssueRow(BaseModel):
    id: int
    event_id: int
    client_id: int
    raised_by: int
    raised_by_username: Optional[str] = None
    issue_text: str
    created_at: datetime
    analyst_comment: Optional[str] = None
    resolved_by: Optional[int] = None
    resolved_by_username: Optional[str] = None
    resolved_at: Optional[datetime] = None
    deleted: bool = False
    reply_seen_at: Optional[datetime] = None
    model_config = ConfigDict(from_attributes=True)


class RaiseIssueV2Request(BaseModel):
    event_id: int
    issue_text: str

    @field_validator("issue_text")
    @classmethod
    def not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("issue_text cannot be empty")
        return v.strip()


class ResolveIssueRequest(BaseModel):
    issue_id: int
    # analyst_comment is optional — analyst can resolve with or without a reply.
    # None / empty string both mean "resolved without comment".
    analyst_comment: Optional[str] = None

    @field_validator("analyst_comment", mode="before")
    @classmethod
    def normalise_comment(cls, v):
        if v is None:
            return None
        stripped = str(v).strip()
        return stripped if stripped else None


class DeleteIssueRequest(BaseModel):
    issue_id: int


class EventIssueSummary(BaseModel):
    open_count: int
    resolved_count: int
    has_open: bool
    all_resolved: bool  # True when open_count==0 and resolved_count>0
