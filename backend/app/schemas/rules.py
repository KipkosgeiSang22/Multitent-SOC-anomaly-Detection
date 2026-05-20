from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, field_validator

# ── Valid value sets ──────────────────────────────────────────────────────────

VALID_CATEGORIES = {
    "AuthenticationEvents",
    "AccountManagementEvents",
    "ProcessCreationEvents",
}
VALID_SEVERITIES = {"low", "medium", "high", "critical"}
VALID_OPERATORS = {"in", "not_in", "eq", "gt", "lt", "contains"}
VALID_AGGREGATIONS: set[Optional[str]] = {"count", "distinct_count", None}


# ── Condition (validates the JSONB blob) ──────────────────────────────────────

class RuleCondition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    field: str
    operator: str
    values: list[Any]
    aggregation: Optional[str] = None
    threshold: Optional[int] = None
    window_minutes: Optional[int] = None
    group_by: Optional[str] = None

    @field_validator("operator")
    @classmethod
    def validate_operator(cls, v: str) -> str:
        if v not in VALID_OPERATORS:
            raise ValueError(f"operator must be one of {sorted(VALID_OPERATORS)}")
        return v

    @field_validator("aggregation")
    @classmethod
    def validate_aggregation(cls, v: Optional[str]) -> Optional[str]:
        if v not in VALID_AGGREGATIONS:
            raise ValueError(f"aggregation must be one of {VALID_AGGREGATIONS}")
        return v


# ── Request bodies ────────────────────────────────────────────────────────────

class RuleCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    client_id: int
    rule_name: str
    description: Optional[str] = None
    category: str
    conditions: RuleCondition
    severity: str
    enabled: bool = True

    @field_validator("category")
    @classmethod
    def validate_category(cls, v: str) -> str:
        if v not in VALID_CATEGORIES:
            raise ValueError(f"category must be one of {sorted(VALID_CATEGORIES)}")
        return v

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        if v not in VALID_SEVERITIES:
            raise ValueError(f"severity must be one of {sorted(VALID_SEVERITIES)}")
        return v


class RuleUpdate(BaseModel):
    """All fields optional — PATCH semantics."""
    model_config = ConfigDict(extra="forbid")

    rule_name: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None
    conditions: Optional[RuleCondition] = None
    severity: Optional[str] = None
    enabled: Optional[bool] = None

    @field_validator("category")
    @classmethod
    def validate_category(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v not in VALID_CATEGORIES:
            raise ValueError(f"category must be one of {sorted(VALID_CATEGORIES)}")
        return v

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v not in VALID_SEVERITIES:
            raise ValueError(f"severity must be one of {sorted(VALID_SEVERITIES)}")
        return v


# ── Response bodies ───────────────────────────────────────────────────────────

class RuleResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    client_id: int
    rule_name: str
    description: Optional[str]
    category: str
    conditions: dict
    severity: str
    enabled: bool
    created_by: Optional[int]
    updated_by: Optional[int]
    created_at: datetime
    updated_at: datetime


class MatchedEvent(BaseModel):
    event_id: int
    timestamp: datetime
    fields_summary: dict
    match_reason: str


class TestResult(BaseModel):
    rule: RuleResponse
    period_hours: int = 24
    total_events_scanned: int
    matched_count: int
    matched_events: list[MatchedEvent]  # max 10


class SeedResult(BaseModel):
    client_id: int
    seeded: list[str]
    skipped: list[str]
