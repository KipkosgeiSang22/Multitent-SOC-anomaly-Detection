from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, Optional, Union

from pydantic import BaseModel, ConfigDict, field_validator

# ── Valid value sets ──────────────────────────────────────────────────────────

VALID_CATEGORIES = {
    "AuthenticationEvents",
    "AccountManagementEvents",
    "ProcessCreationEvents",
}
VALID_SEVERITIES = {"low", "medium", "high", "critical"}
VALID_OPERATORS = {"in", "not_in", "eq", "gt", "lt", "contains", "gte", "lte"}
VALID_AGGREGATIONS: set[Optional[str]] = {"count", "distinct_count", None}
VALID_LOGIC = {"OR", "AND"}


# ── Single condition ──────────────────────────────────────────────────────────

class RuleCondition(BaseModel):
    """A single field-level condition. Stored flat in JSONB."""
    model_config = ConfigDict(extra="forbid")

    kind: Literal["single"] = "single"   # discriminator field
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


# ── Compound condition ────────────────────────────────────────────────────────

class CompoundCondition(BaseModel):
    """
    Two or more single conditions joined by OR / AND.
    Aggregation (count/window) is not supported inside compound conditions —
    each branch must be a simple per-row check.

    Example — OffHoursActivity:
        {
            "kind": "compound",
            "logic": "OR",
            "conditions": [
                {"kind": "single", "field": "hour", "operator": "lt", "values": [7]},
                {"kind": "single", "field": "hour", "operator": "gte", "values": [19]}
            ]
        }
    """
    model_config = ConfigDict(extra="forbid")

    kind: Literal["compound"] = "compound"   # discriminator field
    logic: str                                # "OR" | "AND"
    conditions: list[RuleCondition]           # two or more single conditions

    @field_validator("logic")
    @classmethod
    def validate_logic(cls, v: str) -> str:
        if v not in VALID_LOGIC:
            raise ValueError(f"logic must be one of {sorted(VALID_LOGIC)}")
        return v

    @field_validator("conditions")
    @classmethod
    def validate_min_conditions(cls, v: list) -> list:
        if len(v) < 2:
            raise ValueError("compound condition must have at least 2 branches")
        for branch in v:
            if branch.aggregation is not None:
                raise ValueError(
                    "aggregation is not supported inside compound conditions"
                )
        return v


# ── Union type used in Create / Update ───────────────────────────────────────
# Pydantic uses the 'kind' discriminator to pick the right model.
# The DB stores whichever dict comes out of .model_dump().

AnyCondition = Union[
    RuleCondition,      # kind="single"  (or omitted — defaults to "single")
    CompoundCondition,  # kind="compound"
]


# ── Request bodies ────────────────────────────────────────────────────────────

class RuleCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    client_id: int
    rule_name: str
    description: Optional[str] = None
    category: str
    conditions: AnyCondition
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
    model_config = ConfigDict(extra="forbid")

    rule_name: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None
    conditions: Optional[AnyCondition] = None
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


# ── Response bodies (unchanged) ───────────────────────────────────────────────

class RuleResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    client_id: int
    rule_name: str
    description: Optional[str]
    category: str
    conditions: dict        # raw JSONB — whatever shape was stored
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
    matched_events: list[MatchedEvent]


class SeedResult(BaseModel):
    client_id: int
    seeded: list[str]
    skipped: list[str]