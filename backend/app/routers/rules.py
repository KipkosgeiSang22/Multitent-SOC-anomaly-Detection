"""
app/routers/rules.py
Layer 1 Rules CRUD API — Session 10

Permission gate:
  - Superadmin: always allowed
  - Analyst: needs can_edit_layer1_rules=True AND client_id in scope

JWT payload: { "sub": "<user_id>", "role": "...", "client_id": ..., "type": "access" }
security.py exports: decode_token(), NOT decode_access_token()
audit.py log_action() signature: (db, request, event_type, user_id, client_id, target_id, details, flush_only)
  — no 'role' parameter.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import log_action
from app.core.dependencies import get_current_user, get_db, require_superadmin
from app.models.analyst_permission import AnalystPermission
from app.models.layer1_rule import Layer1Rule
from app.models.operational_event import OperationalEvent
from app.models.user import User
from app.schemas.rules import (
    MatchedEvent,
    RuleCreate,
    RuleResponse, 
    RuleUpdate,
    SeedResult,
    TestResult,
)

log = logging.getLogger(__name__)
router = APIRouter() 

# ── LOLBin patterns (mirrors anomaly_processing.py MALICIOUS_TOOLS) ──────────
LOLBIN_PATTERNS = [
    "mimikatz", "powershell -enc", "psexec", "whoami", "net user /add",
    "certutil", "bitsadmin", "wmic", "regsvr32", "mshta", "rundll32",
    "cmstp", "installutil", "csc.exe", "msbuild",
]
#TODO Add dropdown for category and severity
# ── Default rules seeded for every new client ─────────────────────────────────
DEFAULT_RULES: list[dict] = [
    {
        "rule_name": "BruteForce",
        "description": "More than 5 failed logins from the same source IP within 5 minutes",
        "category": "AuthenticationEvents",
        "severity": "high",
        "conditions": {
            "field": "EventID",
            "operator": "in",
            "values": [4625],
            "aggregation": "count",
            "threshold": 5,
            "window_minutes": 5,
            "group_by": "IpAddress",
        },
    },
    {
        "rule_name": "PrivilegeEscalation",
        "description": "Privilege-related EventIDs indicating potential escalation",
        "category": "AuthenticationEvents",
        "severity": "high",
        "conditions": {
            "field": "EventID",
            "operator": "in",
            "values": [4672, 4728, 4732],
            "aggregation": None,
            "threshold": None,
            "window_minutes": None,
            "group_by": None,
        },
    },
    {
        "rule_name": "SuspiciousProcess",
        "description": "CommandLine matches known LOLBin / post-exploitation patterns",
        "category": "ProcessCreationEvents",
        "severity": "high",
        "conditions": {
            "field": "CommandLine",
            "operator": "contains",
            "values": LOLBIN_PATTERNS,
            "aggregation": None,
            "threshold": None,
            "window_minutes": None,
            "group_by": None,
        },
    },
{
    "rule_name": "OffHoursActivity",
    "description": "Authentication events outside 07:00-19:00 EAT",
    "category": "AuthenticationEvents",
    "severity": "medium",
    "conditions": {
        "kind": "compound",
        "logic": "OR",
        "conditions": [
            {
                "kind": "single",
                "field": "hour",
                "operator": "lt",
                "values": [7],
                "aggregation": None,
                "threshold": None,
                "window_minutes": None,
                "group_by": None,
            },
            {
                "kind": "single",
                "field": "hour",
                "operator": "gte",
                "values": [19],
                "aggregation": None,
                "threshold": None,
                "window_minutes": None,
                "group_by": None,
            },
        ],
    },
},
    {
        "rule_name": "AccountManipulation",
        "description": "Account created then deleted in rapid succession (4720 + 4726)",
        "category": "AccountManagementEvents",
        "severity": "high",
        "conditions": {
            "field": "EventID",
            "operator": "in",
            "values": [4720, 4726],
            "aggregation": None,
            "threshold": None,
            "window_minutes": None,
            "group_by": None,
        },
    },
]


# ── Permission check (called directly, not as a Depends) ─────────────────────

async def _require_rules_access(
    client_id: int,
    current_user: User,
    db: AsyncSession,
) -> None:
    """Allow superadmin always; analyst only if they have can_edit_layer1_rules
    and the client_id is within their scope."""
    if current_user.role == "superadmin":
        return

    if current_user.role != "analyst":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")

    result = await db.execute(
        select(AnalystPermission).where(
            AnalystPermission.analyst_id == current_user.id,
            AnalystPermission.revoked_at.is_(None),
            AnalystPermission.can_edit_layer1_rules.is_(True),
        )
    )
    perm = result.scalar_one_or_none()

    if perm is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="can_edit_layer1_rules permission not granted",
        )

    scope: list = perm.client_scope or []
    if scope != ["ALL"] and client_id not in scope:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"client_id {client_id} not in your assigned scope",
        )


# ── Helpers ───────────────────────────────────────────────────────────────────
# Used during rule creation, update, deletion, or seeding
# When a new rule is added (create_rule, seed_rules) or updated (update_rule, toggle_rule), the system logs the action with log_action
def _rule_to_dict(rule: Layer1Rule) -> dict:
    return {
        "id": rule.id,
        "client_id": rule.client_id,
        "rule_name": rule.rule_name,
        "description": rule.description,
        "category": rule.category,
        "conditions": rule.conditions,
        "severity": rule.severity,
        "enabled": rule.enabled,
        "created_by": rule.created_by,
        "updated_by": rule.updated_by,
        "created_at": rule.created_at.isoformat() if rule.created_at else None,
        "updated_at": rule.updated_at.isoformat() if rule.updated_at else None,
    }

def _evaluate_condition(cond: dict, row_fields: dict, all_rows: list[dict]) -> tuple[bool, str]:
    """
    Evaluate one rule condition (single or compound) against a single event row.
    Returns (matched: bool, reason: str).
    """
    kind = cond.get("kind", "single")

    # ── Compound branch ──────────────────────────────────────────────────────
    if kind == "compound":
        logic = cond.get("logic", "OR").upper()
        branches = cond.get("conditions", [])
        results = [_evaluate_condition(b, row_fields, all_rows) for b in branches]
#results is a list of tuples
        if logic == "OR":
            for matched, reason in results:
                if matched:
                    return True, reason          # first branch that fires
            return False, ""

        else:  # AND
            reasons = []
            for matched, reason in results:
                if not matched:
                    return False, ""      # one branch failed → whole thing fails immediately
                reasons.append(reason)    # all passed → collect all reasons
            return True, " AND ".join(reasons)  # e.g. "hour gte [8] AND hour lt [19]"

    # ── Single branch (original logic, unchanged) ────────────────────────────
    field = cond.get("field", "")
    operator = cond.get("operator", "")
    values = cond.get("values", [])
    aggregation = cond.get("aggregation")
    threshold = cond.get("threshold")
    window_minutes = cond.get("window_minutes")
    group_by = cond.get("group_by")

    if aggregation in ("count", "distinct_count") and threshold is not None:
        row_val = row_fields.get(field)
        if row_val is None:
            return False, ""

        if group_by:
            group_val = row_fields.get(group_by)
            candidates = [
                r for r in all_rows if r.get("fields", {}).get(group_by) == group_val
            ]
        else:
            candidates = all_rows

        if window_minutes:
            row_ts = row_fields.get("_ts")#confirm if timestamp has been set as _ts below
            # .get checks whether _ts exist before using the actual value
            if row_ts:
                window_start = row_ts - timedelta(minutes=window_minutes)
                candidates = [
                    r for r in candidates
                    if r.get("_ts") and r["_ts"] >= window_start
                ]

        if aggregation == "count":
            count = sum(
                1 for r in candidates
                if _field_matches(operator, r.get("fields", {}).get(field), values)
            )
        else:
            seen = set()
            for r in candidates:
                v = r.get("fields", {}).get(field)
                if v is not None and _field_matches(operator, v, values):
                    seen.add(str(v))
            count = len(seen)

        if count >= threshold:
            return True, (
                f"{aggregation}({field}) {operator} {values} "
                f"= {count} >= {threshold} "
                f"(window={window_minutes}m, group_by={group_by})"
            )
        return False, ""

    # Simple per-row
    row_val = row_fields.get(field)
    if row_val is None:
        return False, ""

    matched = _field_matches(operator, row_val, values)
    if matched:
        return True, f"{field} {operator} {values}"
    return False, ""


def _field_matches(operator: str, value: object, values: list) -> bool:
    if operator == "in":
        return value in values or str(value) in [str(v) for v in values]
    if operator == "not_in":
        return value not in values and str(value) not in [str(v) for v in values]
    if operator == "eq":
        return str(value) == str(values[0]) if values else False
    if operator == "gt":
        try: return float(value) > float(values[0])
        except (TypeError, ValueError): return False
    if operator == "lt":
        try: return float(value) < float(values[0])
        except (TypeError, ValueError): return False
    if operator == "gte":                              
        try: return float(value) >= float(values[0])
        except (TypeError, ValueError): return False
    if operator == "lte":                              
        try: return float(value) <= float(values[0])
        except (TypeError, ValueError): return False
    if operator == "contains":
        val_lower = str(value).lower()
        return any(str(v).lower() in val_lower for v in values)
    return False


async def _get_rule_or_404(rule_id: int, db: AsyncSession) -> Layer1Rule:
    result = await db.execute(select(Layer1Rule).where(Layer1Rule.id == rule_id))
    rule = result.scalar_one_or_none()
    if rule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")
    return rule


# ── IMPORTANT: /seed/{client_id} MUST be registered before /{rule_id} routes ─
# FastAPI matches routes in registration order. If /{rule_id} is registered first,
# GET/POST /rules/seed/1 would try to parse "seed" as an integer rule_id and 422.

# ── POST /rules/seed/{client_id} ─────────────────────────────────────────────

@router.post("/seed/{client_id}", response_model=SeedResult)
async def seed_rules(
    client_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_superadmin),  # superadmin only; provides current_user
) -> SeedResult:
    """Seed default rules for a client. Superadmin only. Idempotent."""
    result = await db.execute(
        select(Layer1Rule.rule_name).where(Layer1Rule.client_id == client_id)
    )
    existing_names: set[str] = {row[0] for row in result.fetchall()}

    seeded: list[str] = []
    skipped: list[str] = []

    for default in DEFAULT_RULES:
        name = default["rule_name"]
        if name in existing_names:
            skipped.append(name)
            continue

        rule = Layer1Rule(
            client_id=client_id,
            rule_name=name,
            description=default.get("description"),
            category=default["category"],
            conditions=default["conditions"],
            severity=default["severity"],
            enabled=True,
            created_by=current_user.id,
            updated_by=current_user.id,
        )
        db.add(rule)
        await db.flush()

        await log_action(
            db=db,
            request=request,
            event_type="LAYER1_RULE_CREATED",
            user_id=current_user.id,
            client_id=client_id,
            target_id=rule.id,
            details={"rule": _rule_to_dict(rule), "seeded": True},
            flush_only=True,
        )
        seeded.append(name)

    await db.commit()
    return SeedResult(client_id=client_id, seeded=seeded, skipped=skipped)


# ── GET /rules/{client_id} ────────────────────────────────────────────────────

@router.get("/{client_id}", response_model=list[RuleResponse])
async def list_rules(
    client_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[RuleResponse]:
    await _require_rules_access(client_id, current_user, db)

    result = await db.execute(
        select(Layer1Rule)
        .where(Layer1Rule.client_id == client_id)
        .order_by(Layer1Rule.id)
    )
    rules = result.scalars().all()
    return [RuleResponse.model_validate(r) for r in rules]
# Reads the attributes of the ORM object (id, client_id, rule_name, conditions, etc.).Validates them against the RuleResponse schema (types, required fields, allowed values).Produces a proper RuleResponse Pydantic model instance


# ── POST /rules ───────────────────────────────────────────────────────────────
# ── POST /rules ───────────────────────────────────────────────────────────────

# TODO (Session 17 — Rule Builder UI):
# The frontend builds the conditions payload before submitting — the backend
# accepts whatever shape arrives and Pydantic validates it automatically.
#
# Frontend logic needed in the rule creation/edit form:
#
# 1. SINGLE CONDITION (1 row):
#    - Show aggregation fields: count/distinct_count, threshold,
#      window_minutes, group_by
#    - Build payload as a flat dict (no "kind" needed — defaults to "single"):
#      { "field": "EventID", "operator": "in", "values": [4625],
#        "aggregation": "count", "threshold": 5, "window_minutes": 5,
#        "group_by": "IpAddress" }
#
# 2. COMPOUND CONDITION (2+ rows):
#    - Hide aggregation fields (not supported inside compound)
#    - Show OR / AND toggle
#    - Build payload as compound dict:
#      { "kind": "compound", "logic": "OR", "conditions": [
#          { "kind": "single", "field": "hour", "operator": "lt", "values": [7] },
#          { "kind": "single", "field": "hour", "operator": "gte", "values": [19] }
#      ]}
#
# 3. The buildConditions(rows, logic) function in the frontend decides
#    which shape to build based on rows.length — the user never picks
#    between single/compound explicitly.
#
# 4. Operators available: in, not_in, eq, gt, lt, gte, lte, contains
#    Show as a dropdown — same list as VALID_OPERATORS in schemas/rules.py
#
# 5. Test rule button calls POST /rules/{rule_id}/test after saving —
#    shows matched_events from the dry-run result in a preview panel.

@router.post("", response_model=RuleResponse, status_code=status.HTTP_201_CREATED)
async def create_rule(
    body: RuleCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> RuleResponse:
    await _require_rules_access(body.client_id, current_user, db)

    rule = Layer1Rule(
        client_id=body.client_id,
        rule_name=body.rule_name,
        description=body.description,
        category=body.category,
        conditions=body.conditions.model_dump(),
        severity=body.severity,
        enabled=body.enabled,
        created_by=current_user.id,
        updated_by=current_user.id,
    )
    db.add(rule)
    await db.flush()

    await log_action(
        db=db,
        request=request,
        event_type="LAYER1_RULE_CREATED",
        user_id=current_user.id,
        client_id=rule.client_id,
        target_id=rule.id,
        details={"rule": _rule_to_dict(rule)},
        flush_only=True,
    )
    await db.commit()
    await db.refresh(rule)
    return RuleResponse.model_validate(rule)


# ── PATCH /rules/{rule_id} ────────────────────────────────────────────────────

@router.patch("/{rule_id}", response_model=RuleResponse)
async def update_rule(
    rule_id: int,
    body: RuleUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> RuleResponse:
    rule = await _get_rule_or_404(rule_id, db)
    await _require_rules_access(rule.client_id, current_user, db)

    before = _rule_to_dict(rule)

    if body.rule_name is not None:
        rule.rule_name = body.rule_name
    if body.description is not None:
        rule.description = body.description
    if body.category is not None:
        rule.category = body.category
    if body.conditions is not None:
        rule.conditions = body.conditions.model_dump()
    if body.severity is not None:
        rule.severity = body.severity
    if body.enabled is not None:
        rule.enabled = body.enabled

    rule.updated_by = current_user.id
    rule.updated_at = datetime.now(timezone.utc)

    await db.flush()

    await log_action(
        db=db,
        request=request,
        event_type="LAYER1_RULE_UPDATED",
        user_id=current_user.id,
        client_id=rule.client_id,
        target_id=rule.id,
        details={"before": before, "after": _rule_to_dict(rule)},
        flush_only=True,
    )
    await db.commit()
    await db.refresh(rule)
    return RuleResponse.model_validate(rule)


# ── DELETE /rules/{rule_id} ───────────────────────────────────────────────────

@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_rule(
    rule_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> None:
    rule = await _get_rule_or_404(rule_id, db)
    await _require_rules_access(rule.client_id, current_user, db)

    snapshot = _rule_to_dict(rule)
    await db.delete(rule)
    await db.flush()

    await log_action(
        db=db,
        request=request,
        event_type="LAYER1_RULE_DELETED",
        user_id=current_user.id,
        client_id=snapshot["client_id"],
        target_id=rule_id,
        details={"rule": snapshot},
        flush_only=True,
    )
    await db.commit()


# ── POST /rules/{rule_id}/toggle ──────────────────────────────────────────────

@router.post("/{rule_id}/toggle", response_model=RuleResponse)
async def toggle_rule(
    rule_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> RuleResponse:
    rule = await _get_rule_or_404(rule_id, db)
    await _require_rules_access(rule.client_id, current_user, db)

    before = _rule_to_dict(rule)
    rule.enabled = not rule.enabled
    rule.updated_by = current_user.id
    rule.updated_at = datetime.now(timezone.utc)

    await db.flush()

    await log_action(
        db=db,
        request=request,
        event_type="LAYER1_RULE_UPDATED",
        user_id=current_user.id,
        client_id=rule.client_id,
        target_id=rule.id,
        details={
            "before": before,
            "after": _rule_to_dict(rule),
            "action": "toggle",
        },
        flush_only=True,
    )
    await db.commit()
    await db.refresh(rule)
    return RuleResponse.model_validate(rule)


# ── POST /rules/{rule_id}/test ────────────────────────────────────────────────

@router.post("/{rule_id}/test", response_model=TestResult)
async def test_rule(
    rule_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> TestResult:
    """
    Dry-run: evaluate this rule against the last 24h of operational_events
    for the rule's client and category. Nothing is written.
    """
    rule = await _get_rule_or_404(rule_id, db)
    await _require_rules_access(rule.client_id, current_user, db)

    since = datetime.now(timezone.utc) - timedelta(hours=24)

    result = await db.execute(
        select(OperationalEvent).where(
            OperationalEvent.client_id == rule.client_id,
            OperationalEvent.query_name == rule.category,#to be checked
            OperationalEvent.timestamp >= since,
        )
    )
    events = result.scalars().all()

    rows: list[dict] = []
    for ev in events:
        row = {"id": ev.id, "timestamp": ev.timestamp, "fields": ev.fields or {}}
        row["_ts"] = ev.timestamp
        rows.append(row)

    cond = rule.conditions or {}
    matched_events: list[MatchedEvent] = []

    for row in rows:
        fields = {**row["fields"], "_ts": row["timestamp"]}
        matched, reason = _evaluate_condition(cond, fields, rows)
        if matched:
            matched_events.append(
                MatchedEvent(
                    event_id=row["id"],
                    timestamp=row["timestamp"],
                    fields_summary={
                        k: v for k, v in row["fields"].items()
                        if k in ("EventID", "TargetUserName", "SubjectUserName",
                                 "IpAddress", "CommandLine", "source")
                    },
                    match_reason=reason,
                )
            )

    return TestResult(
        rule=RuleResponse.model_validate(rule),
        period_hours=24,
        total_events_scanned=len(events),
        matched_count=len(matched_events),
        matched_events=matched_events[:10],
    )