"""
app/routers/retrain.py — Session 11: ML Retraining endpoint + rollback
Registered in main.py: prefix="/retrain", tags=["retrain"]

Permission gate (same pattern as rules.py):
  Superadmin: always allowed
  Analyst: needs can_retrain_models=True AND client_id in scope

Endpoints:
  GET  /retrain/{client_id}/{category}          — preview data (step 1)
  POST /retrain/start                           — kick off background retrain (steps 2-4)
  GET  /retrain/status/{job_id}                 — poll job status
  POST /retrain/rollback/{client_id}/{category} — rollback to .bak.pkl (step 5)
"""


from __future__ import annotations

import asyncio
import logging
import os
import pickle
import shutil
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession
import joblib as _joblib

from app.core.audit import log_action
from app.core.config import settings
from app.core.dependencies import get_current_user, get_db
from app.models.analyst_permission import AnalystPermission
from app.models.anomaly import Anomaly
from app.models.auth_event import AuthEvent
from app.models.ml_model import MLModel
from app.models.user import User
from app.schemas.retrain import (
    RetrainPreviewResponse,
    RetrainRollbackResponse,
    RetrainStartRequest,
    RetrainStatusResponse,
)

log = logging.getLogger(__name__)
router = APIRouter()

# ── In-memory job store (simple; survives single process lifetime) ─────────────
_jobs: Dict[str, Dict[str, Any]] = {}

# ── Category → model table mapping ────────────────────────────────────────────
CATEGORY_TABLES = {
    "AuthenticationEvents": "auth_events",
    "AccountManagementEvents": "account_events",
    "ProcessCreationEvents": "process_events",
}

# Required feature columns per category (locked — must always be in model)
REQUIRED_FEATURES = {
    "AuthenticationEvents":    ["Hour", "DayOfWeek", "IsWeekend", "EventID",
                                 "TargetUserName_Freq", "IpAddress_Freq"],
    "AccountManagementEvents": ["Hour", "DayOfWeek", "IsWeekend", "EventID",
                                 "SubjectUserName_Freq", "TargetUserName_Freq"],
    "ProcessCreationEvents":   ["Hour", "DayOfWeek", "IsWeekend", "EventID",
                                 "SubjectUserName_Freq", "CommandLine_Freq"],
}

# DB column → feature name mapping (typed table uses snake_case)
COL_TO_FEATURE = {
    "hour": "Hour",
    "day_of_week": "DayOfWeek",
    "is_weekend": "IsWeekend",
    "event_id": "EventID",
    "target_username_freq": "TargetUserName_Freq",
    "ip_address_freq": "IpAddress_Freq",
    "subject_username_freq": "SubjectUserName_Freq",
    "command_line_freq": "CommandLine_Freq",
}


# ── Permission helper ─────────────────────────────────────────────────────────
async def _check_retrain_permission(
    db: AsyncSession, current_user: User, client_id: int
) -> None:
    if current_user.role == "superadmin":
        return
    if current_user.role != "analyst":
        raise HTTPException(status_code=403, detail="Access denied")

    result = await db.execute(
        select(AnalystPermission).where(
            AnalystPermission.analyst_id == current_user.id,
            AnalystPermission.revoked_at.is_(None),
            AnalystPermission.can_retrain_models.is_(True),
        )
    )
    perm = result.scalar_one_or_none()
    if not perm:
        raise HTTPException(status_code=403, detail="can_retrain_models permission required")

    scope = perm.client_scope or []
    if scope != ["ALL"] and client_id not in scope:
        raise HTTPException(status_code=403, detail="Client not in your scope")


# ── Step 1: Preview data ───────────────────────────────────────────────────────
@router.get("/preview/{client_id}/{category}", response_model=RetrainPreviewResponse)
async def preview_retrain_data(
    client_id: int,
    category: str,
    period_start: datetime = Query(...),
    period_end: datetime = Query(...),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=10, le=200),
    request: Request = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if category not in CATEGORY_TABLES:
        raise HTTPException(status_code=400, detail=f"Invalid category. Must be one of: {list(CATEGORY_TABLES)}")

    await _check_retrain_permission(db, current_user, client_id)

    table = CATEGORY_TABLES[category]
    offset = (page - 1) * page_size

    # Raw SQL — typed tables are fixed-schema, join anomalies for score/type/layer
    sql = text(f"""
        SELECT
            te.*,
            an.id          AS anomaly_id,
            an.anomaly_type,
            an.layer,
            an.anomaly_score AS an_score,
            an.is_false_positive,
            an.details     AS anomaly_details
        FROM {table} te
        LEFT JOIN anomalies an
            ON an.typed_event_id = te.id
            AND an.category = :category
        WHERE te.client_id = :client_id
          AND te.timestamp BETWEEN :period_start AND :period_end
        ORDER BY COALESCE(an.anomaly_score, 0) ASC
        LIMIT :limit OFFSET :offset
    """)

    count_sql = text(f"""
        SELECT COUNT(*) FROM {table} te
        WHERE te.client_id = :client_id
          AND te.timestamp BETWEEN :period_start AND :period_end
    """)

    rows_result = await db.execute(sql, {
        "category": category,
        "client_id": client_id,
        "period_start": period_start,
        "period_end": period_end,
        "limit": page_size,
        "offset": offset,
    })
    count_result = await db.execute(count_sql, {
        "client_id": client_id,
        "period_start": period_start,
        "period_end": period_end,
    })

    rows = rows_result.mappings().all()
    total = count_result.scalar()

    # Serialize — convert datetimes to ISO strings
    serialized = []
    for row in rows:
        d = dict(row)
        for k, v in d.items():
            if isinstance(v, datetime):
                d[k] = v.isoformat()
        serialized.append(d)

    return RetrainPreviewResponse(
        total=total,
        page=page,
        page_size=page_size,
        rows=serialized,
    )


# ── Background retrain task ───────────────────────────────────────────────────
async def _run_retrain(
    job_id: str,
    req: RetrainStartRequest,
    analyst_id: int,
    model_base_path: str,
):
    """
    Runs in background. Queries typed table, trains IsolationForest,
    backs up old model, saves new model, updates ml_models row.
    """
    from sklearn.ensemble import IsolationForest
    import numpy as np
    from app.db.session import AsyncSessionLocal

    _jobs[job_id]["status"] = "running"
    category = req.category
    client_id = req.client_id
    table = CATEGORY_TABLES[category]
    feature_cols = REQUIRED_FEATURES[category]

    try:
        async with AsyncSessionLocal() as db:
            # Build query: exclude true positives, include forced false positives
            exclude_clause = ""
            if req.exclude_ids:
                ids = ",".join(str(i) for i in req.exclude_ids)
                exclude_clause = f"AND te.id NOT IN ({ids})"

            include_clause = ""
            if req.include_ids:
                ids = ",".join(str(i) for i in req.include_ids)
                include_clause = f"OR te.id IN ({ids})"

            sql = text(f"""
                SELECT
                    te.*,
                    oe.all_timestamps
                FROM {table} te
                JOIN operational_events oe
                    ON oe.id = te.operational_event_id
                WHERE (
                    te.client_id = :client_id
                    AND te.timestamp BETWEEN :period_start AND :period_end
                    {exclude_clause}
                )
                {include_clause}
            """)

            result = await db.execute(sql, {
                "client_id": client_id,
                "period_start": req.period_start,
                "period_end": req.period_end,
            })
            rows = result.mappings().all()

            if len(rows) < 10:
                _jobs[job_id].update({
                    "status": "failed",
                    "message": f"Not enough training rows ({len(rows)}). Need at least 10.",
                })
                return

            import pytz as _pytz
            from collections import Counter as _Counter
            EAT_TZ = _pytz.timezone("Africa/Nairobi")

            # ── Step 1: Build fresh freq maps from raw text columns ───────────
            # Must happen BEFORE expansion so get_feature_val can use them.
            # Each occurrence counts independently — repeat value n times
            # where n = number of timestamps in all_timestamps for that row.
            def _build_freq_map_from_rows(values: list) -> dict:
                counts = _Counter(v for v in values if v is not None)
                total = len(values) or 1
                return {k: v / total for k, v in counts.items()}

            freq_maps = {}
            if category == "AuthenticationEvents":
                tu_vals, ip_vals = [], []
                for r in rows:
                    row = dict(r)
                    n = max(len(row.get("all_timestamps") or []), 1)
                    tu_vals.extend([row.get("target_username")] * n)
                    ip_vals.extend([row.get("ip_address")] * n)
                    #duplicates n times eg [ josh, josh, josh, victoria, victoria, when building freq, josh will be 3/5 and victoria will be 2/5]
                freq_maps["TargetUserName_Freq"] = _build_freq_map_from_rows(tu_vals)
                freq_maps["IpAddress_Freq"]       = _build_freq_map_from_rows(ip_vals)
            elif category == "AccountManagementEvents":
                su_vals, tu_vals = [], []
                for r in rows:
                    row = dict(r)
                    n = max(len(row.get("all_timestamps") or []), 1)
                    su_vals.extend([row.get("subject_username")] * n)
                    tu_vals.extend([row.get("target_username")] * n)
                freq_maps["SubjectUserName_Freq"] = _build_freq_map_from_rows(su_vals)
                freq_maps["TargetUserName_Freq"]  = _build_freq_map_from_rows(tu_vals)
            elif category == "ProcessCreationEvents":
                su_vals, cl_vals = [], []
                for r in rows:
                    row = dict(r)
                    n = max(len(row.get("all_timestamps") or []), 1)
                    su_vals.extend([row.get("subject_username")] * n)
                    cl_vals.extend([row.get("command_line")] * n)
                freq_maps["SubjectUserName_Freq"] = _build_freq_map_from_rows(su_vals)
                freq_maps["CommandLine_Freq"]     = _build_freq_map_from_rows(cl_vals)

            # Raw text column names used to look up fresh freq per occurrence
            RAW_TEXT_COLS = {
                "AuthenticationEvents": {
                    "TargetUserName_Freq": "target_username",
                    "IpAddress_Freq":      "ip_address",
                },
                "AccountManagementEvents": {
                    "SubjectUserName_Freq": "subject_username",
                    "TargetUserName_Freq":  "target_username",
                },
                "ProcessCreationEvents": {
                    "SubjectUserName_Freq": "subject_username",
                    "CommandLine_Freq":     "command_line",
                },
            }
            raw_text_cols = RAW_TEXT_COLS[category]

            def get_feature_val(row: dict, feature: str) -> float:
                """
                For _Freq features: look up raw text value in freshly built
                freq_maps — NOT the old pre-computed freq stored in typed row.
                For EventID: read directly from typed row.
                Time features handled separately in the expansion loop.
                """
                if feature.endswith("_Freq"):
                    raw_col = raw_text_cols.get(feature)
                    raw_val = row.get(raw_col) if raw_col else None
                    return freq_maps.get(feature, {}).get(raw_val, 0.0)
                elif feature == "EventID":
                    v = row.get("event_id")
                    return float(v) if v is not None else 0.0
                return 0.0

            # ── Step 2: Expand rows — one training vector per occurrence ──────
            expanded_rows = []
            for r in rows:
                row = dict(r)
                all_ts = row.get("all_timestamps") or []

                # Parse stored timestamp strings back to EAT datetimes
                timestamps = []
                for ts_str in all_ts:
                    try:
                        ts_dt = datetime.strptime(
                            ts_str, "%Y-%m-%d %H:%M:%S"
                        ).replace(tzinfo=EAT_TZ)
                        timestamps.append(ts_dt)
                    except ValueError:
                        continue

                # Fallback to the typed row's single timestamp
                if not timestamps:
                    ts = row.get("timestamp")
                    if ts is not None:
                        if ts.tzinfo is None:
                            ts = ts.replace(tzinfo=EAT_TZ)
                        timestamps = [ts.astimezone(EAT_TZ)]

                # One training vector per occurrence
                for ts in timestamps:
                    vec = []
                    for feat in feature_cols:
                        if feat == "Hour":
                            vec.append(float(ts.hour))
                        elif feat == "DayOfWeek":
                            vec.append(float(ts.weekday()))
                        elif feat == "IsWeekend":
                            vec.append(1.0 if ts.weekday() >= 5 else 0.0)
                        else:
                            # EventID and _Freq features — use fresh freq maps
                            # NOT the old pre-computed freq stored in typed row
                            vec.append(get_feature_val(row, feat))
                    expanded_rows.append(vec)

            if not expanded_rows:
                _jobs[job_id].update({
                    "status": "failed",
                    "message": "No training vectors could be built from the selected rows.",
                })
                return

            X = np.array(expanded_rows, dtype=float)

            # Train
            model = IsolationForest(contamination=0.1, random_state=42)
            model.fit(X)
            training_rows = len(X)

            # Paths
            model_dir = os.path.join(model_base_path, str(client_id))
            os.makedirs(model_dir, exist_ok=True)
            pkl_path = os.path.join(model_dir, f"{category}.pkl")
            bak_path = os.path.join(model_dir, f"{category}.bak.pkl")

# Backup existing
            if os.path.exists(pkl_path):
                shutil.copy2(pkl_path, bak_path)
                log.info(f"Backed up {pkl_path} → {bak_path}")

            model_artifact = {
                "model": model,
                "freq_maps": freq_maps,
                "feature_columns": feature_cols,
                "category": category,
                "trained_at": datetime.now(timezone.utc).isoformat(),
                "training_rows": training_rows,
            }

            _joblib.dump(model_artifact, pkl_path)
            log.info(f"Saved new model artifact: {pkl_path} ({training_rows} rows)")

            # Update ml_models row
            trained_at = datetime.now(timezone.utc)
            ml_result = await db.execute(
                select(MLModel).where(
                    MLModel.client_id == client_id,
                    MLModel.category == category,
                    MLModel.is_active.is_(True),
                )
            )
            ml_model = ml_result.scalar_one_or_none()

            if ml_model:
                ml_model.model_path = pkl_path
                ml_model.backup_path = bak_path
                ml_model.trained_at = trained_at
                ml_model.trained_by = analyst_id
                ml_model.training_rows = training_rows
                ml_model.feature_columns = feature_cols
                ml_model.excluded_event_ids = req.exclude_ids or []
                ml_model.notes = req.notes
            else:
                # First-time: create record
                ml_model = MLModel(
                    client_id=client_id,
                    category=category,
                    model_path=pkl_path,
                    backup_path=bak_path,
                    trained_at=trained_at,
                    trained_by=analyst_id,
                    training_rows=training_rows,
                    feature_columns=feature_cols,
                    excluded_event_ids=req.exclude_ids or [],
                    notes=req.notes,
                    is_active=True,
                )
                db.add(ml_model)

            await db.flush()

            # Audit log - background task has no Request object, use raw insert
            import json as _json
            audit_details = _json.dumps({
                "category": category,
                "training_rows": training_rows,
                "job_id": job_id,
                "exclude_ids": req.exclude_ids,
                "notes": req.notes,
            })
            await db.execute(text("""
                INSERT INTO audit_log
                    (user_id, role, event_type, client_id, target_id, details,
                     ip_address, user_agent, performed_at)
                VALUES
                    (:user_id, 'analyst', 'MODEL_RETRAINED', :client_id, :target_id,
                     cast(:details as jsonb), 'scheduler', 'retrain-bg-task', NOW())
            """), {
                "user_id": analyst_id,
                "client_id": client_id,
                "target_id": ml_model.id if ml_model.id else None,
                "details": audit_details,
            })

            await db.commit()

            _jobs[job_id].update({
                "status": "complete",
                "message": f"Model retrained on {training_rows} rows.",
                "trained_at": trained_at.isoformat(),
                "training_rows": training_rows,
            })
            log.info(f"Retrain job {job_id} complete: {client_id}/{category}, {training_rows} rows")

    except Exception as exc:
        log.exception(f"Retrain job {job_id} failed: {exc}")
        _jobs[job_id].update({"status": "failed", "message": str(exc)})


# ── Step 2/3: Start retrain ────────────────────────────────────────────────────
# Register /start BEFORE /{client_id}/{category} to avoid routing collision
@router.post("/start", response_model=RetrainStatusResponse)
async def start_retrain(
    body: RetrainStartRequest,
    background_tasks: BackgroundTasks,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if body.category not in CATEGORY_TABLES:
        raise HTTPException(status_code=400, detail=f"Invalid category")

    await _check_retrain_permission(db, current_user, body.client_id)

    if body.period_end <= body.period_start:
        raise HTTPException(status_code=400, detail="period_end must be after period_start")

    job_id = str(uuid.uuid4())
    _jobs[job_id] = {"status": "started", "message": "Queued"}

    model_base_path = getattr(settings, "MODEL_BASE_PATH", "/opt/soc_platform/models")
    background_tasks.add_task(
        _run_retrain,
        job_id=job_id,
        req=body,
        analyst_id=current_user.id,
        model_base_path=model_base_path,
    )

    log.info(f"Retrain job {job_id} queued: client={body.client_id} category={body.category}")
    return RetrainStatusResponse(job_id=job_id, status="started")


# ── Step 4: Poll status ────────────────────────────────────────────────────────
@router.get("/status/{job_id}", response_model=RetrainStatusResponse)
async def retrain_status(
    job_id: str,
    current_user: User = Depends(get_current_user),
):
    if current_user.role not in ("superadmin", "analyst"):
        raise HTTPException(status_code=403, detail="Access denied")
    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    trained_at = job.get("trained_at")
    return RetrainStatusResponse(
        job_id=job_id,
        status=job["status"],
        message=job.get("message"),
        trained_at=datetime.fromisoformat(trained_at) if trained_at else None,
        training_rows=job.get("training_rows"),
    )


# ── Step 5: Rollback ──────────────────────────────────────────────────────────
@router.post("/rollback/{client_id}/{category}", response_model=RetrainRollbackResponse)
async def rollback_model(
    client_id: int,
    category: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if category not in CATEGORY_TABLES:
        raise HTTPException(status_code=400, detail="Invalid category")

    await _check_retrain_permission(db, current_user, client_id)

    result = await db.execute(
        select(MLModel).where(
            MLModel.client_id == client_id,
            MLModel.category == category,
            MLModel.is_active.is_(True),
        )
    )
    ml_model = result.scalar_one_or_none()
    if not ml_model:
        raise HTTPException(status_code=404, detail="No active model found for this client/category")

    bak = ml_model.backup_path
    pkl = ml_model.model_path

    if not bak or not os.path.exists(bak):
        raise HTTPException(status_code=409, detail="No backup model found — cannot rollback")

    try:
        shutil.copy2(bak, pkl)
        log.info(f"Rolled back {bak} → {pkl}")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Rollback file copy failed: {exc}")

    rolled_back_at = datetime.now(timezone.utc)
    ml_model.trained_at = rolled_back_at
    ml_model.trained_by = current_user.id
    ml_model.notes = f"Rolled back by {current_user.username} at {rolled_back_at.isoformat()}"

    await db.flush()
#where does log_action write to and where does lo write to
    await log_action(
        db=db,
        request=request,
        event_type="MODEL_ROLLED_BACK",
        user_id=current_user.id,
        client_id=client_id,
        target_id=ml_model.id,
        details={
            "category": category,
            "pkl_path": pkl,
            "bak_path": bak,
            "rolled_back_at": rolled_back_at.isoformat(),
        },
        flush_only=True,
    )

    await db.commit()

    return RetrainRollbackResponse(
        client_id=client_id,
        category=category,
        model_path=pkl,
        backup_path=bak,
        message="Rollback successful. Previous model restored.",
        rolled_back_at=rolled_back_at,
    )
#TODO Contamination parameter should be from request
# Bootstrap (bootstrap_train.py):

# Reads from operational_events only
# Reads the raw JSONB fields (PascalCase keys like TargetUserName, IpAddress)
# Trains the model and saves the .pkl file
# Writes to ml_models table only
# Never touches auth_events, account_events, process_events

# Anomaly Engine (anomaly_engine.py):

# Reads from operational_events (unanalyzed rows)
# Scores them using the model
# Writes to auth_events, account_events, process_events — these typed rows have the snake_case columns (target_username, ip_address) because they're proper PostgreSQL columns
# Writes to anomalies
# Sets analyzed_at on the operational_events rows

# Retrain (retrain.py):

# Reads from the typed tables (auth_events etc.) — snake_case columns — because the analyst is reviewing already-scored events
# Retrains the model using those rows
# Saves new .pkl file
# Updates ml_models
# Never writes back to the typed tables