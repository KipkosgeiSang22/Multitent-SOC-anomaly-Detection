"""
app/routers/bootstrap_train.py — Initial Model Training for newly onboarded clients

Registered in main.py:
    from app.routers import bootstrap_train
    app.include_router(bootstrap_train.router, prefix="/admin/bootstrap-train", tags=["bootstrap"])

Only superadmin can access these endpoints.

Endpoints:
  GET  /admin/bootstrap-train/readiness/{client_id}   — check data readiness per category
  POST /admin/bootstrap-train/start/{client_id}       — kick off background bootstrap training
  GET  /admin/bootstrap-train/status/{job_id}         — poll job status
"""
from __future__ import annotations

import logging
import os
import pickle
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import numpy as np
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from pydantic import BaseModel
from sklearn.ensemble import IsolationForest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import log_action
from app.core.config import settings
from app.core.dependencies import get_db, require_superadmin
from app.models.ml_model import MLModel
from app.models.user import User
from sqlalchemy import select

log = logging.getLogger(__name__)
router = APIRouter()

# ── Constants ──────────────────────────────────────────────────────────────────

CATEGORY_EVENT_IDS = {
    "AuthenticationEvents":    [4624, 4625, 4634, 4648, 4672],
    "AccountManagementEvents": [4720, 4722, 4723, 4724, 4725,
                                4726, 4728, 4729, 4732, 4733, 4781],
    "ProcessCreationEvents":   [4688, 4689],
}

REQUIRED_FEATURES = {
    "AuthenticationEvents":    ["Hour", "DayOfWeek", "IsWeekend", "EventID",
                                 "TargetUserName_Freq", "IpAddress_Freq"],
    "AccountManagementEvents": ["Hour", "DayOfWeek", "IsWeekend", "EventID",
                                 "SubjectUserName_Freq", "TargetUserName_Freq"],
    "ProcessCreationEvents":   ["Hour", "DayOfWeek", "IsWeekend", "EventID",
                                 "SubjectUserName_Freq", "CommandLine_Freq"],
}

# Maps JSONB field keys → feature column names for each category
FIELD_MAP = {
    "AuthenticationEvents": {
        "EventID":        "EventID",
        "TargetUserName": "TargetUserName_Freq",
        "IpAddress":      "IpAddress_Freq",
    },
    "AccountManagementEvents": {
        "EventID":         "EventID",
        "SubjectUserName": "SubjectUserName_Freq",
        "TargetUserName":  "TargetUserName_Freq",
    },
    "ProcessCreationEvents": {
        "EventID":      "EventID",
        "SubjectUserName": "SubjectUserName_Freq",
        "CommandLine":  "CommandLine_Freq",
    },
}

# Minimum rows required before a model will be trained
MIN_ROWS = 50

# ── In-memory job store ────────────────────────────────────────────────────────
_jobs: Dict[str, Dict[str, Any]] = {}


# ── Schemas ───────────────────────────────────────────────────────────────────

class CategoryReadiness(BaseModel):
    category: str
    event_count: int
    ready: bool
    min_required: int
    model_exists: bool
    trained_at: Optional[datetime]


class ReadinessResponse(BaseModel):
    client_id: int
    categories: List[CategoryReadiness]


class BootstrapStartRequest(BaseModel):
    categories: List[str]           # which categories to train
    contamination: float = 0.05     # IsolationForest contamination (0.01–0.2)
    notes: Optional[str] = None


class BootstrapStatusResponse(BaseModel):
    job_id: str
    status: str                     # queued | running | complete | failed | partial
    message: Optional[str] = None
    results: Optional[List[Dict[str, Any]]] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None


# ── Feature engineering (mirrors anomaly_engine pipeline) ────────────────────

def _build_freq_map(values: list) -> dict:
    """Build a frequency map: value → count/total (float in [0,1])."""
    from collections import Counter
    counts = Counter(v for v in values if v is not None)
    total = len(values) or 1
    return {k: v / total for k, v in counts.items()}


def _extract_features(rows: list, category: str) -> np.ndarray:
    """
    Given raw rows from operational_events (fields JSONB already expanded),
    compute the same feature columns that the anomaly engine uses so the
    bootstrap model is consistent with the scoring pipeline.

    Returns an (N, F) numpy array in the locked feature column order.
    """
    field_map = FIELD_MAP[category]
    features = REQUIRED_FEATURES[category]

    # Collect text columns for frequency mapping
    text_col_map: Dict[str, list] = {}
    for jsonb_key, feat_name in field_map.items():
        if feat_name.endswith("_Freq"):
            vals = [r.get(jsonb_key) for r in rows]
            freq = _build_freq_map(vals)
            text_col_map[feat_name] = freq

    matrix = []
    for row in rows:
        ts: datetime = row["timestamp"]
        if ts is None:
            continue

        vec = []
        for feat in features:
            if feat == "Hour":
                vec.append(float(ts.hour))
            elif feat == "DayOfWeek":
                vec.append(float(ts.weekday()))
            elif feat == "IsWeekend":
                vec.append(1.0 if ts.weekday() >= 5 else 0.0)
            elif feat == "EventID":
                # Find the JSONB key that maps to EventID
                raw_val = row.get("EventID") or row.get("eventid") or 0
                try:
                    vec.append(float(raw_val))
                except (ValueError, TypeError):
                    vec.append(0.0)
            elif feat.endswith("_Freq"):
                freq_map = text_col_map.get(feat, {})
                # Reverse-look up the JSONB key
                jsonb_key = next(
                    (k for k, v in field_map.items() if v == feat), None
                )
                raw_val = row.get(jsonb_key) if jsonb_key else None
                vec.append(freq_map.get(raw_val, 0.0))
            else:
                vec.append(0.0)
        matrix.append(vec)

    return np.array(matrix, dtype=float)


# ── Background training task ──────────────────────────────────────────────────

async def _run_bootstrap(
    job_id: str,
    client_id: int,
    categories: List[str],
    contamination: float,
    notes: Optional[str],
    admin_id: int,
    model_base_path: str,
):
    from app.db.session import AsyncSessionLocal

    _jobs[job_id]["status"] = "running"
    _jobs[job_id]["started_at"] = datetime.now(timezone.utc)
    results = []

    for category in categories:
        cat_result = {"category": category, "status": "pending", "rows": 0}
        event_ids = CATEGORY_EVENT_IDS[category]

        try:
            async with AsyncSessionLocal() as db:
                # Pull raw events from operational_events.
                # We use the JSONB fields column — expand EventID for filtering.
                sql = text("""
                    SELECT
                        id,
                        timestamp,
                        fields
                    FROM operational_events
                    WHERE client_id = :client_id
                      AND query_name = :query_name
                      AND (fields->>'EventID')::int = ANY(:event_ids)
                    ORDER BY timestamp ASC
                """)
                result = await db.execute(sql, {
                    "client_id": client_id,
                    "query_name": category,
                    "event_ids": event_ids,
                })
                raw_rows = result.mappings().all()

                if len(raw_rows) < MIN_ROWS:
                    cat_result.update({
                        "status": "skipped",
                        "message": (
                            f"Only {len(raw_rows)} events found "
                            f"(need ≥ {MIN_ROWS}). Collect more data first."
                        ),
                        "rows": len(raw_rows),
                    })
                    results.append(cat_result)
                    continue

                # Expand JSONB fields into flat dicts for feature extraction
                flat_rows = []
                for row in raw_rows:
                    d = dict(row["fields"] or {})
                    d["timestamp"] = row["timestamp"]
                    flat_rows.append(d)

                X = _extract_features(flat_rows, category)

                if X.shape[0] < MIN_ROWS:
                    cat_result.update({
                        "status": "skipped",
                        "message": f"Feature extraction yielded only {X.shape[0]} valid rows.",
                        "rows": X.shape[0],
                    })
                    results.append(cat_result)
                    continue

                # Train IsolationForest
                model = IsolationForest(
                    n_estimators=100,
                    contamination=contamination,
                    random_state=42,
                    n_jobs=-1,
                )
                model.fit(X)
                training_rows = X.shape[0]

                # Persist model file
                model_dir = os.path.join(model_base_path, str(client_id))
                os.makedirs(model_dir, exist_ok=True)
                pkl_path = os.path.join(model_dir, f"{category}.pkl")
                bak_path = os.path.join(model_dir, f"{category}.bak.pkl")

                # Backup existing model if present
                if os.path.exists(pkl_path):
                    import shutil
                    shutil.copy2(pkl_path, bak_path)
                    log.info(f"Bootstrap backed up existing: {pkl_path} → {bak_path}")

                with open(pkl_path, "wb") as f:
                    pickle.dump(model, f)
                log.info(
                    f"Bootstrap saved model: {pkl_path} "
                    f"(client={client_id}, category={category}, rows={training_rows})"
                )

                # Upsert ml_models record
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
                    ml_model.trained_by = admin_id
                    ml_model.training_rows = training_rows
                    ml_model.feature_columns = REQUIRED_FEATURES[category]
                    ml_model.excluded_event_ids = []
                    ml_model.notes = notes or f"Bootstrap training — {training_rows} rows"
                else:
                    ml_model = MLModel(
                        client_id=client_id,
                        category=category,
                        model_path=pkl_path,
                        backup_path=bak_path,
                        trained_at=trained_at,
                        trained_by=admin_id,
                        training_rows=training_rows,
                        feature_columns=REQUIRED_FEATURES[category],
                        excluded_event_ids=[],
                        notes=notes or f"Bootstrap training — {training_rows} rows",
                        is_active=True,
                    )
                    db.add(ml_model)

                await db.flush()

                # Audit log
                import json as _json
                await db.execute(text("""
                    INSERT INTO audit_log
                        (user_id, role, event_type, client_id, target_id, details,
                         ip_address, user_agent, performed_at)
                    VALUES
                        (:user_id, 'superadmin', 'MODEL_RETRAINED', :client_id,
                         :target_id, cast(:details as jsonb),
                         'admin-ui', 'bootstrap-train', NOW())
                """), {
                    "user_id": admin_id,
                    "client_id": client_id,
                    "target_id": ml_model.id,
                    "details": _json.dumps({
                        "category": category,
                        "training_rows": training_rows,
                        "contamination": contamination,
                        "job_id": job_id,
                        "bootstrap": True,
                        "notes": notes,
                    }),
                })

                await db.commit()

                cat_result.update({
                    "status": "complete",
                    "rows": training_rows,
                    "message": f"Model trained on {training_rows} events.",
                    "model_path": pkl_path,
                    "trained_at": trained_at.isoformat(),
                })

        except Exception as exc:
            log.exception(
                f"Bootstrap job {job_id} failed for {category}: {exc}"
            )
            cat_result.update({
                "status": "failed",
                "message": str(exc),
            })

        results.append(cat_result)

    # Determine overall job status
    statuses = {r["status"] for r in results}
    if statuses == {"complete"}:
        overall = "complete"
    elif statuses == {"skipped"}:
        overall = "skipped"
    elif "complete" in statuses:
        overall = "partial"
    elif "failed" in statuses:
        overall = "failed"
    else:
        overall = "skipped"

    _jobs[job_id].update({
        "status": overall,
        "results": results,
        "finished_at": datetime.now(timezone.utc),
        "message": f"Processed {len(results)} categories.",
    })
    log.info(f"Bootstrap job {job_id} finished with status={overall}")


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/readiness/{client_id}", response_model=ReadinessResponse)
async def check_readiness(
    client_id: int,
    current_user: User = Depends(require_superadmin),
    db: AsyncSession = Depends(get_db),
):
    """
    Returns event counts per ML category for the given client and
    whether the threshold for training has been reached.
    Also reports if a model already exists.
    """
    categories_out = []

    for category, event_ids in CATEGORY_EVENT_IDS.items():
        # Count events
        count_result = await db.execute(text("""
            SELECT COUNT(*) FROM operational_events
            WHERE client_id = :client_id
              AND query_name = :query_name
              AND (fields->>'EventID')::int = ANY(:event_ids)
        """), {
            "client_id": client_id,
            "query_name": category,
            "event_ids": event_ids,
        })
        event_count = count_result.scalar() or 0

        # Check existing model
        ml_result = await db.execute(
            select(MLModel).where(
                MLModel.client_id == client_id,
                MLModel.category == category,
                MLModel.is_active.is_(True),
            )
        )
        ml_model = ml_result.scalar_one_or_none()

        categories_out.append(CategoryReadiness(
            category=category,
            event_count=event_count,
            ready=(event_count >= MIN_ROWS),
            min_required=MIN_ROWS,
            model_exists=(ml_model is not None),
            trained_at=ml_model.trained_at if ml_model else None,
        ))

    return ReadinessResponse(client_id=client_id, categories=categories_out)


@router.post("/start/{client_id}", response_model=BootstrapStatusResponse, status_code=202)
async def start_bootstrap_training(
    client_id: int,
    body: BootstrapStartRequest,
    background_tasks: BackgroundTasks,
    request: Request,
    current_user: User = Depends(require_superadmin),
    db: AsyncSession = Depends(get_db),
):
    """
    Kick off initial model training for one or more ML categories.
    Training runs as a background task. Poll /status/{job_id} for progress.
    """
    # Validate categories
    invalid = [c for c in body.categories if c not in CATEGORY_EVENT_IDS]
    if invalid:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid categories: {invalid}. "
                   f"Must be one of: {list(CATEGORY_EVENT_IDS.keys())}",
        )

    if not (0.01 <= body.contamination <= 0.20):
        raise HTTPException(
            status_code=400,
            detail="contamination must be between 0.01 and 0.20",
        )

    model_base_path = getattr(settings, "MODEL_BASE_PATH", "/opt/soc_platform/models")
    job_id = str(uuid.uuid4())

    _jobs[job_id] = {
        "status": "queued",
        "message": "Queued for background processing",
        "results": None,
        "started_at": None,
        "finished_at": None,
    }

    background_tasks.add_task(
        _run_bootstrap,
        job_id=job_id,
        client_id=client_id,
        categories=body.categories,
        contamination=body.contamination,
        notes=body.notes,
        admin_id=current_user.id,
        model_base_path=model_base_path,
    )

    log.info(
        f"Bootstrap training job {job_id} queued: "
        f"client={client_id}, categories={body.categories}"
    )

    return BootstrapStatusResponse(
        job_id=job_id,
        status="queued",
        message=f"Training queued for {len(body.categories)} category(s).",
    )


@router.get("/status/{job_id}", response_model=BootstrapStatusResponse)
async def get_bootstrap_status(
    job_id: str,
    current_user: User = Depends(require_superadmin),
):
    """Poll background training job status."""
    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    return BootstrapStatusResponse(
        job_id=job_id,
        status=job["status"],
        message=job.get("message"),
        results=job.get("results"),
        started_at=job.get("started_at"),
        finished_at=job.get("finished_at"),
    )
