"""
anomaly_engine.py — Pipeline 2
Runs every 5 minutes. Reads unanalyzed operational_events, runs L1 rules +
L2 Isolation Forest, writes typed tables + anomalies, sets analyzed_at.

Run: cd backend && python -m schedulers.anomaly_engine
"""
import asyncio
import json
import logging
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

import joblib
import numpy as np
import pandas as pd
import pytz
from dotenv import load_dotenv
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("anomaly_engine")

# ── Config ────────────────────────────────────────────────────────────────────
DATABASE_URL = os.environ["DATABASE_URL"]
MODEL_BASE_PATH = os.getenv("MODEL_BASE_PATH", "/opt/soc_platform/models")
AUTH_THRESHOLD = float(os.getenv("AUTH_THRESHOLD", "-0.1"))
ACCOUNT_THRESHOLD = float(os.getenv("ACCOUNT_THRESHOLD", "-0.1"))
PROCESS_THRESHOLD = float(os.getenv("PROCESS_THRESHOLD", "-0.15"))
SLEEP = int(os.getenv("ENGINE_SLEEP_SECONDS", "300"))
MOCK_MODE = os.getenv("ENGINE_MOCK_MODE", "false").lower() == "true"

EAT = pytz.timezone("Africa/Nairobi")

engine = create_async_engine(DATABASE_URL, pool_size=5, max_overflow=10)
Session = async_sessionmaker(engine, expire_on_commit=False)

# ── Category definitions ──────────────────────────────────────────────────────
CATEGORIES = {
    "AuthenticationEvents": {
        "event_ids": [4624, 4625, 4634, 4648, 4672],
        "threshold": AUTH_THRESHOLD,
        "features": ["Hour", "DayOfWeek", "IsWeekend", "EventID",
                     "TargetUserName_Freq", "IpAddress_Freq"],
        "typed_table": "auth_events",
    },
    "AccountManagementEvents": {
        "event_ids": [4720, 4722, 4723, 4724, 4725, 4726,
                      4728, 4729, 4732, 4733, 4781],
        "threshold": ACCOUNT_THRESHOLD,
        "features": ["Hour", "DayOfWeek", "IsWeekend", "EventID",
                     "SubjectUserName_Freq", "TargetUserName_Freq"],
        "typed_table": "account_events",
    },
    "ProcessCreationEvents": {
        "event_ids": [4688, 4689],
        "threshold": PROCESS_THRESHOLD,
        "features": ["Hour", "DayOfWeek", "IsWeekend", "EventID",
                     "SubjectUserName_Freq", "CommandLine_Freq"],
        "typed_table": "process_events",
    },
}

# LOLBins + suspicious patterns for L1 process rules
LOLBIN_PATTERNS = [
    "certutil", "bitsadmin", "mshta", "wscript", "cscript",
    "regsvr32", "rundll32", "powershell -enc", "powershell -e ",
    "net user", "net localgroup", "whoami", "mimikatz",
    "invoke-expression", "iex(", "downloadstring",
]

# Off-hours: outside 07:00–19:00 EAT
OFF_HOURS_START = 19
OFF_HOURS_END = 7


# ── Feature engineering ───────────────────────────────────────────────────────

def add_time_features(df: pd.DataFrame) -> pd.DataFrame:
    """Extract Hour, DayOfWeek, IsWeekend from timestamp column."""
    ts = pd.to_datetime(df["timestamp"], utc=True)
    df["Hour"] = ts.dt.hour
    df["DayOfWeek"] = ts.dt.dayofweek
    df["IsWeekend"] = ts["DayOfWeek"].isin([5, 6]).astype(int) if "DayOfWeek" in ts else df["DayOfWeek"].isin([5, 6]).astype(int)
    return df


def apply_freq_map(df: pd.DataFrame, column: str) -> pd.DataFrame:
    """Map text column to frequency float, adding {column}_Freq."""
    if column not in df.columns:
        df[column] = ""
    freq = df[column].astype(str).value_counts(normalize=True)
    df[f"{column}_Freq"] = df[column].astype(str).map(freq).fillna(0.0)
    return df


def engineer_features(df: pd.DataFrame, category: str) -> pd.DataFrame:
    df = add_time_features(df)
    if category == "AuthenticationEvents":
        df = apply_freq_map(df, "TargetUserName")
        df = apply_freq_map(df, "IpAddress")
    elif category == "AccountManagementEvents":
        df = apply_freq_map(df, "SubjectUserName")
        df = apply_freq_map(df, "TargetUserName")
    elif category == "ProcessCreationEvents":
        df = apply_freq_map(df, "SubjectUserName")
        df = apply_freq_map(df, "CommandLine")
    return df


# ── Model loading ─────────────────────────────────────────────────────────────

_model_cache: dict[str, object] = {}


def load_model(client_id: int, category: str, model_path: str):
    """Load .pkl model with simple in-process cache. Returns None on failure."""
    cache_key = f"{client_id}:{category}"
    if cache_key in _model_cache:
        return _model_cache[cache_key]
    try:
        model = joblib.load(model_path)
        _model_cache[cache_key] = model
        log.info("Loaded model client=%d category=%s", client_id, category)
        return model
    except Exception as e:
        log.critical("Cannot load model client=%d category=%s path=%s: %s",
                     client_id, category, model_path, e)
        return None


def invalidate_model_cache(client_id: int, category: str):
    _model_cache.pop(f"{client_id}:{category}", None)


# ── DB helpers ────────────────────────────────────────────────────────────────

async def get_active_clients(db: AsyncSession) -> list[dict]:
    rows = await db.execute(
        text("SELECT id, name FROM clients WHERE active = true")
    )
    return [dict(r._mapping) for r in rows.fetchall()]


async def get_unanalyzed_events(db: AsyncSession, client_id: int,
                                category: str, event_ids: list[int]) -> list[dict]:
    ids_str = ",".join(str(i) for i in event_ids)
    rows = await db.execute(text(f"""
        SELECT id, client_id, query_name, timestamp, source_host, fields
        FROM operational_events
        WHERE client_id = :cid
          AND analyzed_at IS NULL
          AND query_name = :qname
          AND (fields->>'EventID')::int IN ({ids_str})
        ORDER BY timestamp ASC
        LIMIT 2000
    """), {"cid": client_id, "qname": category})
    return [dict(r._mapping) for r in rows.fetchall()]


async def get_layer1_rules(db: AsyncSession, client_id: int, category: str) -> list[dict]:
    rows = await db.execute(text("""
        SELECT id, rule_name, description, conditions, severity
        FROM layer1_rules
        WHERE client_id = :cid AND category = :cat AND enabled = true
    """), {"cid": client_id, "cat": category})
    return [dict(r._mapping) for r in rows.fetchall()]


async def get_model_path(db: AsyncSession, client_id: int, category: str) -> Optional[str]:
    row = await db.execute(text("""
        SELECT model_path FROM ml_models
        WHERE client_id = :cid AND category = :cat AND is_active = true
        LIMIT 1
    """), {"cid": client_id, "cat": category})
    result = row.fetchone()
    return result[0] if result else None


async def get_threat_iocs(db: AsyncSession) -> list[dict]:
    """Load all IOC entries for cross-referencing."""
    rows = await db.execute(text("SELECT id, iocs FROM threat_intel WHERE iocs IS NOT NULL"))
    result = []
    for r in rows.fetchall():
        iocs = r[1]
        if isinstance(iocs, str):
            iocs = json.loads(iocs)
        result.append({"id": r[0], "iocs": iocs if isinstance(iocs, list) else []})
    return result


async def insert_typed_event(db: AsyncSession, table: str, row: dict) -> Optional[int]:
    """Insert into auth_events / account_events / process_events. Returns new id."""
    cols = ", ".join(row.keys())
    placeholders = ", ".join(f":{k}" for k in row.keys())
    result = await db.execute(
        text(f"INSERT INTO {table} ({cols}) VALUES ({placeholders}) RETURNING id"),
        row
    )
    r = result.fetchone()
    return r[0] if r else None


async def insert_anomaly(db: AsyncSession, row: dict):
    await db.execute(text("""
        INSERT INTO anomalies
            (client_id, operational_event_id, typed_event_id, category,
             layer, anomaly_type, anomaly_score, details, is_false_positive, detected_at)
        VALUES
            (:client_id, :operational_event_id, :typed_event_id, :category,
             :layer, :anomaly_type, :anomaly_score,
             cast(:details as jsonb), false, NOW())
        ON CONFLICT (operational_event_id, layer, anomaly_type) DO NOTHING
    """), row)


async def mark_analyzed(db: AsyncSession, event_ids: list[int]):
    await db.execute(text("""
        UPDATE operational_events
        SET analyzed_at = NOW()
        WHERE id = ANY(:ids)
    """), {"ids": event_ids})


async def update_scheduler_status(db: AsyncSession, status: str, error: Optional[str],
                                  clients: int, events: int, anomalies: int, duration: float):
    await db.execute(text("""
        INSERT INTO scheduler_status
            (process_name, last_run_at, last_run_status, last_error,
             clients_processed, events_inserted, anomalies_detected, duration_seconds)
        VALUES
            ('anomaly_engine', NOW(), :status, :error, :clients, :events, :anomalies, :duration)
        ON CONFLICT (process_name) DO UPDATE SET
            last_run_at       = NOW(),
            last_run_status   = EXCLUDED.last_run_status,
            last_error        = EXCLUDED.last_error,
            clients_processed = EXCLUDED.clients_processed,
            events_inserted   = EXCLUDED.events_inserted,
            anomalies_detected= EXCLUDED.anomalies_detected,
            duration_seconds  = EXCLUDED.duration_seconds
    """), {"status": status, "error": error, "clients": clients,
           "events": events, "anomalies": anomalies, "duration": duration})
    await db.commit()


# ── Layer 1 rule engine ───────────────────────────────────────────────────────

def _extract_field(event_fields: dict, field: str):
    """Get a field value from the event, trying JSONB fields dict."""
    return event_fields.get(field)


def _matches_operator(value, operator: str, target) -> bool:
    if value is None:
        return False
    try:
        if operator == "in":
            return str(value) in [str(v) for v in target] or value in target
        elif operator == "not_in":
            return str(value) not in [str(v) for v in target] and value not in target
        elif operator == "eq":
            return str(value) == str(target)
        elif operator == "gt":
            return float(value) > float(target)
        elif operator == "lt":
            return float(value) < float(target)
        elif operator == "contains":
            return str(target).lower() in str(value).lower()
    except (TypeError, ValueError):
        return False
    return False


def evaluate_layer1_rules(events: list[dict], rules: list[dict]) -> dict[int, list[str]]:
    """
    Evaluate all L1 rules against the event batch.
    Returns dict: operational_event_id → list of fired rule descriptions.
    """
    fired: dict[int, list[str]] = {}

    for rule in rules:
        cond = rule["conditions"]
        if isinstance(cond, str):
            cond = json.loads(cond)

        field = cond.get("field", "EventID")
        operator = cond.get("operator", "in")
        values = cond.get("values", [])
        aggregation = cond.get("aggregation")
        threshold = cond.get("threshold", 1)
        window_min = cond.get("window_minutes", 5)
        group_by = cond.get("group_by")
        severity = rule.get("severity", "medium")
        rule_name = rule["rule_name"]

        window_min = window_min if window_min is not None else 0
        window = timedelta(minutes=window_min) if window_min > 0 else None

        if aggregation in ("count", "distinct_count"):
            # Group matching events by group_by field within time window
            matching = [
                e for e in events
                if _matches_operator(_extract_field(e["fields"], field), operator, values)
            ]
            if not matching:
                continue

            # Group by group_by field
            groups: dict[str, list[dict]] = {}
            for ev in matching:
                gval = str(_extract_field(ev["fields"], group_by) or "ALL") if group_by else "ALL"
                groups.setdefault(gval, []).append(ev)

            for gval, gevents in groups.items():
                # Sliding window check
                gevents_sorted = sorted(gevents, key=lambda e: e["timestamp"])
                for i, ev in enumerate(gevents_sorted):
                    ts_i = ev["timestamp"]
                    if hasattr(ts_i, "replace"):
                        ts_i = ts_i if ts_i.tzinfo else ts_i.replace(tzinfo=timezone.utc)
                    window_events = [
                        e for e in gevents_sorted[i:]
                        if (e["timestamp"] if e["timestamp"].tzinfo
                            else e["timestamp"].replace(tzinfo=timezone.utc)) - ts_i <= window
                    ]
                    count = (len(set(str(_extract_field(e["fields"], group_by))
                                     for e in window_events))
                             if aggregation == "distinct_count"
                             else len(window_events))
                    if count >= threshold:
                        for we in window_events:
                            eid = we["id"]
                            desc = f"{rule_name} [{severity}]: {field} {operator} {values}, count={count}"
                            fired.setdefault(eid, []).append(desc)
                        break  # avoid duplicate firing for same group
        else:
            # Simple per-event evaluation
            for ev in events:
                val = _extract_field(ev["fields"], field)
                if _matches_operator(val, operator, values):
                    eid = ev["id"]
                    desc = f"{rule_name} [{severity}]"
                    fired.setdefault(eid, []).append(desc)

    return fired


def evaluate_default_rules(events: list[dict], category: str) -> dict[int, list[str]]:
    """
    Built-in rules applied when no custom rules are defined.
    Also supplements custom rules with off-hours + LOLBins checks.
    """
    fired: dict[int, list[str]] = {}

    for ev in events:
        fields = ev["fields"]
        eid = ev["id"]
        reasons = []

        # Off-hours check (all categories)
        ts = ev["timestamp"]
        if hasattr(ts, "astimezone"):
            ts_eat = ts.astimezone(EAT)
            hour = ts_eat.hour
            if hour >= OFF_HOURS_START or hour < OFF_HOURS_END:
                reasons.append("OffHoursActivity [medium]")

        if category == "AuthenticationEvents":
            event_id = str(fields.get("EventID", ""))
            # Privilege escalation
            if event_id in ("4672", "4728", "4732"):
                reasons.append("PrivilegeEscalation [high]")

        elif category == "ProcessCreationEvents":
            cmd = str(fields.get("CommandLine", "")).lower()
            for pattern in LOLBIN_PATTERNS:
                if pattern.lower() in cmd:
                    reasons.append(f"SuspiciousProcess:{pattern} [high]")
                    break

        if reasons:
            fired[eid] = fired.get(eid, []) + reasons

    return fired


# ── Threat intel cross-reference ──────────────────────────────────────────────

def check_threat_intel(events: list[dict], ioc_entries: list[dict]) -> dict[int, list[dict]]:
    """
    Returns dict: operational_event_id → list of {matched_ioc, intel_id}
    """
    # Build flat IOC lookup set: value → intel_id
    ioc_map: dict[str, int] = {}
    for entry in ioc_entries:
        for ioc in entry["iocs"]:
            ioc_map[str(ioc).lower()] = entry["id"]

    hits: dict[int, list[dict]] = {}
    for ev in events:
        fields = ev["fields"]
        candidates = [
            fields.get("IpAddress", ""),
            fields.get("SourceIp", ""),
            fields.get("DestinationIp", ""),
            fields.get("Hashes", ""),
            fields.get("FileHash", ""),
        ]
        for val in candidates:
            if not val:
                continue
            if str(val).lower() in ioc_map:
                intel_id = ioc_map[str(val).lower()]
                hits.setdefault(ev["id"], []).append(
                    {"matched_ioc": val, "intel_id": intel_id}
                )

    return hits


# ── Mock data for testing ──────────────────────────────────────────────────────

def make_mock_events(client_id: int, category: str, n: int = 10) -> list[dict]:
    import random
    base = datetime.now(timezone.utc)
    cfg = CATEGORIES[category]
    eids = cfg["event_ids"]
    users = ["alice", "bob", "charlie", "admin", "svc_account"]
    ips = ["10.0.0.1", "192.168.1.50", "172.16.0.5", "203.0.113.1"]
    cmds = ["cmd.exe /c whoami", "powershell -enc SGVsbG8=",
            "net user admin /add", "certutil -urlcache"]
    result = []
    for i in range(n):
        ts = base - timedelta(seconds=random.randint(0, 900))
        eid = random.choice(eids)
        fields: dict = {"EventID": str(eid)}
        if category == "AuthenticationEvents":
            fields["TargetUserName"] = random.choice(users)
            fields["IpAddress"] = random.choice(ips)
        elif category == "AccountManagementEvents":
            fields["SubjectUserName"] = random.choice(users)
            fields["TargetUserName"] = random.choice(users)
        elif category == "ProcessCreationEvents":
            fields["SubjectUserName"] = random.choice(users)
            fields["CommandLine"] = random.choice(cmds)
        result.append({
            "id": i + 1,
            "client_id": client_id,
            "query_name": category,
            "timestamp": ts,
            "source_host": f"server-{random.randint(1,5)}",
            "fields": fields,
        })
    return result


# ── Core: process one client+category ────────────────────────────────────────

async def process_category(db: AsyncSession, client_id: int, client_name: str,
                            category: str) -> tuple[int, int]:
    """
    Returns (typed_rows_written, anomalies_written).
    Never raises — logs and returns (0,0) on failure.
    """
    cfg = CATEGORIES[category]
    typed_table = cfg["typed_table"]
    threshold = cfg["threshold"]
    features = cfg["features"]

    try:
        # 1. Fetch unanalyzed events
        if MOCK_MODE:
            events = make_mock_events(client_id, category)
        else:
            events = await get_unanalyzed_events(db, client_id, category, cfg["event_ids"])

        if not events:
            return 0, 0

        log.debug("[%s] %s: %d unanalyzed events", client_name, category, len(events))

        # Parse fields JSONB if needed
        for ev in events:
            if isinstance(ev["fields"], str):
                ev["fields"] = json.loads(ev["fields"])
            if isinstance(ev["timestamp"], str):
                from dateutil import parser as dtparser
                ev["timestamp"] = dtparser.parse(ev["timestamp"])

        # 2. Layer 1 rules
        custom_rules = await get_layer1_rules(db, client_id, category)
        l1_fired = evaluate_layer1_rules(events, custom_rules)
        default_fired = evaluate_default_rules(events, category)
        # Merge both
        all_l1: dict[int, list[str]] = {}
        for eid, reasons in {**default_fired, **l1_fired}.items():
            all_l1.setdefault(eid, [])
            all_l1[eid] = list(dict.fromkeys(all_l1[eid] + reasons))  # dedupe

        # 3. Layer 2 — load model
        model = None
        if not MOCK_MODE:
            model_path = await get_model_path(db, client_id, category)
            if model_path:
                model = load_model(client_id, category, model_path)
            else:
                log.warning("[%s] %s: no active model found, skipping L2", client_name, category)

        # 4. Feature engineering
        df = pd.DataFrame([
            {
                "op_event_id": ev["id"],
                "timestamp": ev["timestamp"],
                "EventID": int(ev["fields"].get("EventID", 0)),
                "TargetUserName": ev["fields"].get("TargetUserName", ""),
                "IpAddress": ev["fields"].get("IpAddress", ""),
                "SubjectUserName": ev["fields"].get("SubjectUserName", ""),
                "CommandLine": ev["fields"].get("CommandLine", ""),
            }
            for ev in events
        ])
        df = engineer_features(df, category)

        # 5. L2 scoring
        scores: dict[int, float] = {}
        if model is not None or MOCK_MODE:
            try:
                if MOCK_MODE:
                    import random
                    for ev in events:
                        scores[ev["id"]] = random.uniform(-0.3, 0.1)
                else:
                    available = [f for f in features if f in df.columns]
                    X = df[available].fillna(0).values
                    raw_scores = model.decision_function(X)
                    for i, ev in enumerate(events):
                        scores[ev["id"]] = float(raw_scores[i])
            except Exception as e:
                log.error("[%s] %s: L2 scoring failed: %s", client_name, category, e)

        # 6. Threat intel
        ioc_entries = await get_threat_iocs(db)
        ti_hits = check_threat_intel(events, ioc_entries)

        # 7. Write typed rows + anomalies
        typed_count = 0
        anomaly_count = 0
        processed_ids = []

        for ev in events:
            eid = ev["id"]
            fields = ev["fields"]
            ts = ev["timestamp"]
            score = scores.get(eid)
            l1_reasons = all_l1.get(eid, [])
            rule_reason = " | ".join(l1_reasons) if l1_reasons else None
            l1_hit = bool(l1_reasons)
            l2_hit = score is not None and score < threshold
            is_anomaly = l1_hit or l2_hit

            df_row = df[df["op_event_id"] == eid].iloc[0] if not df[df["op_event_id"] == eid].empty else None

            def safe(col, default=None):
                if df_row is None:
                    return default
                return df_row.get(col, default)

            # Build typed row
            if typed_table == "auth_events":
                typed_row = {
                    "client_id": client_id,
                    "operational_event_id": eid,
                    "timestamp": ts,
                    "event_id": int(fields.get("EventID", 0)),
                    "target_username": fields.get("TargetUserName"),
                    "ip_address": fields.get("IpAddress"),
                    "hour": int(safe("Hour", 0)),
                    "day_of_week": int(safe("DayOfWeek", 0)),
                    "is_weekend": bool(safe("IsWeekend", 0)),
                    "target_username_freq": float(safe("TargetUserName_Freq", 0.0)),
                    "ip_address_freq": float(safe("IpAddress_Freq", 0.0)),
                    "anomaly_score": score,
                    "rule_reason": rule_reason,
                    "is_anomaly": is_anomaly,
                }
            elif typed_table == "account_events":
                typed_row = {
                    "client_id": client_id,
                    "operational_event_id": eid,
                    "timestamp": ts,
                    "event_id": int(fields.get("EventID", 0)),
                    "subject_username": fields.get("SubjectUserName"),
                    "target_username": fields.get("TargetUserName"),
                    "hour": int(safe("Hour", 0)),
                    "day_of_week": int(safe("DayOfWeek", 0)),
                    "is_weekend": bool(safe("IsWeekend", 0)),
                    "subject_username_freq": float(safe("SubjectUserName_Freq", 0.0)),
                    "target_username_freq": float(safe("TargetUserName_Freq", 0.0)),
                    "anomaly_score": score,
                    "rule_reason": rule_reason,
                    "is_anomaly": is_anomaly,
                }
            else:  # process_events
                typed_row = {
                    "client_id": client_id,
                    "operational_event_id": eid,
                    "timestamp": ts,
                    "event_id": int(fields.get("EventID", 0)),
                    "subject_username": fields.get("SubjectUserName"),
                    "command_line": fields.get("CommandLine"),
                    "hour": int(safe("Hour", 0)),
                    "day_of_week": int(safe("DayOfWeek", 0)),
                    "is_weekend": bool(safe("IsWeekend", 0)),
                    "subject_username_freq": float(safe("SubjectUserName_Freq", 0.0)),
                    "command_line_freq": float(safe("CommandLine_Freq", 0.0)),
                    "anomaly_score": score,
                    "rule_reason": rule_reason,
                    "is_anomaly": is_anomaly,
                }

            if not MOCK_MODE:
                typed_id = await insert_typed_event(db, typed_table, typed_row)
                typed_count += 1

                # L1 anomaly rows
                for reason in l1_reasons:
                    rule_name = reason.split(" [")[0]
                    severity = reason.split("[")[1].rstrip("]") if "[" in reason else "medium"
                    await insert_anomaly(db, {
                        "client_id": client_id,
                        "operational_event_id": eid,
                        "typed_event_id": typed_id,
                        "category": category,
                        "layer": 1,
                        "anomaly_type": rule_name,
                        "anomaly_score": None,
                        "details": json.dumps({"rule_reason": reason, "severity": severity}),
                    })
                    anomaly_count += 1

                # L2 anomaly row
                if l2_hit:
                    feature_vals = {f: float(safe(f, 0)) for f in features if f in df.columns}
                    await insert_anomaly(db, {
                        "client_id": client_id,
                        "operational_event_id": eid,
                        "typed_event_id": typed_id,
                        "category": category,
                        "layer": 2,
                        "anomaly_type": "IsolationForest",
                        "anomaly_score": score,
                        "details": json.dumps({"features": feature_vals, "threshold": threshold}),
                    })
                    anomaly_count += 1

                # Threat intel anomaly rows
                for hit in ti_hits.get(eid, []):
                    await insert_anomaly(db, {
                        "client_id": client_id,
                        "operational_event_id": eid,
                        "typed_event_id": typed_id,
                        "category": category,
                        "layer": 2,
                        "anomaly_type": "ThreatIntelMatch",
                        "anomaly_score": None,
                        "details": json.dumps(hit),
                    })
                    anomaly_count += 1
            else:
                # MOCK_MODE — just count, don't write
                typed_count += 1
                if is_anomaly:
                    anomaly_count += 1

            processed_ids.append(eid)

        # 8. Commit writes, THEN mark analyzed (critical ordering)
        if not MOCK_MODE and processed_ids:
            await db.commit()
            await mark_analyzed(db, processed_ids)
            await db.commit()
        elif MOCK_MODE:
            log.info("[MOCK][%s] %s: would write %d typed rows, %d anomalies",
                     client_name, category, typed_count, anomaly_count)

        return typed_count, anomaly_count

    except Exception as e:
        log.error("[%s] %s: category processing failed: %s", client_name, category, e, exc_info=True)
        try:
            await db.rollback()
        except Exception:
            pass
        return 0, 0


# ── Core cycle ────────────────────────────────────────────────────────────────

async def run_cycle():
    start = time.monotonic()
    total_clients = 0
    total_typed = 0
    total_anomalies = 0
    cycle_status = "success"
    cycle_error = None

    async with Session() as db:
        try:
            clients = await get_active_clients(db)
            log.info("Cycle start — %d active clients", len(clients))

            for client in clients:
                total_clients += 1
                client_typed = 0
                client_anomalies = 0

                for category in CATEGORIES:
                    try:
                        typed, anomalies = await process_category(
                            db, client["id"], client["name"], category
                        )
                        client_typed += typed
                        client_anomalies += anomalies
                    except Exception as e:
                        log.error("[%s] %s: unhandled error: %s",
                                  client["name"], category, e, exc_info=True)
                        cycle_status = "failed"
                        cycle_error = str(e)

                total_typed += client_typed
                total_anomalies += client_anomalies
                if client_typed > 0 or client_anomalies > 0:
                    log.info("[%s] typed=%d anomalies=%d",
                             client["name"], client_typed, client_anomalies)

        except Exception as e:
            log.error("Cycle fatal: %s", e, exc_info=True)
            cycle_status = "failed"
            cycle_error = str(e)

        duration = time.monotonic() - start
        log.info("Cycle done — clients=%d typed=%d anomalies=%d duration=%.1fs status=%s",
                 total_clients, total_typed, total_anomalies, duration, cycle_status)

        try:
            await update_scheduler_status(
                db, cycle_status, cycle_error, total_clients,
                total_typed, total_anomalies, duration
            )
        except Exception as e:
            log.error("Failed to update scheduler_status: %s", e)


async def main():
    mode = "MOCK" if MOCK_MODE else "LIVE"
    log.info("anomaly_engine starting [%s] sleep=%ds", mode, SLEEP)
    while True:
        await run_cycle()
        log.info("Sleeping %ds...", SLEEP)
        await asyncio.sleep(SLEEP)


if __name__ == "__main__":
    asyncio.run(main())