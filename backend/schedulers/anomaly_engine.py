"""
anomaly_engine.py — Pipeline 2
Runs every 5 minutes. Reads unanalyzed operational_events, runs L1 rules +
L2 Isolation Forest, writes typed tables + anomalies, sets analyzed_at.

Run: cd backend && python -m schedulers.anomaly_engine
"""

# TODO: Adjust marking logic for aggregation rules.
# For rules with a time window (e.g. BruteForce needing 5 failed logins in 5 minutes),
# do NOT mark events as analyzed immediately. Instead, delay marking until the window
# has passed, so earlier events remain available for aggregation checks.
# NOTE: Ensure each event dict includes '_ts' = ev.timestamp.
# This is required for aggregation rules with window_minutes,
# since _evaluate_condition expects '_ts' to exist (copied from OperationalEvent.timestamp).
# run_cycle()
#   └── for client in clients:          # loops client 1, 2, 3
#         └── for category in CATEGORIES:   # loops Auth, Account, Process
#               └── process_category(db, client_id, category)
#                     └── freq_maps_complete check runs HERE
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
POOL_SIZE = int(os.getenv("DB_POOL_SIZE", "5"))
MAX_OVERFLOW = int(os.getenv("DB_MAX_OVERFLOW", "10"))
EAT = pytz.timezone("Africa/Nairobi")

engine = create_async_engine(DATABASE_URL, echo=False, pool_size=POOL_SIZE, max_overflow=MAX_OVERFLOW)
# provides ORM sessions, transaction safety, automatic mapping.
Session = async_sessionmaker(engine, expire_on_commit=False)

# ── Category definitions ──────────────────────────────────────────────────────
CATEGORIES = {
    "AuthenticationEvents": {
        "event_ids": [4624, 4625, 4634, 4648, 4672],
        "threshold": AUTH_THRESHOLD,
        "features": ["Hour", "DayOfWeek", "IsWeekend", "EventID",
                     "TargetUserName_Freq", "IpAddress_Freq"],
        "typed_table": "auth_events",
        "required_fields": ["EventID", "TargetUserName", "IpAddress"],
    },
    "AccountManagementEvents": {
        "event_ids": [4720, 4722, 4723, 4724, 4725, 4726,
                      4728, 4729, 4732, 4733, 4781],
        "threshold": ACCOUNT_THRESHOLD,
        "features": ["Hour", "DayOfWeek", "IsWeekend", "EventID",
                     "SubjectUserName_Freq", "TargetUserName_Freq"],
        "typed_table": "account_events",
        "required_fields": ["EventID", "SubjectUserName", "TargetUserName"],
    },
    "ProcessCreationEvents": {
        "event_ids": [4688, 4689],
        "threshold": PROCESS_THRESHOLD,
        "features": ["Hour", "DayOfWeek", "IsWeekend", "EventID",
                     "SubjectUserName_Freq", "CommandLine_Freq"],
        "typed_table": "process_events",
        "required_fields": ["EventID", "SubjectUserName", "CommandLine"],
    },
}

# LOLBins + suspicious patterns for L1 process rules
LOLBIN_PATTERNS = [
    "certutil", "bitsadmin", "mshta", "wscript", "cscript", "net user /add",
    "regsvr32", "rundll32", "powershell -enc", "wmic", "cmstp", "psexec", "powershell -e ",
    "net user", "net localgroup", "whoami", "csc.exe", "msbuild", "mimikatz", "installutil",
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
    df["IsWeekend"] = df["DayOfWeek"].isin([5, 6]).astype(int)
    return df


def apply_saved_freq_map(df: pd.DataFrame, column: str, freq_map: dict) -> pd.DataFrame:
    """
    Map a text column to frequencies using a *saved* training-time freq map.
    Unknown values (unseen at training time) get 0.0 — correctly low frequency.
    """
    if column not in df.columns:
        df[column] = ""
    df[f"{column}_Freq"] = (
        df[column].astype(str).map(freq_map).fillna(0.0)
    )
    return df


def engineer_features(
    df: pd.DataFrame,
    category: str,
    saved_freq_maps: Optional[dict] = None,
) -> pd.DataFrame:
    """
    If saved_freq_maps is provided (from a loaded model artifact), apply those.
    """
    df = add_time_features(df)

    def _freq(col: str, freq_feat: str):
        if saved_freq_maps and freq_feat in saved_freq_maps:
            return apply_saved_freq_map(df, col, saved_freq_maps[freq_feat])
        else:
            log.warning(
                "[%s] %s: freq_map for %s not found in model artifact — "
                "L2 scoring will be skipped for this batch",
                category, freq_feat
            )
            # Zero-fill the freq column so the dataframe stays valid,
            # but signal the caller to skip L2
            if col not in df.columns:
                df[col] = ""
            df[f"{col}_Freq"] = 0.0
            return df


    if category == "AuthenticationEvents":
        df = _freq("TargetUserName", "TargetUserName_Freq")
        df = _freq("IpAddress",      "IpAddress_Freq")
    elif category == "AccountManagementEvents":
        df = _freq("SubjectUserName", "SubjectUserName_Freq")
        df = _freq("TargetUserName",  "TargetUserName_Freq")
    elif category == "ProcessCreationEvents":
        df = _freq("SubjectUserName", "SubjectUserName_Freq")
        df = _freq("CommandLine",     "CommandLine_Freq")
    return df


# ── Model loading ─────────────────────────────────────────────────────────────

_model_cache: dict[str, object] = {}


def load_model(client_id: int, category: str, model_path: str) -> Optional[dict]:
    """
    Returns the full artifact dict:
      { "model": IsolationForest, "freq_maps": {...}, "feature_columns": [...], ... }
    Returns None on failure.
    """
    # cache_key = f"{client_id}:{category}"
    # if cache_key in _model_cache:
    #     return _model_cache[cache_key]
    try:
        artifact = joblib.load(model_path)
        # _model_cache[cache_key] = artifact
        log.info("Loaded model client=%d category=%s", client_id, category)
        return artifact
    except Exception as e:
        log.critical("Cannot load model client=%d category=%s path=%s: %s",
                     client_id, category, model_path, e)
        return None


# def invalidate_model_cache(client_id: int, category: str):
#     _model_cache.pop(f"{client_id}:{category}", None)


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
        SELECT id, client_id, query_name, timestamp, source_host, fields,
               all_timestamps                          
        FROM operational_events
        WHERE client_id = :cid
          AND analyzed_at IS NULL
          AND (fields->>'EventID')::int IN ({ids_str})
        ORDER BY timestamp ASC
        LIMIT 2000
    """), {"cid": client_id})
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
#json.loads converts  JSON string into the corresponding Python type, '["malware.com", "bad-ip"] becomes a list, '{"key": "value"}' becomes a dictionary
        result.append({"id": r[0], "iocs": iocs if isinstance(iocs, list) else []})
    return result


async def insert_typed_event(db: AsyncSession, table: str, row: dict) -> Optional[int]:
    cols = ", ".join(row.keys())
    placeholders = ", ".join(f":{k}" for k in row.keys())
    result = await db.execute(
        text(f"""
            INSERT INTO {table} ({cols}) VALUES ({placeholders})
            ON CONFLICT (operational_event_id) DO NOTHING
            RETURNING id
        """),
        row
    )
    r = result.fetchone()
    if r:
        return r[0]  # freshly inserted
    
    # Already existed — fetch the existing id
    existing = await db.execute(
        text(f"SELECT id FROM {table} WHERE operational_event_id = :op_id"),
        {"op_id": row["operational_event_id"]}
    )
    e = existing.fetchone()
    return e[0] if e else None


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


def _matches_operator(operator: str, value: object, values: list) -> bool:
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


def _evaluate_condition(cond: dict, ev_fields: dict, all_events: list[dict]) -> tuple[bool, str]:
    kind = cond.get("kind", "single")

    # ── Compound — recurse into each branch ──────────────────────────────────
    if kind == "compound":
        logic = cond.get("logic", "OR").upper()
        branches = cond.get("conditions", [])
        results = [_evaluate_condition(b, ev_fields, all_events) for b in branches]

        if logic == "OR":
            for matched, reason in results:
                if matched:
                    return True, reason
            return False, ""
        else:  # AND
            reasons = []
            for matched, reason in results:
                if not matched:
                    return False, ""
                reasons.append(reason)
            return True, " AND ".join(reasons)

    # ── Single ───────────────────────────────────────────────────────────────
    field = cond.get("field", "")
    operator = cond.get("operator", "")
    values = cond.get("values", [])
    aggregation = cond.get("aggregation")
    threshold = cond.get("threshold")
    window_minutes = cond.get("window_minutes")
    group_by = cond.get("group_by")

    if aggregation in ("count", "distinct_count") and threshold is not None:
        row_val = ev_fields.get(field)
        if row_val is None:
            return False, ""

        candidates = [
            e for e in all_events
            if e.get("fields", {}).get(group_by) == ev_fields.get(group_by)
        ] if group_by else all_events#drops events that don't have the specified roup_by

        if window_minutes:
            row_ts = ev_fields.get("_ts")
            if row_ts:
                window_start = row_ts - timedelta(minutes=window_minutes)
                candidates = [
                    e for e in candidates
                    if e.get("_ts") and e["_ts"] >= window_start
                ]
# candidates = a filtered list of full event dicts sharing the same group_by value (e.g. same IpAddress)
# _matches_operator checks one specific field (e.g. EventID) on each candidate row
# if it passes, all individual timestamps in all_timestamps for that row are counted
# this repeats across every row in candidates, accumulating into one running count
# final count = total individual occurrences matching the condition from that group within the window
        if aggregation == "count":
            count = 0
            for e in candidates:
                if _matches_operator(_extract_field(e["fields"], field), operator, values):
                #silently drops candidates that don't have the required field same as the one checked by row_val = ev_fields.get(field)
                    all_ts = e.get("all_timestamps") or []
                    if all_ts and window_minutes and ev_fields.get("_ts"):
                        # count only individual timestamps within the window
                        for ts_str in all_ts:
                            try:
                                ts_dt = datetime.strptime(
                                    ts_str, "%Y-%m-%d %H:%M:%S"
                                ).replace(tzinfo=EAT)
                                if ts_dt >= window_start:
                                    count += 1#counts across all candidates
                            except ValueError:
                                continue
                    elif all_ts:
                        # no window — count all occurrences
                        count += len(all_ts)
                    else:
                        # fallback: no all_timestamps stored = 1 occurrence
                        count += 1
        else:  # distinct_count, doesn't care about timestamps, only unique values
            seen = set()
            for e in candidates:
                v = _extract_field(e["fields"], field)
                if v is not None and _matches_operator(v, operator, values):
                    seen.add(str(v))
            count = len(seen)

        if count >= threshold:
            return True, (
                f"{aggregation}({field}) {operator} {values} "
                f"= {count} >= {threshold} "
                f"(window={window_minutes}m, group_by={group_by})"
            )
        return False, ""
    row_val = _extract_field(ev_fields, field)
    if row_val is None:
        return False, ""
    matched = _matches_operator(row_val, operator, values)
    if matched:
        return True, f"{field} {operator} {values}"
    return False, ""

def evaluate_layer1_rules(events: list[dict], rules: list[dict]) -> dict[int, list[str]]:
    fired: dict[int, list[str]] = {}

    # attach _ts once so window-based aggregation can use it
    for ev in events:
        ev["_ts"] = ev["timestamp"]

    for rule in rules:
        cond = rule["conditions"]
        if isinstance(cond, str):
            cond = json.loads(cond)

        severity = rule.get("severity", "medium")
        rule_name = rule["rule_name"]

        for ev in events:
            ev_fields = {**ev["fields"], "_ts": ev["_ts"]}
            matched, reason = _evaluate_condition(cond, ev_fields, events)
            if matched:
                fired.setdefault(ev["id"], []).append(f"{rule_name} [{severity}]: {reason}")

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
            "all_timestamps": [ts.strftime("%Y-%m-%d %H:%M:%S")], 
        })
    return result


# Replace the DataFrame construction blocks in process_category()
# with an expanded version that creates one row per timestamp occurrence

def _expand_events(events: list[dict], category: str) -> pd.DataFrame:
    """
    Expands grouped events into individual occurrence rows using all_timestamps.
    Each occurrence gets its own row for ML scoring.
    The op_event_id links back to the original grouped row.
    """
    rows = []
    for ev in events:
        all_ts = ev.get("all_timestamps") or []
        fields = ev["fields"]

        # parse stored timestamp strings back to datetime
        timestamps = []
        for ts_str in all_ts:
            try:
                ts_dt = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S").replace(tzinfo=EAT)
                timestamps.append(ts_dt)
            except ValueError:
                continue

        # fallback to single timestamp if all_timestamps empty
        if not timestamps:
            timestamps = [ev["timestamp"]]

        for ts in timestamps:
            base = {
                "op_event_id": ev["id"],
                "timestamp": ts,
                "EventID": int(float(fields.get("EventID") or 0)),
            }
            if category == "AuthenticationEvents":
                base["TargetUserName"] = fields.get("TargetUserName", "")
                base["IpAddress"] = fields.get("IpAddress", "")
            elif category == "AccountManagementEvents":
                base["SubjectUserName"] = fields.get("SubjectUserName", "")
                base["TargetUserName"] = fields.get("TargetUserName", "")
            else:  # ProcessCreationEvents
                base["SubjectUserName"] = fields.get("SubjectUserName", "")
                base["CommandLine"] = fields.get("CommandLine", "")
            rows.append(base)

    return pd.DataFrame(rows) if rows else pd.DataFrame()


def _extract_max_window(cond: dict) -> int:
    """Recursively extract the largest window_minutes from any condition."""
    if cond.get("kind") == "compound":
        return max(
            (_extract_max_window(b) for b in cond.get("conditions", [])),
            default=0
        )
    return cond.get("window_minutes") or 0
# ── Core: process one client+category ────────────────────────────────────────

async def process_category(client_id: int, client_name: str,
                            category: str) -> tuple[int, int]:
    """
    Returns (typed_rows_written, anomalies_written).
    Never raises — logs and returns (0,0) on failure.
    """
    async with Session() as db:#as it is concurrent, each process_category gets it's own db session
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

            # Parse fields JSONB 
            for ev in events:
                if isinstance(ev["fields"], str):
                    ev["fields"] = json.loads(ev["fields"])
                if isinstance(ev["timestamp"], str):
                    from dateutil import parser as dtparser
                    ev["timestamp"] = dtparser.parse(ev["timestamp"])  #It says: "if SQLAlchemy gave me a string instead of a datetime object, parse it into a proper datetime before I do anything with it., eg  from "2024-01-15 08:30:00+03:00"   to datetime(2024, 1, 15, 8, 30, 0, tzinfo=<UTC+3>)
                ts = ev["timestamp"]
                if not ts.tzinfo:
                    ts = ts.replace(tzinfo=timezone.utc)
                ev["fields"]["hour"] = ts.astimezone(EAT).hour  
                ev["timestamp"] = ts  

            # ── Field completeness check ──────────────────────────────────────
            # Log missing fields for analyst visibility via scheduler_status,
            # but do NOT drop the event — it still gets scored and marked
            # analyzed_at so it never loops forever in the queue.
            required_fields = cfg["required_fields"]
            skipped_details = []

            for ev in events:
                missing = [f for f in required_fields if not ev["fields"].get(f)]
                if missing:
                    log.warning(
                        "[%s] %s: op_event_id=%d missing fields %s — "
                        "will score with defaults, marking analyzed",
                        client_name, category, ev["id"], missing
                    )
                    skipped_details.append(
                        f"op_event_id={ev['id']} missing={missing}")
            if skipped_details:
                log.warning(
                    "[%s] %s: %d events had missing fields: %s",
                    client_name, category, len(skipped_details),
                    "; ".join(skipped_details)
                )
            # ─────────────────────────────────────────────────────────────────

            # 2. Layer 1 rules   ← continues here unchanged
            custom_rules = await get_layer1_rules(db, client_id, category)
            l1_fired = evaluate_layer1_rules(events, custom_rules)
            default_fired = evaluate_default_rules(events, category)
            # Merge both
            all_l1: dict[int, list[str]] = {}

            for eid, reasons in default_fired.items():
                all_l1.setdefault(eid, [])
                all_l1[eid] = list(dict.fromkeys(all_l1[eid] + reasons))

            for eid, reasons in l1_fired.items():
                all_l1.setdefault(eid, [])
                all_l1[eid] = list(dict.fromkeys(all_l1[eid] + reasons))
                                    # Internally Python builds this dict:
                                    # python{
                                    #     "OffHoursActivity [medium]":  None,   # key = the reason string itself
                                    #     "BruteForce [high]: ...":     None,   # key = the reason string itself
                                    # } it is then converted back to lisst, it is a deduplication trick

            # 3. Layer 2 — load model
            artifact = None
            saved_freq_maps = None
            if not MOCK_MODE:
                model_path = await get_model_path(db, client_id, category)
                if model_path:
                    artifact = load_model(client_id, category, model_path)
                    if artifact:
                        saved_freq_maps = artifact.get("freq_maps", {})
                    else:
                        log.warning("[%s] %s: no active model found, skipping L2", client_name, category)

            df = _expand_events(events, category)
            if df.empty:
                log.error(
                    "[%s] %s: _expand_events() returned empty df for %d events — "
                    "marking analyzed to avoid infinite retry",
                    client_name, category, len(events)
                )
                if not MOCK_MODE:
                    async with Session() as db2:
                        await mark_analyzed(db2, [ev["id"] for ev in events])
                        await db2.commit()
                return 0, 0
            df = engineer_features(df, category, saved_freq_maps=saved_freq_maps)

            # 5. L2 scoring
            freq_cols = [f for f in features if f.endswith("_Freq")]
            freq_maps_complete = all(
                f in (saved_freq_maps or {}) for f in freq_cols
            )
            if not freq_maps_complete:
                log.warning(
                    "[%s] %s: incomplete freq maps — skipping L2 this cycle",
                    client_name, category
                )
                artifact = None  # forces L2 skip in step 5

            # 5. L2 scoring
            model = artifact["model"] if artifact else None
            scores: dict[int, float] = {}
            if model is not None or MOCK_MODE:
                try:
                    if MOCK_MODE:
                        import random
                        for ev in events:
                            scores[ev["id"]] = random.uniform(-0.3, 0.1)
                    else:
                        available = [f for f in features if f in df.columns]
                        if len(available) != len(features):
                            missing = set(features) - set(df.columns)
                            log.error(
                                "[%s] %s: feature mismatch — missing %s, skipping L2",
                                client_name, category, missing
                            )
                        else:
                            X = df[available].fillna(0).values
                            raw_scores = model.decision_function(X)
                            # assign worst (lowest) score per grouped event
                            # so if ANY occurrence was anomalous, the group is flagged
                            for i, row in df.iterrows():
                                op_id = int(row["op_event_id"])
                                s = float(raw_scores[i])
                                if op_id not in scores or s < scores[op_id]:
                                    scores[op_id] = s
                except Exception as e:
                    log.error("[%s] %s: L2 scoring failed: %s", client_name, category, e)

            # 6. Threat intel
            # TODO(perf+correctness):
            # 1. get_threat_iocs() is called once per client per category — for 3 clients
            #    and 3 categories that is 9 identical DB reads per cycle. Move this call
            #    to run_cycle() and pass ioc_entries down to process_category() as a parameter.
            #
            # 2. The IOC lookup checks IpAddress, SourceIp, DestinationIp, Hashes, FileHash
            #    but these field names come from Graylog and may not match what is actually
            #    stored in operational_events.fields for each category. Verify the exact
            #    JSONB field keys that Graylog returns for each category and update
            #    check_threat_intel() accordingly. A mismatch here means real threat intel
            #    hits are silently missed — ti_hits will always be empty even when a known
            #    malicious IP is present in the event.
            ioc_entries = await get_threat_iocs(db)
            ti_hits = check_threat_intel(events, ioc_entries)


            # 7. Write typed rows + anomalies
            typed_count = 0
            anomaly_count = 0
            processed_ids = []
            def safe(df_row, col, default=None):
                if df_row is None:
                    return default
                return df_row.get(col, default)
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
                # ev["timestamp"] is the latest occurrence — find its exact row in the expanded df
                matching = df[df["op_event_id"] == eid]
                if not matching.empty:
                    # sort by timestamp to guarantee latest is last
                    df_row = matching.sort_values("timestamp").iloc[-1]
                else:
                    df_row = None

                # Build typed row
                if typed_table == "auth_events":
                    typed_row = {
                        "client_id": client_id,
                        "operational_event_id": eid,
                        "timestamp": ts,
                        "event_id": int(fields.get("EventID", 0)),
                        "target_username": fields.get("TargetUserName"),
                        "ip_address": fields.get("IpAddress"),
                        "hour": int(safe(df_row,"Hour", 0)),
                        "day_of_week": int(safe(df_row,"DayOfWeek", 0)),
                        "is_weekend": bool(safe(df_row,"IsWeekend", 0)),
                        "target_username_freq": float(safe(df_row,"TargetUserName_Freq", 0.0)),
                        "ip_address_freq": float(safe(df_row,"IpAddress_Freq", 0.0)),
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
                        "hour": int(safe(df_row,"Hour", 0)),
                        "day_of_week": int(safe(df_row,"DayOfWeek", 0)),
                        "is_weekend": bool(safe(df_row,"IsWeekend", 0)),
                        "subject_username_freq": float(safe(df_row,"SubjectUserName_Freq", 0.0)),
                        "target_username_freq": float(safe(df_row,"TargetUserName_Freq", 0.0)),
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
                        "hour": int(safe(df_row,"Hour", 0)),
                        "day_of_week": int(safe(df_row,"DayOfWeek", 0)),
                        "is_weekend": bool(safe(df_row,"IsWeekend", 0)),
                        "subject_username_freq": float(safe(df_row,"SubjectUserName_Freq", 0.0)),
                        "command_line_freq": float(safe(df_row,"CommandLine_Freq", 0.0)),
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
    # splitting on " [" and taking index [0] strips everything from the bracket onwards, leaving just the rule name
                        severity = reason.split("[")[1].split("]")[0] if "[" in reason else "medium"
    # Split on "[", take index [1], then split again on "]" and take index [0], giving just "high" or "medium"
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
                        feature_vals = {f: float(safe(df_row,f, 0)) for f in features if f in df.columns}
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

                # Determine which events are safe to mark analyzed
                now = datetime.now(timezone.utc)
                max_window_minutes = 0
                for rule in custom_rules:
                    cond = rule["conditions"]
    # {           Example of how cond looks like, this is for BruteForce rule
    #     "field": "EventID",
    #     "operator": "in",
    #     "values": [4625],
    #     "aggregation": "count",
    #     "threshold": 5,
    #     "window_minutes": 5,
    #     "group_by": "IpAddress"
    # }
                    if isinstance(cond, str):
                        cond = json.loads(cond)
                    wm = _extract_max_window(cond)
                    if wm > max_window_minutes:
                        max_window_minutes = wm

                safe_to_mark = []
                hold_back = []
                for ev in events:
                    if ev["id"] not in processed_ids:
                        continue
                    ts = ev["timestamp"]
                    if not ts.tzinfo:
                        ts = ts.replace(tzinfo=timezone.utc)
                    if max_window_minutes > 0 and (now - ts) < timedelta(minutes=max_window_minutes):
                        hold_back.append(ev["id"])
                    else:
                        safe_to_mark.append(ev["id"])

                if safe_to_mark:
                    await mark_analyzed(db, safe_to_mark)
                    await db.commit()

                if hold_back:
                    log.info(
                        "[%s] %s: holding back %d events — aggregation window not yet expired",
                        client_name, category, len(hold_back)
                    )

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
    cycle_errors = []
    total_typed = 0
    total_anomalies = 0

    # fetch clients needs its own short-lived session
    async with Session() as db:
        clients = await get_active_clients(db)

    log.info("Cycle start — %d active clients", len(clients))

    async def process_client(client):
        client_typed = 0
        client_anomalies = 0
        for category in CATEGORIES:
            try:
                typed, anomalies = await process_category(
                    client["id"], client["name"], category
                )
                client_typed += typed
                client_anomalies += anomalies
            except Exception as e:
                log.error("[%s] %s: unhandled error: %s",
                          client["name"], category, e, exc_info=True)
                cycle_errors.append(f"[{client['name']}][{category}]: {e}")
        if client_typed > 0 or client_anomalies > 0:
            log.info("[%s] typed=%d anomalies=%d",
                     client["name"], client_typed, client_anomalies)
        return client_typed, client_anomalies

    # all clients run concurrently
    results = await asyncio.gather(
        *[process_client(client) for client in clients],
        return_exceptions=True
    )

    for r in results:
        if isinstance(r, Exception):
            cycle_errors.append(str(r))
        else:
            typed, anomalies = r
            total_typed += typed
            total_anomalies += anomalies

    duration = time.monotonic() - start
    cycle_status = "failed" if cycle_errors else "success"
    cycle_error = " | ".join(cycle_errors) if cycle_errors else None

    log.info("Cycle done — clients=%d typed=%d anomalies=%d duration=%.1fs status=%s",
             len(clients), total_typed, total_anomalies, duration, cycle_status)

    async with Session() as db:
        try:
            await update_scheduler_status(
                db, cycle_status, cycle_error, len(clients),
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