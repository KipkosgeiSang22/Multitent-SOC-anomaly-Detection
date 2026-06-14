#!/usr/bin/env python3
"""
MSSP SOC PLATFORM — LOG COLLECTOR ENGINE (PIPELINE 1)
Scheduled Standalone Process — Runs every 3 minutes.

Tasks:
1. Ingests named queries and ML configurations from 'client_queries' table.
2. Routes through app/siem abstraction layer (GraylogAdapter, SplunkAdapter, etc.).
3. Automatically normalizes tracking times to Africa/Nairobi (EAT).
4. Employs a rolling 2-hour sliding window grouping mechanism (correlate_events).
5. Executes safe atomic upserts to 'operational_events' preserving client states.

Rewrite improvements (Pipeline 1, Session 7→8):
  - Async concurrent fetching: all (client, query) pairs run concurrently via
    asyncio.gather, bounded by asyncio.Semaphore(MAX_CONCURRENT_FETCHES).
  - Exponential backoff retries: fetch_with_retry() retries up to MAX_RETRIES
    times with waits of RETRY_BASE_SEC**1, **2, **3 before giving up.
  - SIEM-agnostic fetch interface: collector never imports or references
    GraylogAdapter directly; all SIEM calls go through get_adapter() only and
    call adapter.fetch_events(query=..., lookback_seconds=..., limit=1000).
"""

import os
import sys
import asyncio
import logging
import hashlib
import json
from datetime import datetime
from pathlib import Path
import zoneinfo
from cryptography.fernet import Fernet
import asyncpg
import pandas as pd
from dotenv import load_dotenv
from typing import List, Tuple
from app.siem.factory import get_adapter


# Fail fast at startup if Fernet key is missing or invalid

# ── ENVIRONMENT LOADING ───────────────────────────────────────────────────────
# Walk up to backend/.env regardless of where the script is invoked from.
load_dotenv(dotenv_path=Path(__file__).resolve().parent.parent / ".env")
MAX_DB_POOL_SIZE = int(os.getenv("LOG_COLLECTOR_DB_POOL_SIZE","100"))
DATABASE_URL = os.environ["DATABASE_URL"]
FERNET_KEY   = os.environ["FERNET_KEY"]
try:
    Fernet(FERNET_KEY)
except Exception as e:
    sys.stderr.write(f"Invalid Fernet key: {e}\n")
    sys.exit(1)

# ── RESOLVE INTER-MODULE PATHS ────────────────────────────────────────────────
# Adds the backend/ directory to sys.path so app.siem.factory is importable.
_backend_dir = Path(__file__).resolve().parent.parent
if str(_backend_dir) not in sys.path:
    sys.path.insert(0, str(_backend_dir))



# ── LOGGING ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] PROCESS_SEPARATION (LogCollector): %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("LogCollector")

# ── TIMEZONE CONSTANTS ────────────────────────────────────────────────────────
EAT_TZ = zoneinfo.ZoneInfo("Africa/Nairobi")
UTC_TZ = zoneinfo.ZoneInfo("UTC")

# ── DATABASE URL (from .env only — no hardcoded credentials) ──────────────────
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    logger.critical("DATABASE_URL is absent from the environment. Check backend/.env.")
    sys.exit(1)
# asyncpg requires plain postgresql:// — strip SQLAlchemy driver suffix if present.
DATABASE_URL = DATABASE_URL.replace("postgresql+asyncpg://", "postgresql://", 1)

# ── CONCURRENCY AND RETRY CONSTANTS ──────────────────────────────────────────
MAX_CONCURRENT_FETCHES   = int(os.getenv("LOG_COLLECTOR_CONCURRENCY", "8"))
DEFAULT_LOOKBACK_SECONDS = int(os.getenv("LOG_COLLECTOR_LOOKBACK_SECONDS", str(24 * 3600)))
MAX_RETRIES              = 3
RETRY_BASE_SEC           = 2   # backoff: 2s, 4s, 8s

# ── SIEM META-FIELDS — stripped from stored fields JSONB ─────────────────────
# Combined set covers Graylog, Elastic, Wazuh, and Splunk internals.
_SIEM_META_FIELDS = {
    # Common / Graylog
    "timestamp", "source", "_time", "@timestamp",
    "gl2_message_id", "gl2_source_input", "gl2_remote_ip", "streams",
    # Elastic / Wazuh
    "_index", "_type", "_id", "_score", "sort",
    # Splunk
    "splunk_server", "index", "linecount", "punct",
    "timeendpos", "timestartpos",
}


# ── CORRELATION AND TIME SUMMARY ENGINE ───────────────────────────────────────

def generate_fingerprint(client_id: int, query_name: str, group_key: str, initial_ts: datetime) -> str:
    """
    Generates a deterministic fingerprint bound to a 2-hour window slot.
    Two events with the same non-timestamp fields in the same 2-hour window
    resolve to the same fingerprint and are merged into one display row.
    """
    epoch = datetime(1970, 1, 1, tzinfo=EAT_TZ)
    two_hour_slot = int((initial_ts - epoch).total_seconds() / 7200)
    seed = f"{client_id}|{query_name}|{group_key}|{two_hour_slot}"
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


def compute_time_summary(timestamps_list: List[datetime])->Tuple[List[str], str]:
    """
    Returns (all_timestamps, summary_string).
    - all_timestamps: full deduplicated sorted list of ISO-like strings
    - summary_string: condensed human-readable summary
    """
    sorted_ts = sorted(set(ts.replace(microsecond=0) for ts in timestamps_list))
    formatted = [ts.strftime("%Y-%m-%d %H:%M:%S") for ts in sorted_ts]
    count = len(formatted)
    if count == 1:
        summary = formatted[0]
    elif count <=3:
        summary = " | ".join(formatted)
    else:
        middle_idx = count // 2
        summary  = f"{formatted[0]} | {formatted[middle_idx]} | {formatted[-1]}"
    return formatted, summary


# ── FETCH WITH EXPONENTIAL BACKOFF RETRY ─────────────────────────────────────

async def fetch_with_retry(adapter, query: str, lookback_seconds: int, limit: int = 1000) -> list[dict]:
    """
    Calls adapter.fetch_events() with up to MAX_RETRIES attempts.
    On transient failure waits RETRY_BASE_SEC ** (attempt+1) seconds
    (i.e. 2s, 4s, 8s) before retrying.
    Re-raises on the final attempt so the caller can handle it.
    Never passes Graylog-specific kwargs — only the three base interface params.
    """
    for attempt in range(MAX_RETRIES):
        try:
            return await adapter.fetch_events(
                query=query,
                lookback_seconds=lookback_seconds,
                limit=limit,
            )
        except Exception as e:
            wait = RETRY_BASE_SEC ** (attempt + 1)
            if attempt < MAX_RETRIES - 1:
                logger.warning(
                    f"Fetch attempt {attempt + 1} failed: {e}. Retrying in {wait}s..."
                )
                await asyncio.sleep(wait)
            else:
                raise   # re-raise on final attempt so caller logs it


# ── CORE ORCHESTRATION ENGINE ─────────────────────────────────────────────────
async def process_client_telemetry(
    pool: asyncpg.Pool,
    client: dict,
    query_config: dict,
    semaphore: asyncio.Semaphore,
    adapter,            
) -> int:
    """
    Fetches events for one (client, named_query) pair from the SIEM adapter
    and upserts them into operational_events with grouping logic applied.
    Returns the number of net-new rows inserted this cycle.
    """
    async with semaphore:
        async with pool.acquire() as conn:
            client_id = client["id"]
            query_name = query_config["query_name"]
            graylog_query = query_config["graylog_query"]
            siem_type = client.get("siem_type", "graylog")

            logger.info(
                f"Syncing '{query_name}' for client [{client_id}] via [{siem_type.upper()}]."
            )

            lookback_seconds = int(
                query_config.get("time_range") or DEFAULT_LOOKBACK_SECONDS
            )

            # Fetch raw events
            try:
                raw_events = await fetch_with_retry(
                    adapter=adapter,
                    query=graylog_query,
                    lookback_seconds=lookback_seconds,
                    limit=1000,
                )
            except Exception as api_err:
                logger.error(
                    f"SIEM fetch failed after {MAX_RETRIES} attempts — "
                    f"client {client_id}, query '{query_name}': "
                    f"{type(api_err).__name__}: {api_err}",
                    exc_info=True,
                )
                return 0

            if not raw_events:
                return 0

            # Normalize events
            normalised = []
            for msg in raw_events:
                ts = msg.get("timestamp") or msg.get("_time") or msg.get("@timestamp")
                src = msg.get("source") or msg.get("host") or "UNKNOWN_HOST_NODE"
                normalised.append({
                    "timestamp": ts,
                    "source_host": src,
                    "fields": {k: v for k, v in msg.items() if k not in _SIEM_META_FIELDS},
                })

            df = pd.DataFrame(normalised)
            if df.empty:
                return 0

            inserted_count = 0

            for _, row in df.iterrows():
                raw_time_str = row.get("timestamp")
                source_host = row.get("source_host", "UNKNOWN_HOST_NODE")
                fields_data = row.get("fields", {})

                if not raw_time_str:
                    continue

                # Convert timestamp → EAT
                try:
                    if isinstance(raw_time_str, str):
                        utc_dt = datetime.fromisoformat(raw_time_str.replace("Z", "+00:00"))
                    else:
                        utc_dt = pd.to_datetime(raw_time_str).to_pydatetime()

                    if utc_dt.tzinfo is None:
                        utc_dt = utc_dt.replace(tzinfo=UTC_TZ)
                    eat_dt = utc_dt.astimezone(EAT_TZ)
                except Exception:
                    logger.warning(
                        f"Could not parse timestamp '{raw_time_str}' for client {client_id} "
                        f"query '{query_name}'. Falling back to current EAT time."
                    )
                    eat_dt = datetime.now(EAT_TZ)

                # Truncate microseconds
                eat_dt_truncated = eat_dt.replace(microsecond=0)

                # Build group_key
                if not isinstance(fields_data, dict):
                    fields_data = {"raw_log_payload": str(fields_data)}

                sorted_fields_string = "|".join(
                    f"{k}:{fields_data[k]}" for k in sorted(fields_data.keys())
                )
                group_key = hashlib.md5(sorted_fields_string.encode("utf-8")).hexdigest()

                # Fingerprint
                fingerprint = generate_fingerprint(client_id, query_name, group_key, eat_dt_truncated)

                # Prepare summary + timestamps
                initial_str = eat_dt_truncated.strftime("%Y-%m-%d %H:%M:%S")
                all_ts, updated_summary = compute_time_summary([eat_dt_truncated])

                # UPSERT: insert or update in one query
                result = await conn.fetchrow(
                    """
                    INSERT INTO operational_events (
                        client_id, query_name, event_fingerprint, timestamp,
                        source_host, fields, time_summary, all_timestamps,
                        group_key, analyzed_at
                    )
                    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NULL)
                    ON CONFLICT (event_fingerprint) DO NOTHING
                    RETURNING id
                    """,
                    client_id,
                    query_name,
                    fingerprint,
                    eat_dt_truncated,
                    source_host,
                    fields_data,
                    updated_summary,
                    all_ts,
                    group_key,
                )
                if result:
                    inserted_count += 1
                else:
                    existing = await conn.fetchrow(
                        """
                        SELECT id, all_timestamps 
                        FROM operational_events 
                        WHERE event_fingerprint = $1 AND client_id = $2
                        """,
                        fingerprint,
                        client_id,
                    )
                    if existing:
                        # Parse existing strings back to datetimes
                        existing_datetimes = []
                        for ts_str in (existing["all_timestamps"] or []):
                            try:
                                existing_datetimes.append(
                                    datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S").replace(tzinfo=EAT_TZ)
                                )
                            except ValueError:
                                continue

                        # Merge with new timestamp and recompute
                        merged_ts_list, merged_summary = compute_time_summary(
                            existing_datetimes + [eat_dt_truncated]
                        )

                        await conn.execute(
                            """
                            UPDATE operational_events
                            SET all_timestamps = $1,
                                time_summary   = $2,
                                timestamp      = $3
                            WHERE id = $4
                            """,
                            merged_ts_list,
                            merged_summary,
                            eat_dt_truncated,   # ← latest occurrence timestamp, for use in anomaly detection
                            existing["id"],
                        )
            return inserted_count


# ── SUBSCRIPTION SUSPENSION ───────────────────────────────────────────────────

async def suspend_overdue_clients(pool: asyncpg.Pool) -> int:
    """
    Suspends clients that are marked active/subscription_status='active' but
    have no completed payment in the last 30 days.
    Uses only the completed_at column (period_covered may not exist in all
    deployments).
    Called at the end of every log_collector cycle.
    """
    try:
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT c.id
                FROM clients c
                WHERE c.subscription_status = 'active'
                  AND c.active = true
                  AND NOT EXISTS (
                      SELECT 1 FROM payments p
                      WHERE p.client_id = c.id
                        AND p.status    = 'completed'
                        AND p.completed_at > NOW() - INTERVAL '30 days'
                  )
                """
            )
            if not rows:
                return 0

            ids = [r["id"] for r in rows]
            await conn.execute(
                "UPDATE clients SET subscription_status = 'suspended' WHERE id = ANY($1::int[])",
                ids,
            )
            logger.warning(f"SUBSCRIPTION SUSPENSION: {len(ids)} client(s) suspended: {ids}")
            return len(ids)

    except Exception as exc:
        logger.error(f"Subscription suspension check failed: {exc}", exc_info=True)
        return 0


# ── MAIN ──────────────────────────────────────────────────────────────────────

async def main():
    """
    Main entry point — runs one full collection cycle then exits.

    All (client, query) pairs are dispatched concurrently via asyncio.gather,
    bounded by a semaphore of MAX_CONCURRENT_FETCHES.
    Per-task exceptions are caught and logged without aborting the rest of the
    cycle; overall status is set to 'failed' if any task raises.
    """
    logger.info(
        f"Starting log_collector cycle. "
        f"concurrency={MAX_CONCURRENT_FETCHES}, "
        f"lookback_default={DEFAULT_LOOKBACK_SECONDS}s"
    )
    start_time = datetime.now(EAT_TZ)

    # Create a connection pool — each concurrent task acquires its own
    # connection, eliminating the "another operation is in progress" error
    # that occurs when multiple coroutines share a single asyncpg.Connection.

    
    try:
        pool = await asyncpg.create_pool(DATABASE_URL, min_size=2, max_size=MAX_DB_POOL_SIZE)
    except Exception as db_err:
        logger.critical(
            f"Cannot connect to PostgreSQL: {type(db_err).__name__}: {db_err}",
            exc_info=True, #stack trace(file, line number, error type)
        )
        sys.exit(1)

    total_events_inserted = 0
    clients_processed     = 0
    status                = "success"
    last_error: str | None = None
    adapters = {}
    tasks = []

    try:
        async with pool.acquire() as conn:
            active_clients = await conn.fetch("SELECT * FROM clients WHERE active = true")
            clients_queries = []
            for client in active_clients:
                clients_processed += 1
                queries = await conn.fetch(
                    "SELECT * FROM client_queries WHERE client_id = $1 AND enabled = true",
                    client["id"],
                )
                clients_queries.append((client, list(queries)))


        # Build the full task list — planning is done; pool connections are released above.
        client_semaphores = {
            client["id"]:asyncio.Semaphore(MAX_CONCURRENT_FETCHES)
            for client, _ in clients_queries
        }



        for client, queries in clients_queries:
            try:
                adapter = get_adapter(dict(client))#ensure one client uses one adapter, only one session is opened for all api calls

                adapters[client["id"]] = adapter
            except (ValueError, RuntimeError) as factory_err:
                logger.warning(f"Skipping client {client['id']}: {factory_err}")
                continue   # skip this client entirely, don't add its tasks

            sem = client_semaphores[client["id"]]
            for query_config in queries:
                tasks.append(
                    process_client_telemetry(pool, dict(client), dict(query_config), sem, adapter)
                )
#                 tasks = [
#     process_client_telemetry(pool, {"id":1,"name":"Acme Corp"}, {"id":10,"query_name":"failed_logins"}, sem_for_client1),
#     process_client_telemetry(pool, {"id":1,"name":"Acme Corp"}, {"id":11,"query_name":"suspicious_files"}, sem_for_client1),
#     process_client_telemetry(pool, {"id":2,"name":"Beta Ltd"}, {"id":12,"query_name":"account_creation"}, sem_for_client2),
#     process_client_telemetry(pool, {"id":2,"name":"Beta Ltd"}, {"id":13,"query_name":"password_resets"}, sem_for_client2),
# ]


        # Dispatch all tasks concurrently; collect results (or exceptions) as they finish.
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, Exception):
                logger.error(f"Task failed: {r}", exc_info=r)
                status     = "failed"
                last_error = str(r)
            elif isinstance(r, int):
                total_events_inserted += r



    except Exception as loop_fault:
        status     = "failed"
        last_error = str(loop_fault)
        logger.error(f"Collector cycle failed: {last_error}", exc_info=True)

    finally:
        duration = (datetime.now(EAT_TZ) - start_time).total_seconds()

        
        for client_id, adapter in adapters.items():
            try:
                await adapter.close()
            except Exception as close_err:
                logger.warning(f"Failed to close adapter for client {client_id}: {close_err}")
        await suspend_overdue_clients(pool)
        # Upsert scheduler_status — ON CONFLICT handles the unique constraint
        # on process_name so repeated runs always update rather than insert.
        try:
            async with pool.acquire() as conn:
                await conn.execute(
                    """
                    INSERT INTO scheduler_status (
                        process_name, last_run_at, last_run_status, last_error,
                        clients_processed, events_inserted, duration_seconds
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7)
                    ON CONFLICT (process_name) DO UPDATE SET
                        last_run_at       = EXCLUDED.last_run_at,
                        last_run_status   = EXCLUDED.last_run_status,
                        last_error        = EXCLUDED.last_error,
                        clients_processed = EXCLUDED.clients_processed,
                        events_inserted   = EXCLUDED.events_inserted,
                        duration_seconds  = EXCLUDED.duration_seconds
                    """,
                    "log_collector.py",
                    start_time,
                    status,
                    last_error,
                    clients_processed,
                    total_events_inserted,
                    duration,
                )
            logger.info(
                f"Cycle complete — status={status} | "
                f"inserted={total_events_inserted} | "
                f"clients={clients_processed} | "
                f"tasks={len(tasks) if 'tasks' in locals() else 0} | "
                f"duration={duration:.2f}s"
            )
        except Exception as report_err:
            logger.error(
                f"Failed to write scheduler_status: {report_err}", exc_info=True
            )

        await pool.close()


if __name__ == "__main__":
    asyncio.run(main())
