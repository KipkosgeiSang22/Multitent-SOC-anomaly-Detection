import os, sys, asyncio, logging, hashlib, json, zoneinfo
from datetime import datetime
from pathlib import Path
import asyncpg
import pandas as pd
from dotenv import load_dotenv
from typing import List, Tuple

MAX_DB_POOL_SIZE = int(os.getenv("LOG_COLLECTOR_DB_POOL_SIZE", str(20*5)))
load_dotenv(dotenv_path=Path(__file__).resolve().parent.parent / ".env")
_backend_dir = Path(__file__).resolve().parent.parent
if str(_backend_dir) not in sys.path:
    sys.path.insert(0, str(_backend_dir))

from app.siem.factory import get_adapter as _get_adapter

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] PROCESS_SEPARATION (LogCollector): %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger =logging.getLogger('LogCollector')
EAT_TZ = zoneinfo.ZoneInfo("Africa/Nairobi")
UTC_TZ = zoneinfo.ZoneInfo("UTC") 
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    logger.critical("DATABASE URL is absent from environment")
    sys.exit(1)

DATABASE_URL = DATABASE_URL.replace("postgresql+asyncpg://", "postgresql://", 1)

MAX_CONCURRENT_FETCHES   = int(os.getenv("LOG_COLLECTOR_CONCURRENCY", "8"))
DEFAULT_LOOKBACK_SECONDS = int(os.getenv("LOG_COLLECTOR_LOOKBACK_SECONDS", str(24 * 3600)))
MAX_RETRIES              = 3
RETRY_BASE_SEC           = 2   # backoff: 2s, 4s, 8s

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

def generate_fingerprint(client_id:int, query_name:str, group_key:str, initial_ts: datetime) ->str:
    epoch = datetime(1970, 1, 1, tzinfo=EAT_TZ)
    two_hour_slot = int((initial_ts-epoch).total_seconds()/7200)
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

async def fetch_with_retry(adapter, query:str, lookback_seconds:int, limit:int = 1000) -> list[dict]:
    for attempt in range(MAX_RETRIES):
        try:
            return await adapter.fetch_events(
                query=query,
                lookback_seconds=lookback_seconds,
                limit=limit,
            )
        except Exception as e:
            wait = RETRY_BASE_SEC ** (attempt+1)
            if attempt < MAX_RETRIES-1:
                logger.warning(
                    f"fetch attempt {attempt + 1} failed: {e}. Retrying in {wait}s.."
                )
                await asyncio.sleep(wait)
            else:
                raise
async def process_client_telemetry(
        pool: asyncpg.Pool,
        client : dict,
        query_config : dict,
        semaphore: asyncio.Semaphore,
)-> int:
    async with semaphore:
        async with pool.acquire() as conn:
            client_id = client["id"]
            query_name = client["query_name"]
            graylog_query = client["graylog_query"]
            siem_type = client["siem_type", "graylog"]

            logger.info(
                f"syncing '{query_name}' for client [{client_id}] via [{siem_type.upper()}]"
            )
            try:
                adapter = _get_adapter(dict(client))
            except (ValueError, RuntimeError) as fact_err:
                logger.warning(f"skipping client {client_id}: {fact_err}")
                return 0
            
            lookback_seconds = int(
                query_config.get("time_range") or DEFAULT_LOOKBACK_SECONDS
            )
            try:
                raw_events = await fetch_with_retry(
                    adapter=adapter,
                    query=graylog_query,
                    lookback_seconds=lookback_seconds,
                    limit=1000
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
            normalised = []
            for msg in raw_events:
                ts = msg.get("timestamp") or msg.get("_time") or msg.get("@timestamp")
                src = msg.get("source") or msg.get("host") or "UNKNOWN_HOST_NODE"
                normalised.append({
                    "timestamp":ts,
                    "source_host":src,
                    "fields" : {k:v for k, v in msg.items() if k not in _SIEM_META_FIELDS},
                })

            df = pd.DataFrame(normalised)
            if df.empty:
                return 0
            inserted_count = 0

            for _, row in df.iterrows():
                raw_time_str = row.get("timestamp")
                source_host = row.get("source_host", "Uknown_host_node")
                fields_data = row.get("fields", {})

                if not raw_time_str:
                    continue

                try:
                    if isinstance(raw_time_str, str):
                        utc_dt = datetime.fromisoformat(raw_time_str.replace("Z", "+00:00"))
                    else:
                        utc_df = pd.to_datetime(raw_time_str).to_pydatetime
                    if utc_dt.tzinfo is None:
                        utc_dt = utc_dt.replace(tzinfo=UTC_TZ)
                    eat_dt = utc_dt.astimezone((EAT_TZ))
                except Exception:
                    logger.warning(
                        f"Could not parse timestamp '{raw_time_str}' for client {client_id} "
                        f"query '{query_name}'. Falling back to current EAT time."
                    )
                    eat_dt = datetime.now(EAT_TZ)
                eat_dt_truncated = eat_dt.replace(microsecond=0)
                if not isinstance(fields_data, dict):
                    fields_data = {"raw_log_payload": str(fields_data)}
                
                sorted_field_string = "|".join(
                    f"{k}: {fields_data[k]}" for k in sorted(fields_data.keys())
                )
                group_key = hashlib.md5(sorted_field_string.encode("utf-8")).hexdigest()

                fingerprint= generate_fingerprint(client_id, query_name, group_key, eat_dt_truncated)
                initial_str = eat_dt_truncated.strftime("%Y-%m-%d %H:%M:%S")
                all_ts, updated_summary = compute_time_summary([eat_dt_truncated])

                await conn.execute(
                    """
                    INSERT INTO Operational_events(
                    client_id, query_name, event_fingerprint, timestamp,
                    source_host, fields, time_summary, all_timestamps,
                    group_key, analyzed_at
                    )
                    VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, NULL)
                    ON CONFLICT (event_fingerprint) DO UPDATE SET
                        all_timestamps = operational_events.all_timestamps || EXCLUDED.all_timestamps,
                        time_summary = EXCLUDED.time_summary
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
                inserted_count += 1

            return inserted_count
        
async def suspend_overdue_clients(pool: asyncpg.Pool)->int:
    try:
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT c.id FROM Clients c where c.subscription_status == 'active' AND c.active == true
                AND NOT EXISTS (SELECT 1 FROM payments P WHERE P.client_id ==c.id AND P.status == "completed"
                AND p.completed_at > NOW() - INTERVAL '30 days')
                """
            )
            if not rows:
                return 0
            ids = [r["id"] for r in rows]
            await conn.execute(
                "UPDATE Clients SET subscription_status ='suspended' WHERE id = ANY($1::int[])",
                ids,
            )
            logger.warning(f"SUBSCRIPTION SUSPENSION: {len(ids)} client(s) suspended: {ids}")
            return len(ids)
    except Exception as exc:
        logger.error(f"Subscription suspension check failed: {exc}", exc_info=True)
        return 0
async def main():
    logger.info(
     f"Starting collector cycle."
     f"concurrency={MAX_CONCURRENT_FETCHES},"
     f"lookback_default={DEFAULT_LOOKBACK_SECONDS}s"   
    )
    start_time = datetime.now(EAT_TZ)
    total_tasks = sum(len(queries) for _, queries in clients_queries)
    max_size = min(total_tasks + 1, MAX_DB_POOL_SIZE)
    try:
        pool = await asyncpg.create_pool(DATABASE_URL, min_size=2, max_size=max_size)
    except Exception as db_err:
        logger.critical(
            f"Cannot connect to postgreSQL: {type(db_err).__name__}: {db_err}",
            exec_info=True,
        )
        sys.exit(1)
    total_events_inserted =     0
    clients_processed =          0
    status =                "success" 
    last_err: str | None = None
    try:
        async with pool.acquire() as conn:
            active_clients = await conn.fetch("SELECT * FROM clients WHERE active = true")
            client_queries = []
            for client in active_clients:
                clients_processed += 1
                queries = await conn.fetch(
                    "SELECT * FROM client_queries WHERE client_id = $1 AND enabled = true",
                    client["id"],
                )
                client_queries.append((client, list(queries)))
        Client_Semaphores = {
            client["id"]:asyncio.Semaphore(MAX_CONCURRENT_FETCHES)
            for client, _ in client_queries
        }
        tasks = []
        for client, queries in client_queries:
            sem = Client_Semaphores[client["id"]]
            for query_config in queries:
                tasks.append(
                    process_client_telemetry(
                        pool,
                        dict(client),
                        dict(query_config),
                        sem,
                    )
                )
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, Exception):
                logger.error(f"Task failed: {r}", exc_info=r)
                status      ="failed"
                last_err       =str(r)
            elif isinstance(r, tuple):
                inserted,_ = r
                total_events_inserted += inserted
    except Exception as loop_fault:
        status   = "failed"
        last_err    = str(loop_fault)
        logger.error(f"collector cycle failed:{last_err}", exc_info=True)
    finally:
        duration = ((datetime.now(EAT_TZ)) - start_time).total_seconds()
        await suspend_overdue_clients(pool)

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
                    last_err,
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

if __name__=="__main__":
    asyncio.run(main())