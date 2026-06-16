"""
simulate_normal.py — Normal Behavior Simulator
================================================
Sends realistic, patterned events to Graylog via GELF HTTP so the log
collector fetches them on its next 3-minute cycle.

Purpose: populate operational_events with clean baseline data so the
Isolation Forest has a meaningful behavioral model to train on.

NO anomalies are injected here. Every event follows established
user-IP affinity, working-hours patterns, and expected command lines.

Run:
    pip install httpx python-dotenv
    python simulate_normal.py [--count 500] [--batch 50] [--dry-run]

Environment variables (same .env as the platform):
    GRAYLOG_BASE_URL   e.g. http://localhost:9000
    GRAYLOG_USERNAME   admin
    GRAYLOG_PASSWORD   yourpassword
    GRAYLOG_GELF_PORT  12201   (UDP/TCP GELF port — we use GELF HTTP on 12201 or the HTTP API)
    SIMULATE_CLIENT_ID integer client id (just for logging; Graylog stream picks the client)
"""

import argparse
import asyncio
import json
import logging
import os
import random
import sys
import time
from datetime import datetime, timedelta, timezone

from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("simulate_normal")

# ── Config ────────────────────────────────────────────────────────────────────
GRAYLOG_BASE_URL  = os.getenv("GRAYLOG_BASE_URL", "http://localhost:9000")
GRAYLOG_USERNAME  = os.getenv("GRAYLOG_USERNAME", "Report")
GRAYLOG_PASSWORD  = os.getenv("GRAYLOG_PASSWORD", "MPdusTrPj1mEaTQEyaKpw9PP6GMrN4")
GELF_TCP_HOST     = os.getenv("GRAYLOG_GELF_TCP_HOST", "127.0.0.1")
GELF_TCP_PORT     = int(os.getenv("GRAYLOG_GELF_TCP_PORT", "12201"))
CLIENT_ID         = int(os.getenv("SIMULATE_CLIENT_ID", "1"))

# ── User profiles — mirror the anomaly engine's known users ──────────────────
USER_PROFILES = {
    "joshua":     {"ips": ["192.168.56.104", "10.10.1.5"],  "work_hours": (8, 17),  "fav_cmd": "chrome.exe"},
    "yvonne":     {"ips": ["192.168.1.10",   "10.10.1.12"], "work_hours": (7, 16),  "fav_cmd": "msedge.exe"},
    "vincent":    {"ips": ["10.0.2.15",      "10.10.1.20"], "work_hours": (9, 18),  "fav_cmd": "WINWORD.EXE"},
    "testuser":   {"ips": ["192.168.56.1",   "10.10.1.99"], "work_hours": (8, 17),  "fav_cmd": "powershell.exe"},
    "alice":      {"ips": ["10.10.2.5",      "10.10.1.30"], "work_hours": (8, 17),  "fav_cmd": "EXCEL.EXE"},
    "bob":        {"ips": ["10.10.2.8",      "10.10.1.31"], "work_hours": (9, 17),  "fav_cmd": "outlook.exe"},
    "svc_backup": {"ips": ["10.10.0.5"],                    "work_hours": (1, 3),   "fav_cmd": "robocopy.exe"},
}

ADMIN_ACCOUNTS  = ["Administrator", "SYSTEM", "svc_backup"]
REGULAR_USERS   = [u for u in USER_PROFILES if u not in ("svc_backup",)]

# Normal process commands — nothing suspicious
NORMAL_COMMANDS = [
    "chrome.exe", "msedge.exe", "WINWORD.EXE", "EXCEL.EXE",
    "outlook.exe", "notepad.exe", "explorer.exe", "mspaint.exe",
    "powershell.exe",
    "cmd.exe /c dir",
    "robocopy.exe C:\\Backup D:\\Backup /MIR",
    "svchost.exe",
    "tasklist.exe",
    "ping.exe 10.10.0.1",
]

# Account management events that are routine
ACCOUNT_MGMT_EVENT_IDS = [
    4722,   # Account enabled
    4724,   # Password reset attempt
    4738,   # User account changed
]


# ── Time helpers ──────────────────────────────────────────────────────────────

def _recent_workday_ts(work_start: int = 8, work_end: int = 17,
                       within_hours: int = 48) -> datetime:
    """
    Returns a random timestamp within the last `within_hours` hours,
    biased toward the user's working hours on weekdays.
    """
    now = datetime.now(timezone.utc)
    offset_seconds = random.randint(0, within_hours * 3600)
    candidate = now - timedelta(seconds=offset_seconds)

    if random.random() < 0.85:
        days_back = random.randint(0, min(2, within_hours // 24))
        candidate = now - timedelta(days=days_back)
        hour = random.randint(work_start, work_end - 1)
        minute = random.randint(0, 59)
        second = random.randint(0, 59)
        candidate = candidate.replace(hour=hour, minute=minute, second=second)
    return candidate


# ── Event builders ────────────────────────────────────────────────────────────

def build_auth_event(user: str) -> dict:
    """Normal authentication: 4624 (success) overwhelmingly dominant."""
    profile = USER_PROFILES[user]
    ip = random.choices(
        profile["ips"] + ["127.0.0.1"],
        weights=[70, 25, 5][: len(profile["ips"]) + 1],
    )[0]
    ts = _recent_workday_ts(*profile["work_hours"])
    event_id = random.choices([4624, 4625], weights=[99, 1])[0]

    return {
        "version":         "1.1",
        "host":            "dc01.corp.local",
        "short_message":   f"Authentication event {event_id} for {user}",
        "timestamp":       ts.timestamp(),
        "level":           6,
        "EventID":         str(event_id),
        "TargetUserName":  user,
        "IpAddress":       ip,
        "LogonType":       "3",
        "WorkstationName": f"WS-{random.randint(1, 20):02d}",
        "source_host":     "dc01.corp.local",
        "_simulate":       "normal",
    }


def build_process_event(user: str) -> dict:
    """Normal process creation: user's favourite app or common office tools."""
    profile = USER_PROFILES[user]
    ts = _recent_workday_ts(*profile["work_hours"])
    cmd = random.choices(
        [profile["fav_cmd"], random.choice(NORMAL_COMMANDS)],
        weights=[85, 15],
    )[0]

    return {
        "version":          "1.1",
        "host":             f"ws-{random.randint(1, 20):02d}.corp.local",
        "short_message":    f"Process creation {cmd} by {user}",
        "timestamp":        ts.timestamp(),
        "level":            6,
        "EventID":          "4688",
        "SubjectUserName":  user,
        "CommandLine":      cmd,
        "NewProcessName":   cmd.split()[0],
        "source_host":      f"ws-{random.randint(1, 20):02d}.corp.local",
        "_simulate":        "normal",
    }


def build_account_event(admin: str) -> dict:
    """Routine account management by known admins during business hours."""
    ts = _recent_workday_ts(8, 17)
    target = random.choice(REGULAR_USERS)
    event_id = random.choice(ACCOUNT_MGMT_EVENT_IDS)

    return {
        "version":         "1.1",
        "host":            "dc01.corp.local",
        "short_message":   f"Account event {event_id}: {admin} acted on {target}",
        "timestamp":       ts.timestamp(),
        "level":           6,
        "EventID":         str(event_id),
        "SubjectUserName": admin,
        "TargetUserName":  target,
        "source_host":     "dc01.corp.local",
        "_simulate":       "normal",
    }


# ── GELF TCP sender (async, non-blocking) ─────────────────────────────────────

async def send_gelf_tcp(message: dict, dry_run: bool = False) -> bool:
    """
    Sends a GELF message over TCP using asyncio streams (non-blocking).
    GELF TCP framing: JSON payload terminated with a null byte (\0).
    Requires a GELF TCP input configured in Graylog on GELF_TCP_PORT.
    """
    if dry_run:
        log.info(
            "[DRY-RUN] Would send: EventID=%s user=%s",
            message.get("EventID"),
            message.get("TargetUserName") or message.get("SubjectUserName"),
        )
        return True
    try:
        payload = (json.dumps(message) + "\0").encode("utf-8")
        reader, writer = await asyncio.open_connection(GELF_TCP_HOST, GELF_TCP_PORT)
        writer.write(payload)
        await writer.drain()
        writer.close()
        await writer.wait_closed()
        return True
    except Exception as e:
        log.error("GELF TCP connection error: %s — is Graylog running at %s:%d?",
                  e, GELF_TCP_HOST, GELF_TCP_PORT)
        return False


# ── Main ──────────────────────────────────────────────────────────────────────

async def run(count: int, batch_size: int, dry_run: bool):
    log.info(
        "simulate_normal starting: count=%d batch=%d dry_run=%s gelf_tcp=%s:%d",
        count, batch_size, dry_run, GELF_TCP_HOST, GELF_TCP_PORT,
    )

    # Event type distribution mirrors a real environment
    event_weights = {"auth": 60, "process": 35, "account": 5}
    event_types   = list(event_weights.keys())
    weights       = list(event_weights.values())

    sent  = 0
    failed = 0
    start = time.monotonic()

    batch = []
    for i in range(count):
        kind = random.choices(event_types, weights=weights)[0]

        if kind == "auth":
            msg = build_auth_event(random.choice(REGULAR_USERS))
        elif kind == "process":
            msg = build_process_event(random.choice(REGULAR_USERS))
        else:
            msg = build_account_event(random.choice(ADMIN_ACCOUNTS))

        batch.append(msg)

        if len(batch) >= batch_size or i == count - 1:
            tasks   = [send_gelf_tcp(m, dry_run) for m in batch]
            results = await asyncio.gather(*tasks)
            sent   += sum(results)
            failed += sum(1 for r in results if not r)
            batch   = []
            await asyncio.sleep(0.2)  # small pause — don't hammer Graylog

    duration = time.monotonic() - start
    log.info("Done. sent=%d failed=%d duration=%.1fs", sent, failed, duration)

    if failed > 0:
        log.warning(
            "%d messages failed to send. "
            "Check that a GELF TCP input is active in Graylog at %s:%d.",
            failed, GELF_TCP_HOST, GELF_TCP_PORT,
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Inject normal baseline events into Graylog via GELF TCP")
    parser.add_argument("--count",   type=int, default=300, help="Total events to send (default 300)")
    parser.add_argument("--batch",   type=int, default=50,  help="Concurrent sends per batch (default 50)")
    parser.add_argument("--dry-run", action="store_true",   help="Print events without sending")
    args = parser.parse_args()

    asyncio.run(run(args.count, args.batch, args.dry_run))

# import pandas as pd
# import random
# import socket
# import json
# import math
# import time
# from datetime import datetime, timedelta

# # ── Graylog Configuration ────────────────────────────────────────────────────
# GRAYLOG_IP = "127.0.0.1"
# GRAYLOG_PORT = 12201
# BASE_DATE = datetime(2026, 3, 30)  # Starting Monday 30 March 2026

# # ── Profiles & Constants ──────────────────────────────────────────────────────
# USER_PROFILES = {
#     "joshua":   {"home_ip": "192.168.56.104", "work_start": 8,  "fav_app": "chrome.exe"},
#     "yvonne":   {"home_ip": "192.168.1.10",   "work_start": 7,  "fav_app": "msedge.exe"},
#     "vincent":  {"home_ip": "10.0.2.15",      "work_start": 9,  "fav_app": "WINWORD.EXE"},
#     "testuser": {"home_ip": "192.168.56.1",   "work_start": 8,  "fav_app": "powershell.exe"},
# }

# REGULAR_USERS   = list(USER_PROFILES.keys())
# INTERNAL_IPS    = ["192.168.56.104", "192.168.1.10", "10.0.2.15", "192.168.56.1", "127.0.0.1"]
# ADMIN_ACCOUNTS  = ["Administrator", "SYSTEM"]
# SAFE_COMMANDS   = ["chrome.exe", "msedge.exe", "WINWORD.EXE", "notepad.exe", "explorer.exe", "powershell.exe"]

# # ── Network Helper ───────────────────────────────────────────────────────────

# def send_to_graylog(payload: dict):
#     """
#     Sends GELF message over TCP with Null-Terminator.
#     Explicitly sets the timestamp field to prevent Graylog from overwriting it.
#     """
#     try:
#         payload["version"] = "1.1"
#         payload["host"] = "AD01-Simulator"
        
#         if "Time" in payload:
#             # Convert the generated EAT time string to a Unix timestamp (UTC)
#             dt = datetime.strptime(payload["Time"], "%Y-%m-%d %H:%M:%S")
#             payload["timestamp"] = dt.timestamp()
#             del payload["Time"] 

#         if "short_message" not in payload:
#             payload["short_message"] = f"Normal Activity: {payload.get('EventID', 'Log')}"

#         # TCP framing: JSON + Null Byte
#         raw = (json.dumps(payload) + "\0").encode("utf-8")
        
#         with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
#             sock.settimeout(3)
#             sock.connect((GRAYLOG_IP, GRAYLOG_PORT))
#             sock.sendall(raw)
#             return True
#     except Exception as e:
#         print(f"Connection Error: {e}")
#         return False

# # ── Time helper ──────────────────────────────────────────────────────────────

# def safe_business_time(user: str) -> str:
#     """
#     STRICT BUSINESS HOURS: 07:00 to 19:00 only.
#     Uses math.ceil to prevent float truncation from dropping into 6 AM.
#     """
#     profile = USER_PROFILES[user]
#     day_idx = random.randint(0, 4)  # Monday - Friday
    
#     # Generate hour with triangular bias centered on work_start
#     float_hour = random.triangular(7.0, 19.0, float(profile["work_start"]))
#     hour = math.ceil(float_hour)
    
#     # Final safety clamp for Layer 1 rules
#     if hour < 7: hour = 7
#     if hour > 19: hour = 19
    
#     minute = random.randint(0, 59)
#     dt = BASE_DATE + timedelta(days=day_idx, hours=hour, minutes=minute)
#     return dt.strftime("%Y-%m-%d %H:%M:%S")

# # ── Category generators ──────────────────────────────────────────────────────

# def generate_and_send_normal_data(n: int = 100):
#     """
#     Generates 100 events per category (Total 600 events) and pushes to Graylog.
#     """
#     print(f"Starting injection of {n*3} total events to Graylog...")

#     # 1. Authentication
#     print(f" [+] Sending {n} AuthenticationEvents...")
#     for _ in range(n):
#         user = random.choice(REGULAR_USERS)
#         ip = random.choices([USER_PROFILES[user]["home_ip"], random.choice(INTERNAL_IPS)], weights=[98, 2])[0]
#         send_to_graylog({
#             "Category": "AuthenticationEvents",
#             "TargetUserName": user,
#             "EventID": 4624,
#             "IpAddress": ip,
#             "Time": safe_business_time(user)
#         })

#     # 2. Process Creation
#     print(f" [+] Sending {n} ProcessCreationEvents...")
#     for _ in range(n):
#         user = random.choice(REGULAR_USERS)
#         cmd = random.choices([USER_PROFILES[user]["fav_app"], random.choice(SAFE_COMMANDS)], weights=[90, 10])[0]
#         send_to_graylog({
#             "Category": "ProcessCreationEvents",
#             "SubjectUserName": user,
#             "CommandLine": cmd,
#             "EventID": 4688,
#             "Time": safe_business_time(user)
#         })

#     # 3. Account Management
#     print(f" [+] Sending {n} AccountManagementEvents...")
#     for _ in range(n):
#         admin = random.choice(ADMIN_ACCOUNTS)
#         send_to_graylog({
#             "Category": "AccountManagementEvents",
#             "SubjectUserName": admin,
#             "TargetUserName": random.choice(REGULAR_USERS),
#             "EventID": random.choice([4720, 4722, 4724]),
#             "Time": safe_business_time("joshua") # Joshua profile used as a generic time baseline
#         })

# if __name__ == "__main__":
#     generate_and_send_normal_data(100)
#     print("\nInjection complete. Check your dashboard for 0 anomalies.")