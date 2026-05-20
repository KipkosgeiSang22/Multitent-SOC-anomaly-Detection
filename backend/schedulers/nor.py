import pandas as pd
import random
import socket
import json
import math
import time
from datetime import datetime, timedelta

# ── Graylog Configuration ────────────────────────────────────────────────────
GRAYLOG_IP = "127.0.0.1"
GRAYLOG_PORT = 12201
BASE_DATE = datetime(2026, 3, 30)  # Starting Monday 30 March 2026

# ── Profiles & Constants ──────────────────────────────────────────────────────
USER_PROFILES = {
    "joshua":   {"home_ip": "192.168.56.104", "work_start": 8,  "fav_app": "chrome.exe"},
    "yvonne":   {"home_ip": "192.168.1.10",   "work_start": 7,  "fav_app": "msedge.exe"},
    "vincent":  {"home_ip": "10.0.2.15",      "work_start": 9,  "fav_app": "WINWORD.EXE"},
    "testuser": {"home_ip": "192.168.56.1",   "work_start": 8,  "fav_app": "powershell.exe"},
}

REGULAR_USERS   = list(USER_PROFILES.keys())
INTERNAL_IPS    = ["192.168.56.104", "192.168.1.10", "10.0.2.15", "192.168.56.1", "127.0.0.1"]
ADMIN_ACCOUNTS  = ["Administrator", "SYSTEM"]
SAFE_COMMANDS   = ["chrome.exe", "msedge.exe", "WINWORD.EXE", "notepad.exe", "explorer.exe", "powershell.exe"]

# ── Network Helper ───────────────────────────────────────────────────────────

def send_to_graylog(payload: dict):
    """
    Sends GELF message over TCP with Null-Terminator.
    Explicitly sets the timestamp field to prevent Graylog from overwriting it.
    """
    try:
        payload["version"] = "1.1"
        payload["host"] = "AD01-Simulator"
        
        if "Time" in payload:
            # Convert the generated EAT time string to a Unix timestamp (UTC)
            dt = datetime.strptime(payload["Time"], "%Y-%m-%d %H:%M:%S")
            payload["timestamp"] = dt.timestamp()
            del payload["Time"] 

        if "short_message" not in payload:
            payload["short_message"] = f"Normal Activity: {payload.get('EventID', 'Log')}"

        # TCP framing: JSON + Null Byte
        raw = (json.dumps(payload) + "\0").encode("utf-8")
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(3)
            sock.connect((GRAYLOG_IP, GRAYLOG_PORT))
            sock.sendall(raw)
            return True
    except Exception as e:
        print(f"Connection Error: {e}")
        return False

# ── Time helper ──────────────────────────────────────────────────────────────

def safe_business_time(user: str) -> str:
    """
    STRICT BUSINESS HOURS: 07:00 to 19:00 only.
    Uses math.ceil to prevent float truncation from dropping into 6 AM.
    """
    profile = USER_PROFILES[user]
    day_idx = random.randint(0, 4)  # Monday - Friday
    
    # Generate hour with triangular bias centered on work_start
    float_hour = random.triangular(7.0, 19.0, float(profile["work_start"]))
    hour = math.ceil(float_hour)
    
    # Final safety clamp for Layer 1 rules
    if hour < 7: hour = 7
    if hour > 19: hour = 19
    
    minute = random.randint(0, 59)
    dt = BASE_DATE + timedelta(days=day_idx, hours=hour, minutes=minute)
    return dt.strftime("%Y-%m-%d %H:%M:%S")

# ── Category generators ──────────────────────────────────────────────────────

def generate_and_send_normal_data(n: int = 100):
    """
    Generates 100 events per category (Total 600 events) and pushes to Graylog.
    """
    print(f"Starting injection of {n*3} total events to Graylog...")

    # 1. Authentication
    print(f" [+] Sending {n} AuthenticationEvents...")
    for _ in range(n):
        user = random.choice(REGULAR_USERS)
        ip = random.choices([USER_PROFILES[user]["home_ip"], random.choice(INTERNAL_IPS)], weights=[98, 2])[0]
        send_to_graylog({
            "Category": "AuthenticationEvents",
            "TargetUserName": user,
            "EventID": 4624,
            "IpAddress": ip,
            "Time": safe_business_time(user)
        })

    # 2. Process Creation
    print(f" [+] Sending {n} ProcessCreationEvents...")
    for _ in range(n):
        user = random.choice(REGULAR_USERS)
        cmd = random.choices([USER_PROFILES[user]["fav_app"], random.choice(SAFE_COMMANDS)], weights=[90, 10])[0]
        send_to_graylog({
            "Category": "ProcessCreationEvents",
            "SubjectUserName": user,
            "CommandLine": cmd,
            "EventID": 4688,
            "Time": safe_business_time(user)
        })

    # 3. Account Management
    print(f" [+] Sending {n} AccountManagementEvents...")
    for _ in range(n):
        admin = random.choice(ADMIN_ACCOUNTS)
        send_to_graylog({
            "Category": "AccountManagementEvents",
            "SubjectUserName": admin,
            "TargetUserName": random.choice(REGULAR_USERS),
            "EventID": random.choice([4720, 4722, 4724]),
            "Time": safe_business_time("joshua") # Joshua profile used as a generic time baseline
        })

if __name__ == "__main__":
    generate_and_send_normal_data(100)
    print("\nInjection complete. Check your dashboard for 0 anomalies.")